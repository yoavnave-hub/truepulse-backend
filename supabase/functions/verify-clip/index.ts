import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-client-sha256, x-ingest-secret",
};

const MAX_BYTES = 50 * 1024 * 1024; // 50MB ceiling

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  // Explicit server arrival timestamp
  const receivedAt = new Date().toISOString();

  try {
    const secret = req.headers.get("x-ingest-secret");
    if (!secret || secret !== Deno.env.get("INGEST_SECRET")) {
      return json({ error: "unauthorized" }, 401);
    }

    const clientHash = (req.headers.get("x-client-sha256") ?? "").toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(clientHash)) {
      return json({ error: "missing or malformed x-client-sha256 header" }, 400);
    }

    const bytes = await req.arrayBuffer();
    if (bytes.byteLength === 0) return json({ error: "empty payload" }, 400);
    if (bytes.byteLength > MAX_BYTES) return json({ error: "payload too large (max 50MB)" }, 413);

    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const serverHash = [...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // 1. Verification check: client assertion vs server digest
    if (serverHash !== clientHash) {
      return json({ error: "hash mismatch", server: serverHash, client: clientHash }, 409);
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    // 2. Idempotent check
    const { data: existing } = await supabase
      .from("clips")
      .select("id, sha256_hash, file_path, received_at")
      .eq("sha256_hash", serverHash)
      .maybeSingle();

    if (existing) {
      return json({
        success: true,
        duplicate: true,
        clip_id: existing.id,
        sha256_hash: existing.sha256_hash,
        received_at: existing.received_at,
      });
    }

    // 3. Upload to private bucket
    const path = `${serverHash}.mp4`;
    const { error: uploadError } = await supabase.storage
      .from("raw-clips")
      .upload(path, bytes, { contentType: "video/mp4", upsert: false });

    if (uploadError) throw uploadError;

    // 4. Insert fresh row with received_at
    const { data, error: insertError } = await supabase
      .from("clips")
      .insert({
        sha256_hash: serverHash,
        file_path: path,
        file_size_bytes: bytes.byteLength,
        status: "verified",
        received_at: receivedAt,
      })
      .select()
      .single();

    if (insertError) throw insertError;

    // 5. Generate short-lived signed URL (1 hour)
    const { data: signedData } = await supabase.storage
      .from("raw-clips")
      .createSignedUrl(path, 3600);

    return json({
      success: true,
      duplicate: false,
      clip_id: data.id,
      sha256_hash: serverHash,
      file_size_bytes: bytes.byteLength,
      received_at: data.received_at,
      signed_playback_url: signedData?.signedUrl ?? null,
    });
  } catch (err: any) {
    return json({ error: err?.message ?? "internal error" }, 500);
  }
});