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

  const receivedAt = new Date().toISOString();

  try {
    // 1. Auth check
    const secret = req.headers.get("x-ingest-secret");
    if (!secret || secret !== Deno.env.get("INGEST_SECRET")) {
      return json({ error: "unauthorized" }, 401);
    }

    // 2. Validate client hash format
    const clientHash = (req.headers.get("x-client-sha256") ?? "").toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(clientHash)) {
      return json({ error: "missing or malformed x-client-sha256 header" }, 400);
    }

    // 3. Early memory guard: check Content-Length before buffering into RAM
    const contentLength = req.headers.get("content-length");
    if (contentLength && parseInt(contentLength, 10) > MAX_BYTES) {
      return json({ error: "payload too large (max 50MB)" }, 413);
    }

    // 4. Read binary payload with secondary size assertion
    const bytes = await req.arrayBuffer();
    if (bytes.byteLength === 0) return json({ error: "empty payload" }, 400);
    if (bytes.byteLength > MAX_BYTES) return json({ error: "payload too large (max 50MB)" }, 413);

    // 5. Container validation: MP4 ftyp box check at offset 4
    if (bytes.byteLength < 12) {
      return json({ error: "payload too small to be valid video container" }, 415);
    }
    const headerBytes = new Uint8Array(bytes.slice(4, 8));
    const boxType = String.fromCharCode(...headerBytes);
    if (boxType !== "ftyp") {
      return json({ error: "invalid container: missing mp4 ftyp box" }, 415);
    }

    // 6. Compute server SHA-256 digest
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const serverHash = [...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // 7. Enforce transit verification
    if (serverHash !== clientHash) {
      return json({ error: "hash mismatch", server: serverHash, client: clientHash }, 409);
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const path = `${serverHash}.mp4`;

    // 8. Idempotency check with missing-storage fallback
    const { data: existing } = await supabase
      .from("clips")
      .select("id, sha256_hash, file_path, received_at")
      .eq("sha256_hash", serverHash)
      .maybeSingle();

    if (existing) {
      const { data: signedExisting } = await supabase.storage
        .from("raw-clips")
        .createSignedUrl(existing.file_path, 3600);

      // If the row exists and storage file is intact, return duplicate
      if (signedExisting?.signedUrl) {
        return json({
          success: true,
          duplicate: true,
          clip_id: existing.id,
          sha256_hash: existing.sha256_hash,
          received_at: existing.received_at,
          signed_playback_url: signedExisting.signedUrl,
        });
      }
      // If signedUrl is null (storage object missing), fall through to re-upload below
    }

    // 9. Storage Upload: verify bytes on storage collision
    const { error: uploadError } = await supabase.storage
      .from("raw-clips")
      .upload(path, bytes, { contentType: "video/mp4", upsert: false });

    if (uploadError) {
      const isAlreadyExists =
        uploadError.message?.toLowerCase().includes("already exists") ||
        (uploadError as any).statusCode === "409" ||
        (uploadError as any).status === 409;

      if (isAlreadyExists) {
        const { data: downloadedBlob } = await supabase.storage
          .from("raw-clips")
          .download(path);

        let storedBytesValid = false;
        if (downloadedBlob) {
          const storedBuf = await downloadedBlob.arrayBuffer();
          const storedDigest = await crypto.subtle.digest("SHA-256", storedBuf);
          const storedHash = [...new Uint8Array(storedDigest)]
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          if (storedHash === serverHash) storedBytesValid = true;
        }

        if (!storedBytesValid) {
          const { error: overwriteError } = await supabase.storage
            .from("raw-clips")
            .upload(path, bytes, { contentType: "video/mp4", upsert: true });
          if (overwriteError) throw overwriteError;
        }
      } else {
        throw uploadError;
      }
    }

    // 10. Database write with concurrent race-condition handling (Postgres 23505)
    let clipId = existing?.id;
    let finalReceivedAt = existing?.received_at ?? receivedAt;

    if (!existing) {
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

      if (insertError) {
        if (insertError.code === "23505" || insertError.message?.includes("unique")) {
          const { data: raceWinner } = await supabase
            .from("clips")
            .select("id, sha256_hash, file_path, received_at")
            .eq("sha256_hash", serverHash)
            .single();

          if (raceWinner) {
            const { data: signedWinner } = await supabase.storage
              .from("raw-clips")
              .createSignedUrl(raceWinner.file_path, 3600);

            return json({
              success: true,
              duplicate: true,
              clip_id: raceWinner.id,
              sha256_hash: raceWinner.sha256_hash,
              received_at: raceWinner.received_at,
              signed_playback_url: signedWinner?.signedUrl ?? null,
            });
          }
        }
        throw insertError;
      }
      clipId = data.id;
      finalReceivedAt = data.received_at;
    }

    // 11. Generate signed playback URL
    const { data: signedData } = await supabase.storage
      .from("raw-clips")
      .createSignedUrl(path, 3600);

    return json({
      success: true,
      duplicate: Boolean(existing),
      clip_id: clipId,
      sha256_hash: serverHash,
      file_size_bytes: bytes.byteLength,
      received_at: finalReceivedAt,
      signed_playback_url: signedData?.signedUrl ?? null,
    });
  } catch (err: any) {
    return json({ error: err?.message ?? "internal error" }, 500);
  }
});