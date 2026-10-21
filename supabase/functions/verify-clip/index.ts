import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { crypto } from "https://deno.land/std@0.168.0/crypto/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // 1. Read binary video bytes from request body
    const fileBytes = await req.arrayBuffer();
    if (!fileBytes || fileBytes.byteLength === 0) {
      return new Response(JSON.stringify({ error: "Empty file payload" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // 2. Compute SHA-256 hash
    const hashBuffer = await crypto.subtle.digest("SHA-256", fileBytes);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha256Hex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

    // 3. Save into Storage bucket
    const fileName = `${Date.now()}_${sha256Hex.slice(0, 10)}.mp4`;
    const { data: storageData, error: storageError } = await supabase.storage
      .from("raw-clips")
      .upload(fileName, fileBytes, {
        contentType: "video/mp4",
        upsert: false,
      });

    if (storageError) throw storageError;

    // 4. Insert row into database clips table
    const { data: dbData, error: dbError } = await supabase
      .from("clips")
      .insert({
        file_path: storageData.path,
        sha256_hash: sha256Hex,
        file_size_bytes: fileBytes.byteLength,
        status: "verified",
      })
      .select()
      .single();

    if (dbError) throw dbError;

    // 5. Return success JSON
    return new Response(
      JSON.stringify({
        success: true,
        clip_id: dbData.id,
        sha256_hash: sha256Hex,
        file_path: storageData.path,
        file_size_bytes: fileBytes.byteLength,
      }),
      {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});