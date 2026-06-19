import { createBrowserClient } from "@/lib/supabase/client";
import { v4 as uuidv4 } from "uuid";
 
export interface UploadProofResult {
  success: true;
  path: string;       // e.g. "topup-proofs/user-uuid/proof-uuid.jpg"
  publicUrl: string;
}
 
export interface UploadProofError {
  success: false;
  error: string;
}
 
const ALLOWED_MIME_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/heic",
  "image/heif",
];
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
const BUCKET = "topup-proofs";
 
export async function uploadPaymentProof(
  file: File,
  userId: string
): Promise<UploadProofResult | UploadProofError> {
  // ── Client-side validation (mirrors bucket policy) ──────────────────────
  if (!ALLOWED_MIME_TYPES.includes(file.type)) {
    return {
      success: false,
      error: `Invalid file type. Allowed: JPG, PNG, WebP. Got: ${file.type}`,
    };
  }
 
  if (file.size > MAX_FILE_SIZE_BYTES) {
    return {
      success: false,
      error: `File too large. Maximum size is 5 MB. Your file: ${(file.size / 1024 / 1024).toFixed(1)} MB.`,
    };
  }
 
  // ── Build storage path ──────────────────────────────────────────────────
  // Path: topup-proofs/{userId}/{uuid}.{ext}
  // The RLS policy on storage.objects checks (foldername(name))[1] = auth.uid()::TEXT
  // which means this exact path format is REQUIRED for the policy to allow the upload.
  const ext = file.name.split(".").pop()?.toLowerCase() ?? "jpg";
  const filename = `${uuidv4()}.${ext}`;
  const storagePath = `${userId}/${filename}`;
 
  const supabase = createBrowserClient();
 
  // ── Upload to Supabase Storage ──────────────────────────────────────────
  const { data, error } = await supabase.storage
    .from(BUCKET)
    .upload(storagePath, file, {
      cacheControl: "3600",
      upsert: false,           // Never overwrite — each upload gets a unique UUID path
      contentType: file.type,
    });
 
  if (error) {
    console.error("[uploadPaymentProof] Storage upload error:", error);
 
    // Map Supabase storage errors to user-friendly messages
    if (error.message.includes("Bucket not found")) {
      return { success: false, error: "Upload service unavailable. Please contact support." };
    }
    if (error.message.includes("row-level security") || error.message.includes("policy")) {
      return { success: false, error: "Upload not authorized. Please sign in again." };
    }
    if (error.message.includes("Entity Too Large") || error.message.includes("413")) {
      return { success: false, error: "File exceeds the 5 MB size limit." };
    }
 
    return { success: false, error: "Upload failed. Please try again." };
  }
 
  // ── Return the full storage path (stored in DB) ────────────────────────
  // We store the full bucket-prefixed path so the Server Action can
  // construct signed URLs without knowing the bucket name.
  const fullPath = `${BUCKET}/${data.path}`;
 
  // For admin preview we also return the signed URL (valid 1 hour)
  const { data: signedData } = await supabase.storage
    .from(BUCKET)
    .createSignedUrl(data.path, 3600);
 
  return {
    success: true,
    path: fullPath,                          // stored in topup_requests.payment_proof
    publicUrl: signedData?.signedUrl ?? "",  // used in admin panel for preview
  };
}