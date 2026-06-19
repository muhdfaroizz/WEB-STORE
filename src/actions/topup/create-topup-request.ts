"use server";
 
import { z } from "zod";
import { revalidatePath } from "next/cache";
import { createServerClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { CreateTopupSchema } from "@/lib/validations/topup";
 
// ── Return types ─────────────────────────────────────────────────────────────
 
export type CreateTopupResult =
  | {
      success: true;
      topupId: string;
      message: string;
    }
  | {
      success: false;
      error: string;
      fieldErrors?: Record<string, string[]>;
    };
 
// ── Rate limit config ────────────────────────────────────────────────────────
// Max pending requests per user at any one time
const MAX_PENDING_REQUESTS = 2;
// Min gap between requests (prevents spam submissions)
const MIN_REQUEST_GAP_MINUTES = 10;
 
// ── Action ───────────────────────────────────────────────────────────────────
 
export async function createTopupRequestAction(
  rawInput: unknown
): Promise<CreateTopupResult> {
  // ── 1. Authenticate ────────────────────────────────────────────────────
  const supabase = await createServerClient();
 
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();
 
  if (authError || !user) {
    return { success: false, error: "You must be signed in to submit a top-up request." };
  }
 
  // ── 2. Check account standing ──────────────────────────────────────────
  const adminClient = createAdminClient();
 
  const { data: profile } = await adminClient
    .from("profiles")
    .select("is_banned, role")
    .eq("id", user.id)
    .single();
 
  if (!profile) {
    return { success: false, error: "Account not found. Please contact support." };
  }
 
  if (profile.is_banned) {
    return { success: false, error: "Your account is suspended. Please contact support." };
  }
 
  // ── 3. Validate input ──────────────────────────────────────────────────
  const parsed = CreateTopupSchema.safeParse(rawInput);
 
  if (!parsed.success) {
    const fieldErrors: Record<string, string[]> = {};
    parsed.error.issues.forEach((issue) => {
      const field = String(issue.path[0]);
      if (!fieldErrors[field]) fieldErrors[field] = [];
      fieldErrors[field].push(issue.message);
    });
    return { success: false, error: "Please fix the errors below.", fieldErrors };
  }
 
  const { amount, payment_method, payment_ref, payment_proof_path, note } =
    parsed.data;
 
  // ── 4. Validate amount against site settings ───────────────────────────
  const { data: minSetting } = await adminClient
    .from("settings")
    .select("value")
    .eq("key", "minimum_topup_amount")
    .single();
 
  const { data: maxSetting } = await adminClient
    .from("settings")
    .select("value")
    .eq("key", "maximum_topup_amount")
    .single();
 
  const minTopup = minSetting ? Number(minSetting.value) : 50;
  const maxTopup = maxSetting ? Number(maxSetting.value) : 50000;
 
  if (amount < minTopup) {
    return {
      success: false,
      error: `Minimum top-up amount is ₱${minTopup}.`,
      fieldErrors: { amount: [`Minimum top-up amount is ₱${minTopup}.`] },
    };
  }
 
  if (amount > maxTopup) {
    return {
      success: false,
      error: `Maximum top-up amount is ₱${maxTopup.toLocaleString()}.`,
      fieldErrors: { amount: [`Maximum top-up amount is ₱${maxTopup.toLocaleString()}.`] },
    };
  }
 
  // ── 5. Verify proof image belongs to this user ─────────────────────────
  // Path format: "topup-proofs/{userId}/{filename}"
  // Extract userId from path and compare to authenticated user
  const pathParts = payment_proof_path.split("/");
  // pathParts[0] = "topup-proofs", pathParts[1] = userId, pathParts[2] = filename
  if (pathParts.length < 3 || pathParts[1] !== user.id) {
    return {
      success: false,
      error: "Invalid payment proof. Please upload your own receipt.",
    };
  }
 
  // Verify the file actually exists in storage (prevents phantom path injection)
  const storagePath = pathParts.slice(1).join("/"); // "{userId}/{filename}"
  const { data: fileExists, error: fileCheckError } = await adminClient.storage
    .from("topup-proofs")
    .list(pathParts[1], {
      search: pathParts[2],
      limit: 1,
    });
 
  if (fileCheckError || !fileExists || fileExists.length === 0) {
    return {
      success: false,
      error: "Payment proof file not found. Please re-upload your receipt.",
    };
  }
 
  // ── 6. Rate limiting — check pending request count ─────────────────────
  const { count: pendingCount } = await adminClient
    .from("topup_requests")
    .select("id", { count: "exact", head: true })
    .eq("user_id", user.id)
    .eq("status", "pending");
 
  if ((pendingCount ?? 0) >= MAX_PENDING_REQUESTS) {
    return {
      success: false,
      error: `You already have ${pendingCount} pending top-up request(s). Please wait for admin review before submitting another.`,
    };
  }
 
  // ── 7. Rate limiting — check minimum gap between submissions ───────────
  const gapThreshold = new Date(
    Date.now() - MIN_REQUEST_GAP_MINUTES * 60 * 1000
  ).toISOString();
 
  const { data: recentRequest } = await adminClient
    .from("topup_requests")
    .select("created_at")
    .eq("user_id", user.id)
    .gte("created_at", gapThreshold)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
 
  if (recentRequest) {
    const nextAllowedAt = new Date(
      new Date(recentRequest.created_at).getTime() +
        MIN_REQUEST_GAP_MINUTES * 60 * 1000
    );
    const waitSeconds = Math.ceil(
      (nextAllowedAt.getTime() - Date.now()) / 1000
    );
    const waitMinutes = Math.ceil(waitSeconds / 60);
 
    return {
      success: false,
      error: `Please wait ${waitMinutes} more minute(s) before submitting another top-up request.`,
    };
  }
 
  // ── 8. Insert topup request ────────────────────────────────────────────
  const { data: newRequest, error: insertError } = await adminClient
    .from("topup_requests")
    .insert({
      user_id: user.id,
      amount,
      status: "pending",
      payment_method,
      payment_ref: payment_ref ?? null,
      payment_proof: payment_proof_path,
      admin_note: null,
    })
    .select("id")
    .single();
 
  if (insertError || !newRequest) {
    console.error("[createTopupRequest] Insert error:", insertError);
    return {
      success: false,
      error: "Failed to submit top-up request. Please try again.",
    };
  }
 
  // ── 9. Revalidate dashboard cache ─────────────────────────────────────
  revalidatePath("/dashboard/topup");
  revalidatePath("/admin/topups");
 
  return {
    success: true,
    topupId: newRequest.id,
    message:
      "Top-up request submitted successfully! Our admin will review your payment within 1–24 hours. You will receive a notification once approved.",
  };
}