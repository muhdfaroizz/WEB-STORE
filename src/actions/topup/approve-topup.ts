"use server";
 
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { createServerClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
import { z } from "zod";
 
// ── Input validation ──────────────────────────────────────────────────────────
 
const ApproveTopupSchema = z.object({
  topupId: z.string().uuid("Invalid top-up request ID."),
  adminNote: z
    .string()
    .trim()
    .max(500, "Note cannot exceed 500 characters.")
    .optional()
    .nullable()
    .transform((v) => (v === "" ? null : v)),
});
 
// ── Return type ───────────────────────────────────────────────────────────────
 
export type ApproveTopupResult =
  | {
      success: true;
      message: string;
      newBalance: number;
      userId: string;
    }
  | {
      success: false;
      error: string;
    };
 
// ── Action ────────────────────────────────────────────────────────────────────
 
export async function approveTopupAction(
  rawInput: unknown
): Promise<ApproveTopupResult> {
  // ── Layer 2: Authenticate the calling admin ───────────────────────────
  const supabase = await createServerClient();
 
  const {
    data: { user: adminUser },
    error: authError,
  } = await supabase.auth.getUser();
 
  if (authError || !adminUser) {
    return { success: false, error: "Authentication required." };
  }
 
  // ── Layer 3: Verify admin role from DB (not JWT) ───────────────────────
  const adminClient = createAdminClient();
 
  const { data: adminProfile, error: profileError } = await adminClient
    .from("profiles")
    .select("role, is_banned, full_name")
    .eq("id", adminUser.id)
    .single();
 
  if (profileError || !adminProfile) {
    return { success: false, error: "Admin profile not found." };
  }
 
  if (adminProfile.is_banned) {
    return { success: false, error: "Your account is suspended." };
  }
 
  if (!["admin", "super_admin"].includes(adminProfile.role)) {
    console.warn(
      `[approveTopup] Non-admin user ${adminUser.id} attempted topup approval`
    );
    return { success: false, error: "Unauthorized. Admin role required." };
  }
 
  // ── Validate input ────────────────────────────────────────────────────
  const parsed = ApproveTopupSchema.safeParse(rawInput);
 
  if (!parsed.success) {
    return {
      success: false,
      error: parsed.error.issues[0]?.message ?? "Invalid input.",
    };
  }
 
  const { topupId, adminNote } = parsed.data;
 
  // ── Fetch topup request to validate state ─────────────────────────────
  // We fetch before calling the DB function to provide a better error message
  const { data: topupRequest, error: fetchError } = await adminClient
    .from("topup_requests")
    .select("id, user_id, amount, status, payment_method, payment_ref")
    .eq("id", topupId)
    .single();
 
  if (fetchError || !topupRequest) {
    return { success: false, error: "Top-up request not found." };
  }
 
  if (topupRequest.status !== "pending") {
    return {
      success: false,
      error: `This request has already been ${topupRequest.status}. It cannot be approved again.`,
    };
  }
 
  // ── Layer 4: Call SECURITY DEFINER DB function ─────────────────────────
  // approve_topup() performs the entire operation atomically:
  //   1. Re-validates admin role inside the DB
  //   2. Locks and credits the wallet
  //   3. Updates topup status to 'approved'
  //   4. Inserts immutable wallet_transaction record
  //   5. Sends in-app notification to the user
  const { error: approveError } = await adminClient.rpc("approve_topup", {
    p_topup_id: topupId,
    p_admin_id: adminUser.id,
    p_note: adminNote ?? null,
  });
 
  if (approveError) {
    console.error("[approveTopup] DB function error:", approveError.message);
 
    // Map DB exception codes to user-friendly messages
    if (approveError.message.includes("TOPUP_NOT_FOUND")) {
      return {
        success: false,
        error: "Request not found or was already processed by another admin.",
      };
    }
    if (approveError.message.includes("UNAUTHORIZED")) {
      return { success: false, error: "Unauthorized." };
    }
 
    return {
      success: false,
      error: "Failed to approve top-up. Please try again.",
    };
  }
 
  // ── Fetch updated wallet balance for response ─────────────────────────
  const { data: wallet } = await adminClient
    .from("wallets")
    .select("balance")
    .eq("user_id", topupRequest.user_id)
    .single();
 
  // ── Log audit action ───────────────────────────────────────────────────
  // Capture request metadata for audit trail
  const headersList = await headers();
  const ipAddress = (
    headersList.get("x-forwarded-for") ??
    headersList.get("x-real-ip") ??
    "unknown"
  ).split(",")[0].trim();
 
  const { error: auditError } = await adminClient.rpc("log_audit_action", {
    p_admin_id: adminUser.id,
    p_action: "topup_approved",
    p_target_type: "topup_request",
    p_target_id: topupId,
    p_details: {
      amount: topupRequest.amount,
      payment_method: topupRequest.payment_method,
      payment_ref: topupRequest.payment_ref,
      admin_note: adminNote,
      admin_name: adminProfile.full_name,
      user_id: topupRequest.user_id,
      new_balance: wallet?.balance,
    },
    p_ip_address: ipAddress,
    p_user_agent: headersList.get("user-agent") ?? null,
  });
 
  if (auditError) {
    // Non-fatal — log but don't fail the approval
    console.warn("[approveTopup] Audit log failed:", auditError.message);
  }
 
  // ── Revalidate admin panel cache ──────────────────────────────────────
  revalidatePath("/admin/topups");
  revalidatePath(`/admin/topups/${topupId}`);
  revalidatePath("/admin");
  revalidatePath(`/dashboard/topup`);
  revalidatePath(`/dashboard/wallet`);
 
  return {
    success: true,
    message: `Top-up of ₱${topupRequest.amount.toLocaleString()} approved successfully. User's wallet has been credited.`,
    newBalance: wallet?.balance ?? 0,
    userId: topupRequest.user_id,
  };
}