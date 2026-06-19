"use server";

import { z } from "zod";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { cookies } from "next/headers";
import { createServerClient } from "@supabase/auth-helpers-nextjs";
import { createClient } from "@supabase/supabase-js";

const RejectTopupSchema = z.object({
  topupId: z.string().uuid("Invalid top-up request ID."),
  adminNote: z
    .string()
    .trim()
    .min(5, "Please provide a reason for rejection (at least 5 characters).")
    .max(500, "Reason cannot exceed 500 characters."),
});

export type RejectTopupResult =
  | { success: true; message: string }
  | { success: false; error: string; fieldErrors?: Record<string, string[]> };

export async function rejectTopupAction(
  rawInput: unknown
): Promise<RejectTopupResult> {
  
  const cookieStore = await cookies();
  
  // Menggunakan createServerClient seperti yang diminta oleh sistem
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        get(name: string) {
          return cookieStore.get(name)?.value;
        },
        set(name: string, value: string, options: any) {
          cookieStore.set({ name, value, ...options });
        },
        remove(name: string, options: any) {
          cookieStore.set({ name, value: "", ...options });
        },
      },
    }
  );

  const {
    data: { session },
    error: authError,
  } = await supabase.auth.getSession();

  if (authError || !session) {
    return { success: false, error: "Authentication required." };
  }

  const adminUser = session.user;

  const adminClient = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );

  const { data: adminProfile } = await adminClient
    .from("profiles")
    .select("role, is_banned, full_name")
    .eq("id", adminUser.id)
    .single();

  if (!adminProfile || adminProfile.is_banned) {
    return { success: false, error: "Unauthorized." };
  }

  if (!["admin", "super_admin"].includes(adminProfile.role)) {
    return { success: false, error: "Unauthorized. Admin role required." };
  }

  const parsed = RejectTopupSchema.safeParse(rawInput);

  if (!parsed.success) {
    const fieldErrors: Record<string, string[]> = {};
    parsed.error.issues.forEach((issue) => {
      const field = String(issue.path[0]);
      if (!fieldErrors[field]) fieldErrors[field] = [];
      fieldErrors[field].push(issue.message);
    });
    return { success: false, error: "Please fix the errors below.", fieldErrors };
  }

  const { topupId, adminNote } = parsed.data;

  const { data: topupRequest } = await adminClient
    .from("topup_requests")
    .select("id, user_id, amount, status, payment_method")
    .eq("id", topupId)
    .single();

  if (!topupRequest) {
    return { success: false, error: "Top-up request not found." };
  }

  if (topupRequest.status !== "pending") {
    return {
      success: false,
      error: `This request is already ${topupRequest.status} and cannot be rejected.`,
    };
  }

  const { error: rejectError } = await adminClient.rpc("reject_topup", {
    p_topup_id: topupId,
    p_admin_id: adminUser.id,
    p_note: adminNote,
  });

  if (rejectError) {
    console.error("[rejectTopup] DB function error:", rejectError.message);

    if (rejectError.message.includes("TOPUP_NOT_FOUND")) {
      return {
        success: false,
        error: "Request not found or already processed.",
      };
    }

    return { success: false, error: "Failed to reject top-up. Please try again." };
  }

  const reqHeaders = await headers();
  const ipAddress = (reqHeaders.get("x-forwarded-for") ?? "unknown").split(",")[0].trim();
  const userAgent = reqHeaders.get("user-agent") ?? null; 
  await adminClient.rpc("log_audit_action", {
    p_admin_id: adminUser.id,
    p_action: "topup_rejected",
    p_target_type: "topup_request",
    p_target_id: topupId,
    p_details: {
      amount: topupRequest.amount,
      payment_method: topupRequest.payment_method,
      rejection_reason: adminNote,
      admin_name: adminProfile.full_name,
      user_id: topupRequest.user_id,
    },
    p_ip_address: ipAddress,
    p_user_agent: userAgent,
  });
 
  revalidatePath("/admin/topups");
  revalidatePath(`/admin/topups/${topupId}`);
  revalidatePath("/admin");
 
  return {
    success: true,
    message: "Top-up request rejected. The user has been notified with your reason.",
  };
}