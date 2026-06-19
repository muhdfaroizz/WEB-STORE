"use server";
 
import { createServerClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";
 
export interface TopupRequest {
  id: string;
  user_id: string;
  amount: number;
  status: "pending" | "approved" | "rejected";
  payment_method: string;
  payment_ref: string | null;
  payment_proof: string | null;
  admin_note: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  created_at: string;
  updated_at: string;
  // Joined fields
  proof_signed_url?: string;
  reviewer_name?: string;
}
 
// ── Get current user's own topup requests ────────────────────────────────────
 
export async function getUserTopupRequests(): Promise<{
  data: TopupRequest[] | null;
  error: string | null;
}> {
  const supabase = await createServerClient();
 
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();
 
  if (authError || !user) {
    return { data: null, error: "Not authenticated." };
  }
 
  const { data, error } = await supabase
    .from("topup_requests")
    .select("*")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false })
    .limit(20);
 
  if (error) {
    console.error("[getUserTopupRequests]", error);
    return { data: null, error: "Failed to load top-up history." };
  }
 
  return { data, error: null };
}
 
// ── Admin: Get all topup requests with user details ──────────────────────────
 
export interface AdminTopupRequest extends TopupRequest {
  user_email: string;
  user_username: string | null;
  user_avatar: string | null;
}
 
export async function getAdminTopupRequests(options?: {
  status?: "pending" | "approved" | "rejected";
  limit?: number;
  offset?: number;
}): Promise<{
  data: AdminTopupRequest[] | null;
  count: number;
  error: string | null;
}> {
  const supabase = await createServerClient();
 
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();
 
  if (authError || !user) {
    return { data: null, count: 0, error: "Not authenticated." };
  }
 
  // Verify admin role
  const adminClient = createAdminClient();
  const { data: profile } = await adminClient
    .from("profiles")
    .select("role")
    .eq("id", user.id)
    .single();
 
  if (!profile || !["admin", "super_admin"].includes(profile.role)) {
    return { data: null, count: 0, error: "Unauthorized." };
  }
 
  const { status, limit = 25, offset = 0 } = options ?? {};
 
  let query = adminClient
    .from("topup_requests")
    .select(
      `
      *,
      profiles!topup_requests_user_id_fkey (
        email,
        username,
        avatar_url
      ),
      reviewer:profiles!topup_requests_reviewed_by_fkey (
        full_name
      )
    `,
      { count: "exact" }
    )
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);
 
  if (status) {
    query = query.eq("status", status);
  }
 
  const { data, count, error } = await query;
 
  if (error) {
    console.error("[getAdminTopupRequests]", error);
    return { data: null, count: 0, error: "Failed to load top-up requests." };
  }
 
  // Generate signed URLs for payment proofs (valid 1 hour)
  const enriched = await Promise.all(
    (data ?? []).map(async (row: any) => {
      let proof_signed_url: string | undefined;
 
      if (row.payment_proof) {
        // path stored as "topup-proofs/{userId}/{filename}"
        // strip bucket prefix to get the storage object path
        const storagePath = row.payment_proof
          .replace(/^topup-proofs\//, "");
 
        const { data: signedData } = await adminClient.storage
          .from("topup-proofs")
          .createSignedUrl(storagePath, 3600);
 
        proof_signed_url = signedData?.signedUrl;
      }
 
      return {
        ...row,
        user_email: row.profiles?.email ?? "—",
        user_username: row.profiles?.username ?? null,
        user_avatar: row.profiles?.avatar_url ?? null,
        reviewer_name: row.reviewer?.full_name ?? null,
        proof_signed_url,
      } as AdminTopupRequest;
    })
  );
 
  return { data: enriched, count: count ?? 0, error: null };
}
 
// ── Get single topup request (admin) ─────────────────────────────────────────
 
export async function getTopupRequestById(topupId: string): Promise<{
  data: AdminTopupRequest | null;
  error: string | null;
}> {
  const supabase = await createServerClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
 
  if (!user) return { data: null, error: "Not authenticated." };
 
  const adminClient = createAdminClient();
 
  const { data, error } = await adminClient
    .from("topup_requests")
    .select(
      `
      *,
      profiles!topup_requests_user_id_fkey (
        email, username, avatar_url, full_name
      ),
      reviewer:profiles!topup_requests_reviewed_by_fkey (
        full_name
      )
    `
    )
    .eq("id", topupId)
    .single();
 
  if (error || !data) {
    return { data: null, error: "Top-up request not found." };
  }
 
  // Generate signed URL for proof image (1 hour)
  let proof_signed_url: string | undefined;
  if (data.payment_proof) {
    const storagePath = data.payment_proof.replace(/^topup-proofs\//, "");
    const { data: signedData } = await adminClient.storage
      .from("topup-proofs")
      .createSignedUrl(storagePath, 3600);
    proof_signed_url = signedData?.signedUrl;
  }
 
  return {
    data: {
      ...(data as any),
      user_email: (data as any).profiles?.email ?? "—",
      user_username: (data as any).profiles?.username ?? null,
      user_avatar: (data as any).profiles?.avatar_url ?? null,
      reviewer_name: (data as any).reviewer?.full_name ?? null,
      proof_signed_url,
    },
    error: null,
  };
}