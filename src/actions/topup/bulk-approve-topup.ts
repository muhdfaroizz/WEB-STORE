"use server";

import { z } from "zod";
import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";
import { createServerClient } from "@supabase/auth-helpers-nextjs";
import { createClient } from "@supabase/supabase-js";

export type BulkApproveResult = {
  succeeded: Array<{ id: string; amount: number }>;
  failed: Array<{ id: string; error: string }>;
};

export async function bulkApproveTopupAction(
  topupIds: string[],
  adminNote?: string
): Promise<BulkApproveResult> {
  
  const cookieStore = await cookies();
  
  // 1. Setup Client Server Auth mengikut standard projek awak
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
    return {
      succeeded: [],
      failed: topupIds.map((id) => ({ id, error: "Not authenticated." })),
    };
  }

  const adminUser = session.user;

  // 2. Setup Admin Client menggunakan Service Role untuk pintas RLS
  const adminClient = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );

  const { data: adminProfile } = await adminClient
    .from("profiles")
    .select("role, is_banned")
    .eq("id", adminUser.id)
    .single();

  if (!adminProfile || adminProfile.is_banned) {
    return {
      succeeded: [],
      failed: topupIds.map((id) => ({ id, error: "Unauthorized." })),
    };
  }

  if (!["admin", "super_admin"].includes(adminProfile.role)) {
    return {
      succeeded: [],
      failed: topupIds.map((id) => ({ id, error: "Unauthorized. Admin role required." })),
    };
  }

  const succeeded: BulkApproveResult["succeeded"] = [];
  const failed: BulkApproveResult["failed"] = [];

  // 3. Proses secara sequential (berperingkat) untuk elakkan wallet lock contention
  for (const topupId of topupIds) {
    try {
      // Validasi format UUID dahulu
      if (!/^[0-9a-f-]{36}$/i.test(topupId)) {
        failed.push({ id: topupId, error: "Invalid ID format." });
        continue;
      }

      // Tarik data amaun & status request
      const { data: req } = await adminClient
        .from("topup_requests")
        .select("amount, status")
        .eq("id", topupId)
        .single();

      if (!req) {
        failed.push({ id: topupId, error: "Not found." });
        continue;
      }

      if (req.status !== "pending") {
        failed.push({ id: topupId, error: `Already ${req.status}.` });
        continue;
      }

      // Panggil RPC database "approve_topup"
      const { error } = await adminClient.rpc("approve_topup", {
        p_topup_id: topupId,
        p_admin_id: adminUser.id,
        p_note: adminNote ?? "Bulk approval",
      });

      if (error) {
        failed.push({ id: topupId, error: error.message });
      } else {
        succeeded.push({ id: topupId, amount: req.amount });
      }
    } catch (err) {
      failed.push({ id: topupId, error: String(err) });
    }
  }

  // Kemaskini cache halaman dashboard admin
  revalidatePath("/admin/topups");
  revalidatePath("/admin");

  return { succeeded, failed };
}