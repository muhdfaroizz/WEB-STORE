import { type NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";
import { createServerClient } from "@supabase/auth-helpers-nextjs";

// Import fungsi aksi dan jenis jenis result daripada folder actions awak
import { 
  approveTopupAction, 
  type ApproveTopupResult 
} from "@/actions/topup/approve-topup";
import { 
  rejectTopupAction, 
  type RejectTopupResult 
} from "@/actions/topup/reject-topup";

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id: topupId } = await params;
 
  // ── Auth via bearer token OR Supabase session cookie ─────────────────
  const authHeader = request.headers.get("authorization");
  const cookieStore = await cookies();
  
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
 
  let adminUserId: string;
  let jsonBody: any = null;
 
  // Ambil JSON body awal-awal sekali sahaja untuk elakkan ralat stream consumed
  try {
    if (request.body) {
      jsonBody = await request.json();
    }
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  // Semak jika menggunakan API Key (Contohnya daripada Bot Telegram)
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.replace("Bearer ", "");
    if (token !== process.env.ADMIN_API_KEY) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
 
    adminUserId = jsonBody?.admin_user_id;
 
    if (!adminUserId) {
      return NextResponse.json(
        { error: "admin_user_id required with API key auth" },
        { status: 400 }
      );
    }
  } else {
    // Pengesahan sesi kuki (browser admin panel)
    const {
      data: { session },
      error,
    } = await supabase.auth.getSession();
 
    if (error || !session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
 
    adminUserId = session.user.id;
  }
 
  // ── Validasi aksi daripada JSON body ────────────────────────────────────
  const action = jsonBody?.action;
  const adminNote = jsonBody?.admin_note;
 
  if (!["approve", "reject"].includes(action)) {
    return NextResponse.json(
      { error: "action must be 'approve' or 'reject'" },
      { status: 400 }
    );
  }
 
  if (action === "reject" && !adminNote) {
    return NextResponse.json(
      { error: "admin_note (reason) is required for rejection." },
      { status: 400 }
    );
  }
 
  // ── Jalankan Fungsi Server Action Yang Sesuai ────────────────────────────────
  let result: ApproveTopupResult | RejectTopupResult;
 
  if (action === "approve") {
    // Pastikan parameter input dipadankan mengikut keperluan fungsi approveTopupAction awak
    result = await approveTopupAction({
      topupId,
    });
  } else {
    result = await rejectTopupAction({
      topupId,
      adminNote: adminNote!,
    });
  }
 
  if (!result.success) {
    return NextResponse.json({ error: result.error }, { status: 400 });
  }
 
  return NextResponse.json(result, { status: 200 });
}