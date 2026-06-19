import { type NextRequest, NextResponse } from "next/server";
import { createAdminClient } from "@/lib/supabase/admin";
import {
  sendTelegramMessage,
  buildTopupNotificationMessage,
} from "@/lib/telegram/notify";
 
// ── Supabase webhook payload shape ────────────────────────────────────────────
 
interface SupabaseWebhookPayload {
  type: "INSERT" | "UPDATE" | "DELETE";
  table: string;
  schema: string;
  record: {
    id: string;
    user_id: string;
    amount: number;
    status: string;
    payment_method: string;
    payment_ref: string | null;
    payment_proof: string | null;
    created_at: string;
  } | null;
  old_record: Record<string, unknown> | null;
}
 
// ── Security: Verify webhook secret ──────────────────────────────────────────
// Supabase sends the secret in the x-webhook-secret header.
// We configured this value when creating the webhook in the dashboard.
 
function verifyWebhookSecret(request: NextRequest): boolean {
  const secret = request.headers.get("x-webhook-secret");
  const expectedSecret = process.env.SUPABASE_WEBHOOK_SECRET;
 
  if (!expectedSecret) {
    console.error(
      "[topup-notify] SUPABASE_WEBHOOK_SECRET env var not set. Rejecting all webhook calls."
    );
    return false;
  }
 
  if (!secret || secret.length === 0) {
    return false;
  }
 
  // Timing-safe string comparison to prevent timing attacks
  // (even though webhook secrets are not as critical as HMAC,
  //  it's good practice)
  const secretBuffer = Buffer.from(secret);
  const expectedBuffer = Buffer.from(expectedSecret);
 
  if (secretBuffer.length !== expectedBuffer.length) {
    return false;
  }
 
  let mismatch = 0;
  for (let i = 0; i < secretBuffer.length; i++) {
    mismatch |= secretBuffer[i] ^ expectedBuffer[i];
  }
 
  return mismatch === 0;
}
 
// ── Route handler ─────────────────────────────────────────────────────────────
 
export async function POST(request: NextRequest) {
  // ── 1. Verify webhook secret ──────────────────────────────────────────
  if (!verifyWebhookSecret(request)) {
    console.warn("[topup-notify] Rejected: invalid webhook secret.");
    // Return 200 to prevent Supabase from retrying (it will retry on non-2xx)
    // We return a specific message so logs are clear about what happened.
    return NextResponse.json(
      { error: "Invalid webhook secret" },
      { status: 401 }
    );
  }
 
  // ── 2. Parse payload ──────────────────────────────────────────────────
  let payload: SupabaseWebhookPayload;
 
  try {
    payload = (await request.json()) as SupabaseWebhookPayload;
  } catch {
    return NextResponse.json({ error: "Invalid JSON payload" }, { status: 400 });
  }
 
  // ── 3. Filter: only process INSERT events on topup_requests ──────────
  if (
    payload.type !== "INSERT" ||
    payload.table !== "topup_requests" ||
    payload.schema !== "public"
  ) {
    // Not our event — acknowledge and ignore
    return NextResponse.json({ received: true, processed: false });
  }
 
  const record = payload.record;
 
  if (!record) {
    return NextResponse.json({ error: "No record in payload" }, { status: 400 });
  }
 
  // Double-check: only notify for pending requests
  if (record.status !== "pending") {
    return NextResponse.json({ received: true, processed: false, reason: "Not pending" });
  }
 
  // ── 4. Fetch user profile for notification context ────────────────────
  // The webhook payload only contains the topup_requests row.
  // We need to join profiles to get the username/email.
  const adminClient = createAdminClient();
 
  const { data: userProfile } = await adminClient
    .from("profiles")
    .select("email, username")
    .eq("id", record.user_id)
    .single();
 
  // ── 5. Generate signed URL for payment proof ──────────────────────────
  // Valid for 1 hour — admin should review promptly
  let proofSignedUrl: string | null = null;
 
  if (record.payment_proof) {
    // payment_proof format: "topup-proofs/{userId}/{filename}"
    const storagePath = record.payment_proof.replace(/^topup-proofs\//, "");
 
    const { data: signedData } = await adminClient.storage
      .from("topup-proofs")
      .createSignedUrl(storagePath, 3600);
 
    proofSignedUrl = signedData?.signedUrl ?? null;
  }
 
  // ── 6. Send Telegram notification ─────────────────────────────────────
  const message = buildTopupNotificationMessage({
    topupId: record.id,
    userId: record.user_id,
    userEmail: userProfile?.email ?? "Unknown",
    username: userProfile?.username ?? null,
    amount: record.amount,
    paymentMethod: record.payment_method,
    paymentRef: record.payment_ref,
    proofUrl: proofSignedUrl,
    submittedAt: record.created_at,
  });
 
  const result = await sendTelegramMessage(message);
 
  if (!result.success) {
    // Log the failure but still return 200 to Supabase
    // (we don't want Supabase to retry just because Telegram is slow)
    console.error("[topup-notify] Telegram send failed:", result.error);
 
    // Insert a fallback notification in DB so admin sees it in panel
    await adminClient.from("notifications").insert({
      user_id: record.user_id,   // Not ideal but ensures visibility
      type: "admin_message",
      title: "⚠️ Telegram Alert Failed",
      body: `Failed to send Telegram notification for topup #${record.id.slice(0, 8)}. Reason: ${result.error}`,
      reference_id: record.id,
      reference_type: "topup_request",
    });
 
    return NextResponse.json({
      received: true,
      processed: true,
      telegram: false,
      error: result.error,
    });
  }
 
  console.log(
    `[topup-notify] Telegram notification sent. Message ID: ${result.messageId}`
  );
 
  return NextResponse.json({
    received: true,
    processed: true,
    telegram: true,
    messageId: result.messageId,
  });
}
 
// Supabase webhooks always use POST — disallow other methods
export async function GET() {
  return NextResponse.json({ error: "Method not allowed" }, { status: 405 });
}