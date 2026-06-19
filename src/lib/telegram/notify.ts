"use server";

const TELEGRAM_API_BASE = "https://api.telegram.org";
 
type ParseMode = "HTML" | "MarkdownV2";
 
export interface TelegramMessage {
  chatId: string;
  text: string;
  parseMode?: ParseMode;
  inlineKeyboard?: TelegramInlineButton[][];
  disableWebPreview?: boolean;
}
 
export interface TelegramInlineButton {
  text: string;
  url?: string;           
  callbackData?: string;  
}
 
export interface TelegramSendResult {
  success: true;
  messageId: number;
}
 
export interface TelegramSendError {
  success: false;
  error: string;
}
 
// ── Core send function ────────────────────────────────────────────────────────
export async function sendTelegramMessage(
  message: TelegramMessage
): Promise<TelegramSendResult | TelegramSendError> {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
 
  if (!botToken) {
    console.error("[Telegram] TELEGRAM_BOT_TOKEN is not set.");
    return { success: false, error: "Telegram bot token not configured." };
  }
 
  const { chatId, text, parseMode = "HTML", inlineKeyboard, disableWebPreview = true } =
    message;
 
  const payload: Record<string, unknown> = {
    chat_id: chatId,
    text,
    parse_mode: parseMode,
    disable_web_page_preview: disableWebPreview,
  };
 
  if (inlineKeyboard && inlineKeyboard.length > 0) {
    payload.reply_markup = {
      inline_keyboard: inlineKeyboard.map((row) =>
        row.map((btn) => ({
          text: btn.text,
          ...(btn.url ? { url: btn.url } : {}),
          ...(btn.callbackData ? { callback_data: btn.callbackData } : {}),
        }))
      ),
    };
  }
 
  try {
    const response = await fetch(
      `${TELEGRAM_API_BASE}/bot${botToken}/sendMessage`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10_000),
      }
    );
 
    const responseData = await response.json();
 
    if (!response.ok || !responseData.ok) {
      console.error("[Telegram] API error:", responseData);
      return {
        success: false,
        error: responseData.description ?? `HTTP ${response.status}`,
      };
    }
 
    return {
      success: true,
      messageId: responseData.result.message_id,
    };
  } catch (err) {
    if (err instanceof Error && err.name === "TimeoutError") {
      return { success: false, error: "Telegram API timeout after 10s." };
    }
    return { success: false, error: String(err) };
  }
}
 
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
 
// ── Build topup notification message ─────────────────────────────────────────
export interface TopupNotificationData {
  topupId: string;
  userId: string;
  userEmail: string;
  username: string | null;
  amount: number;
  paymentMethod: string;
  paymentRef: string | null;
  proofUrl: string | null;  
  submittedAt: string;      
}
 
export function buildTopupNotificationMessage(
  data: TopupNotificationData
): TelegramMessage {
  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";
  const adminPanelUrl = `${siteUrl}/admin/topup/${data.topupId}`;
 
  // 🇲🇾 Ditukar kepada Bank & Kaedah Pembayaran Malaysia
  const paymentMethodLabel: Record<string, string> = {
    duitnow: "🌀 DuitNow QR / Transfer",
    maybank: "🟡 Maybank2u",
    cimb: "🔴 CIMB Clicks",
    bank_islam: "🟢 Bank Islam",
    tng: "🔵 Touch 'n Go eWallet",
    boost: "❤️ Boost eWallet",
  };
 
  const methodDisplay =
    paymentMethodLabel[data.paymentMethod] ?? data.paymentMethod;
 
  // 🇲🇾 Ditukar kepada Format Ringgit Malaysia (RM)
  const amountDisplay = `RM ${Number(data.amount).toLocaleString("en-MY", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
 
  // 🇲🇾 Ditukar kepada Zon Masa Malaysia (Asia/Kuala_Lumpur)
  const submitted = new Date(data.submittedAt);
  const timeDisplay = submitted.toLocaleString("en-MY", {
    timeZone: "Asia/Kuala_Lumpur",
    dateStyle: "medium",
    timeStyle: "short",
  });
 
  const text = [
    `🔔 <b>PERMOHONAN TOP-UP BARU</b>`,
    ``,
    `👤 <b>Pelanggan:</b> ${escapeHtml(data.username ?? data.userEmail)}`,
    `📧 <b>Email:</b> <code>${escapeHtml(data.userEmail)}</code>`,
    ``,
    `💵 <b>Jumlah:</b> <b>${amountDisplay}</b>`,
    `💳 <b>Kaedah:</b> ${methodDisplay}`,
    data.paymentRef
      ? `🔖 <b>No. Rujukan:</b> <code>${escapeHtml(data.paymentRef)}</code>`
      : `🔖 <b>No. Rujukan:</b> <i>Tiada disediakan</i>`,
    ``,
    `🕐 <b>Dihantar pada:</b> ${timeDisplay} MYT`,
    `🆔 <b>ID Request:</b> <code>${data.topupId.slice(0, 8)}…</code>`,
    ``,
    `<i>Sila buka Dashboard Admin untuk semak resit dan buat pengesahan (Approve/Reject).</i>`,
  ]
    .filter(Boolean)
    .join("\n");
 
  const inlineKeyboard: TelegramInlineButton[][] = [
    [
      {
        text: "📋 Semak Request & Resit",
        url: adminPanelUrl,
      },
    ],
  ];
 
  if (data.proofUrl) {
    inlineKeyboard.push([
      {
        text: "🖼 Lihat Gambar Resit Terus",
        url: data.proofUrl,
      },
    ]);
  }
 
  return {
    chatId: process.env.ADMIN_TELEGRAM_CHAT_ID!,
    text,
    parseMode: "HTML",
    inlineKeyboard,
    disableWebPreview: true,
  };
}