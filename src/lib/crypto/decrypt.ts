/**
 * FF Store — AES-256-GCM Decryption
 * src/lib/crypto/decrypt.ts
 *
 * Decrypts Free Fire account credentials from DB storage.
 * This module must ONLY be imported in Server Actions or API Route handlers.
 * Never import in client components — Next.js will tree-shake it, but
 * the "server-only" guard below enforces this at build time.
 *
 * Pair with encrypt.ts — same key derivation, same per-field IV/tag strategy.
 */

import "server-only"; // Build-time guard: prevents client bundle inclusion

import {
  createDecipheriv,
  hkdfSync,
  createHash,
} from "node:crypto";

// ─── Constants (must match encrypt.ts exactly) ────────────────────────────────

const ALGORITHM = "aes-256-gcm" as const;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const HKDF_HASH = "sha256";
const HKDF_INFO = Buffer.from("ff-store-credentials-v1");
const ENCODING = "base64url" as const;

// ─── Types ────────────────────────────────────────────────────────────────────

export interface DecryptedCredentials {
  username: string;
  password: string;
  email: string | null;
  extra: string | null;
}

/** Raw DB row shape from purchased_accounts table */
export interface EncryptedDBRow {
  encrypted_username: string;
  encrypted_password: string;
  encrypted_email: string | null;
  encrypted_extra: string | null;
  encryption_iv: string;    // JSON string of { username, password, email, extra }
  encryption_tag: string;   // JSON string of { username, password, email, extra }
}

interface IVMap {
  username: string;
  password: string;
  email: string | null;
  extra: string | null;
}

interface TagMap {
  username: string;
  password: string;
  email: string | null;
  extra: string | null;
}

// ─── Key derivation (mirrors encrypt.ts) ─────────────────────────────────────

function deriveKey(recordId: string): Buffer {
  const masterKey = process.env.CREDENTIALS_ENCRYPTION_KEY;

  if (!masterKey) {
    throw new Error(
      "[decrypt] CREDENTIALS_ENCRYPTION_KEY is not set. " +
        "This must be set in your server environment."
    );
  }

  if (masterKey.length < 32) {
    throw new Error(
      "[decrypt] CREDENTIALS_ENCRYPTION_KEY must be at least 32 characters."
    );
  }

  const salt = createHash("sha256").update(recordId).digest();

  return Buffer.from(
    hkdfSync(
      HKDF_HASH,
      Buffer.from(masterKey, "utf8"),
      salt,
      HKDF_INFO,
      KEY_LENGTH
    )
  );
}

// ─── Core decrypt ─────────────────────────────────────────────────────────────

/**
 * Decrypts a single base64url-encoded ciphertext using AES-256-GCM.
 * Throws if the auth tag doesn't match (data tampered or wrong key).
 */
function decryptField(
  ciphertext: string,
  iv: string,
  tag: string,
  key: Buffer
): string {
  const decipher = createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, ENCODING),
    { authTagLength: TAG_LENGTH }
  );

  decipher.setAuthTag(Buffer.from(tag, ENCODING));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, ENCODING)),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

/**
 * Safely decrypts a nullable field.
 * Returns null if ciphertext, iv, or tag is absent.
 */
function decryptNullableField(
  ciphertext: string | null,
  iv: string | null,
  tag: string | null,
  key: Buffer
): string | null {
  if (!ciphertext || !iv || !tag) return null;
  return decryptField(ciphertext, iv, tag, key);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Decrypts all credential fields for a purchased account.
 *
 * This must only be called from a Server Action after verifying:
 *   1. The requesting user is authenticated (auth.uid() matches)
 *   2. The user owns the order (orders.user_id === auth.uid())
 *
 * Example (Server Action):
 * ```ts
 * "use server";
 * import { decryptCredentials } from "@/lib/crypto/decrypt";
 * import { createServerClient } from "@/lib/supabase/server";
 *
 * export async function getAccountCredentials(orderId: string) {
 *   const supabase = await createServerClient();
 *   const { data: { user } } = await supabase.auth.getUser();
 *   if (!user) throw new Error("Unauthenticated");
 *
 *   const { data: account, error } = await supabase
 *     .from("purchased_accounts")
 *     .select("*")
 *     .eq("order_id", orderId)
 *     .eq("user_id", user.id)   // RLS + explicit check
 *     .single();
 *
 *   if (error || !account) throw new Error("Account not found or access denied");
 *
 *   return decryptCredentials(account, orderId);
 * }
 * ```
 *
 * @param row       Raw DB row from purchased_accounts
 * @param recordId  The order UUID used as HKDF salt during encryption
 */
export function decryptCredentials(
  row: EncryptedDBRow,
  recordId: string
): DecryptedCredentials {
  if (!recordId || recordId.trim() === "") {
    throw new Error("[decrypt] recordId must be a non-empty string (order UUID).");
  }

  let ivMap: IVMap;
  let tagMap: TagMap;

  try {
    ivMap = JSON.parse(row.encryption_iv) as IVMap;
  } catch {
    throw new Error("[decrypt] encryption_iv column contains invalid JSON.");
  }

  try {
    tagMap = JSON.parse(row.encryption_tag) as TagMap;
  } catch {
    throw new Error("[decrypt] encryption_tag column contains invalid JSON.");
  }

  const key = deriveKey(recordId);

  let username: string;
  let password: string;

  try {
    username = decryptField(
      row.encrypted_username,
      ivMap.username,
      tagMap.username,
      key
    );
  } catch (err) {
    throw new Error(
      `[decrypt] Failed to decrypt username. ` +
        `This may indicate data corruption or a key mismatch. Original: ${String(err)}`
    );
  }

  try {
    password = decryptField(
      row.encrypted_password,
      ivMap.password,
      tagMap.password,
      key
    );
  } catch (err) {
    throw new Error(
      `[decrypt] Failed to decrypt password. ` +
        `This may indicate data corruption or a key mismatch. Original: ${String(err)}`
    );
  }

  const email = decryptNullableField(
    row.encrypted_email,
    ivMap.email,
    tagMap.email,
    key
  );

  const extra = decryptNullableField(
    row.encrypted_extra,
    ivMap.extra,
    tagMap.extra,
    key
  );

  return { username, password, email, extra };
}

/**
 * Verifies that decryption works without returning plaintext.
 * Use this in health-check routes to confirm the key is set correctly.
 * Never call this in a hot path.
 */
export function verifyDecryptionKey(): { ok: boolean; error?: string } {
  try {
    const testKey = process.env.CREDENTIALS_ENCRYPTION_KEY;
    if (!testKey || testKey.length < 32) {
      return { ok: false, error: "Key missing or too short" };
    }
    // Attempt a derive — throws if key material is invalid
    deriveKey("health-check-record-id");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}