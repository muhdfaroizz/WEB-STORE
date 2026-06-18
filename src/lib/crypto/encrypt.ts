/**
 * FF Store — AES-256-GCM Encryption
 * src/lib/crypto/encrypt.ts
 *
 * Encrypts Free Fire account credentials before DB storage.
 * Key is derived from CREDENTIALS_ENCRYPTION_KEY env var using HKDF
 * so the raw key is never used directly — provides domain separation.
 *
 * Output shape (EncryptedPayload) is stored across three DB columns:
 *   encrypted_<field>  → base64 ciphertext
 *   encryption_iv      → base64 IV  (shared per record, unique per encrypt call)
 *   encryption_tag     → base64 GCM auth tag (shared per record)
 *
 * Each field gets its own IV + tag so that partial decryption failures
 * don't silently expose other fields.
 */

import {
  createCipheriv,
  hkdfSync,
  randomBytes,
  createHash,
} from "node:crypto";

// ─── Constants ────────────────────────────────────────────────────────────────

const ALGORITHM = "aes-256-gcm" as const;
const IV_LENGTH = 12;        // 96-bit IV — recommended for GCM
const TAG_LENGTH = 16;       // 128-bit auth tag — GCM maximum
const KEY_LENGTH = 32;       // 256-bit key
const HKDF_HASH = "sha256";
const HKDF_INFO = Buffer.from("ff-store-credentials-v1");
const ENCODING = "base64url" as const;   // URL-safe base64, no padding issues

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EncryptedField {
  ciphertext: string;   // base64url encoded ciphertext
  iv: string;           // base64url encoded 96-bit IV
  tag: string;          // base64url encoded 128-bit GCM auth tag
}

export interface EncryptedCredentials {
  username: EncryptedField;
  password: EncryptedField;
  email: EncryptedField | null;
  extra: EncryptedField | null;    // arbitrary JSON blob (backup codes, etc.)
}

// ─── Key derivation ───────────────────────────────────────────────────────────

/**
 * Derives a 256-bit AES key from the master env key using HKDF-SHA256.
 * The salt is derived from a stable record identifier (e.g. order_id) so
 * each DB record gets a unique derived key without storing the key anywhere.
 *
 * @param recordId  A stable unique identifier for the record (e.g. order UUID)
 */
function deriveKey(recordId: string): Buffer {
  const masterKey = process.env.CREDENTIALS_ENCRYPTION_KEY;

  if (!masterKey) {
    throw new Error(
      "[encrypt] CREDENTIALS_ENCRYPTION_KEY is not set. " +
        "Add it to .env.local and Vercel environment variables."
    );
  }

  if (masterKey.length < 32) {
    throw new Error(
      "[encrypt] CREDENTIALS_ENCRYPTION_KEY must be at least 32 characters. " +
        "Generate one with: openssl rand -hex 32"
    );
  }

  // Salt = SHA-256 of the record ID — deterministic, unique per record, not secret
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

// ─── Core encrypt ─────────────────────────────────────────────────────────────

/**
 * Encrypts a single plaintext string with AES-256-GCM.
 * Generates a cryptographically random IV for every call.
 *
 * @param plaintext  The string to encrypt
 * @param key        The 256-bit AES key (derived via deriveKey)
 */
function encryptField(plaintext: string, key: Buffer): EncryptedField {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, {
    authTagLength: TAG_LENGTH,
  });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString(ENCODING),
    iv: iv.toString(ENCODING),
    tag: tag.toString(ENCODING),
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Encrypts all account credential fields for a given order.
 *
 * Usage (in Server Action, never client):
 * ```ts
 * const creds = encryptCredentials({
 *   recordId: orderId,
 *   username: "player123",
 *   password: "s3cur3P@ss",
 *   email: "player@gmail.com",
 *   extra: JSON.stringify({ bindCode: "XXXX" }),
 * });
 * ```
 *
 * @param recordId  Order UUID — used as HKDF salt for key derivation
 * @param username  FF account username (plaintext)
 * @param password  FF account password (plaintext)
 * @param email     FF account email (optional)
 * @param extra     JSON string of extra data (optional)
 */
export function encryptCredentials(params: {
  recordId: string;
  username: string;
  password: string;
  email?: string | null;
  extra?: string | null;
}): EncryptedCredentials {
  const { recordId, username, password, email, extra } = params;

  if (!recordId || recordId.trim() === "") {
    throw new Error("[encrypt] recordId must be a non-empty string (order UUID).");
  }
  if (!username || username.trim() === "") {
    throw new Error("[encrypt] username is required.");
  }
  if (!password || password.trim() === "") {
    throw new Error("[encrypt] password is required.");
  }

  const key = deriveKey(recordId);

  return {
    username: encryptField(username.trim(), key),
    password: encryptField(password.trim(), key),
    email: email ? encryptField(email.trim(), key) : null,
    extra: extra ? encryptField(extra.trim(), key) : null,
  };
}

/**
 * Flattens EncryptedCredentials into DB column values.
 * Maps to the purchased_accounts table schema.
 */
export function flattenForStorage(creds: EncryptedCredentials) {
  return {
    encrypted_username: creds.username.ciphertext,
    encrypted_password: creds.password.ciphertext,
    encrypted_email: creds.email?.ciphertext ?? null,
    encrypted_extra: creds.extra?.ciphertext ?? null,
    // Store per-field IV+tag as JSON arrays so each field can be decrypted independently
    encryption_iv: JSON.stringify({
      username: creds.username.iv,
      password: creds.password.iv,
      email: creds.email?.iv ?? null,
      extra: creds.extra?.iv ?? null,
    }),
    encryption_tag: JSON.stringify({
      username: creds.username.tag,
      password: creds.password.tag,
      email: creds.email?.tag ?? null,
      extra: creds.extra?.tag ?? null,
    }),
  };
}