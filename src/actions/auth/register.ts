/**
 * FF Store — Register Server Action
 * src/actions/auth/register.ts
 *
 * Handles new user registration via Supabase Auth (email + password).
 * Validates input with Zod, checks for duplicate emails, applies
 * optional referral code, and sends the email verification link.
 *
 * Returns a discriminated union: { success } | { error }
 * Never throws — all errors are returned to the caller.
 */

"use server";

import { z } from "zod";
import { headers } from "next/headers";
import { createServerClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";

// ─── Validation schema ────────────────────────────────────────────────────────

const RegisterSchema = z.object({
  email: z
    .string()
    .min(1, "Email is required.")
    .email("Enter a valid email address.")
    .max(254, "Email is too long.")
    .toLowerCase()
    .trim(),

  username: z
    .string()
    .min(3, "Username must be at least 3 characters.")
    .max(24, "Username must be 24 characters or less.")
    .regex(
      /^[a-zA-Z0-9_]+$/,
      "Username can only contain letters, numbers, and underscores."
    )
    .trim(),

  password: z
    .string()
    .min(8, "Password must be at least 8 characters.")
    .max(72, "Password must be 72 characters or less.") // bcrypt limit
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter.")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter.")
    .regex(/[0-9]/, "Password must contain at least one number."),

  referralCode: z
    .string()
    .trim()
    .toUpperCase()
    .optional()
    .nullable()
    .transform((v) => (v === "" ? null : v)),
});

// ─── Return types ─────────────────────────────────────────────────────────────

export type RegisterResult =
  | { success: true; message: string }
  | { success: false; error: string; fieldErrors?: Record<string, string[]> };

// ─── Action ───────────────────────────────────────────────────────────────────

export async function registerAction(
  formData: FormData
): Promise<RegisterResult> {
  // ── 1. Parse & validate input ──────────────────────────────────────────

  const rawData = {
    email: formData.get("email"),
    username: formData.get("username"),
    password: formData.get("password"),
    referralCode: formData.get("referralCode"),
  };

  const parsed = RegisterSchema.safeParse(rawData);

  if (!parsed.success) {
    const fieldErrors: Record<string, string[]> = {};
    parsed.error.issues.forEach((issue) => {
      const field = issue.path[0] as string;
      if (!fieldErrors[field]) fieldErrors[field] = [];
      fieldErrors[field].push(issue.message);
    });

    return {
      success: false,
      error: "Please fix the errors below.",
      fieldErrors,
    };
  }

  const { email, username, password, referralCode } = parsed.data;

  // ── 2. Check username availability (before creating auth user) ─────────

  // Use admin client to bypass RLS for the existence check
  const adminClient = createAdminClient();

  const { data: existingUsername, error: usernameCheckError } =
    await adminClient
      .from("users")
      .select("id")
      .eq("username", username)
      .maybeSingle();

  if (usernameCheckError) {
    console.error("[register] Username check error:", usernameCheckError);
    return {
      success: false,
      error: "Something went wrong. Please try again.",
    };
  }

  if (existingUsername) {
    return {
      success: false,
      error: "This username is already taken.",
      fieldErrors: { username: ["This username is already taken."] },
    };
  }

  // ── 3. Validate referral code if provided ──────────────────────────────

  let referrerId: string | null = null;

  if (referralCode) {
    const { data: referrer } = await adminClient
      .from("users")
      .select("id")
      .eq("referral_code", referralCode)
      .maybeSingle();

    if (!referrer) {
      return {
        success: false,
        error: "Invalid referral code.",
        fieldErrors: { referralCode: ["This referral code does not exist."] },
      };
    }

    referrerId = referrer.id;
  }

  // ── 4. Get origin for email redirect URL ──────────────────────────────

  const headersList = await headers();
  const origin = headersList.get("origin") ?? process.env.NEXT_PUBLIC_SITE_URL;

  // ── 5. Sign up with Supabase Auth ─────────────────────────────────────

  const supabase = await createServerClient();

  const { data: authData, error: signUpError } = await supabase.auth.signUp({
    email,
    password,
    options: {
      emailRedirectTo: `${origin}/auth/callback?next=/dashboard`,
      data: {
        // Stored in auth.users.raw_user_meta_data
        // handle_new_user() trigger reads these to populate public.users
        username,
        referred_by: referrerId,
      },
    },
  });

  if (signUpError) {
    // Map Supabase error codes to user-friendly messages
    const message = mapSignUpError(signUpError.message);
    return { success: false, error: message };
  }

  // Supabase returns a user with identities: [] when email already exists
  // but email confirmation is required (avoids user enumeration).
  // We still return success to prevent enumeration attacks.
  if (!authData.user) {
    return {
      success: false,
      error: "Registration failed. Please try again.",
    };
  }

  // ── 6. Update username in public.users (set by trigger with metadata) ─

  // The handle_new_user trigger creates the profile from metadata.
  // We explicitly set username separately to handle edge cases.
  if (authData.user.id) {
    await adminClient
      .from("users")
      .update({
        username,
        referred_by: referrerId,
      })
      .eq("id", authData.user.id);
  }

  // ── 7. Create referral record if applicable ────────────────────────────

  if (referrerId && authData.user.id) {
    await adminClient.from("referrals").insert({
      referrer_id: referrerId,
      referred_id: authData.user.id,
      reward_amount: null, // Set when referred user makes first purchase
    });
  }

  return {
    success: true,
    message:
      "Account created! Please check your email to verify your account before logging in.",
  };
}

// ─── Error mapping ─────────────────────────────────────────────────────────────

function mapSignUpError(message: string): string {
  // Supabase error messages are internal — map to user-friendly strings
  if (message.includes("already registered") || message.includes("already been registered")) {
    return "An account with this email already exists. Try logging in instead.";
  }
  if (message.includes("password")) {
    return "Your password does not meet the requirements.";
  }
  if (message.includes("invalid email") || message.includes("unable to validate")) {
    return "Please enter a valid email address.";
  }
  if (message.includes("email rate limit") || message.includes("rate limit")) {
    return "Too many requests. Please wait a few minutes and try again.";
  }
  if (message.includes("network") || message.includes("fetch")) {
    return "Network error. Please check your connection and try again.";
  }
  console.error("[register] Unmapped Supabase sign-up error:", message);
  return "Registration failed. Please try again.";
}