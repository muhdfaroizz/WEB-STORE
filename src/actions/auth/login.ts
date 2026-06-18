/**
 * FF Store — Login Server Action
 * src/actions/auth/login.ts
 *
 * Handles email + password login via Supabase Auth.
 * After successful auth:
 *   - Checks if account is banned
 *   - Updates last_login_at timestamp
 *   - Returns destination URL for client-side redirect
 *     (dashboard for users, /admin for admins)
 *
 * Returns a discriminated union: { success } | { error }
 * Never throws — all errors are returned to the caller.
 */

"use server";

import { z } from "zod";
import { createServerClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";

// ─── Validation schema ────────────────────────────────────────────────────────

const LoginSchema = z.object({
  email: z
    .string()
    .min(1, "Email is required.")
    .email("Enter a valid email address.")
    .toLowerCase()
    .trim(),

  password: z
    .string()
    .min(1, "Password is required.")
    .max(72, "Password is too long."),

  redirectTo: z
    .string()
    .optional()
    .nullable()
    .transform((v) => {
      if (!v || v.trim() === "") return null;
      // Only allow relative URLs to prevent open redirect attacks
      if (v.startsWith("/") && !v.startsWith("//")) return v;
      return null;
    }),
});

// ─── Return types ─────────────────────────────────────────────────────────────

export type LoginResult =
  | { success: true; redirectTo: string }
  | { success: false; error: string; fieldErrors?: Record<string, string[]> };

// ─── Action ───────────────────────────────────────────────────────────────────

export async function loginAction(formData: FormData): Promise<LoginResult> {
  // ── 1. Parse & validate input ──────────────────────────────────────────

  const rawData = {
    email: formData.get("email"),
    password: formData.get("password"),
    redirectTo: formData.get("redirectTo"),
  };

  const parsed = LoginSchema.safeParse(rawData);

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

  const { email, password, redirectTo } = parsed.data;

  // ── 2. Attempt sign in with Supabase Auth ─────────────────────────────

  const supabase = await createServerClient();

  const { data: authData, error: signInError } =
    await supabase.auth.signInWithPassword({ email, password });

  if (signInError) {
    return { success: false, error: mapSignInError(signInError.message) };
  }

  if (!authData.user) {
    return {
      success: false,
      error: "Login failed. Please try again.",
    };
  }

  // ── 3. Fetch user profile for ban check and role ───────────────────────

  // Use admin client — the user's own session may not have propagated yet
  const adminClient = createAdminClient();

  const { data: profile, error: profileError } = await adminClient
    .from("users")
    .select("role, is_banned, email")
    .eq("id", authData.user.id)
    .single();

  if (profileError || !profile) {
    // Profile missing — sign out and surface error
    await supabase.auth.signOut();
    console.error(
      "[login] Profile missing for user:",
      authData.user.id,
      profileError
    );
    return {
      success: false,
      error:
        "Your account profile could not be found. Please contact support.",
    };
  }

  // ── 4. Ban check ───────────────────────────────────────────────────────

  if (profile.is_banned) {
    // Immediately sign them out — do not leave an active session
    await supabase.auth.signOut();
    return {
      success: false,
      error:
        "Your account has been suspended. Please contact support if you believe this is a mistake.",
    };
  }

  // ── 5. Email verification check ───────────────────────────────────────

  if (!authData.user.email_confirmed_at) {
    await supabase.auth.signOut();
    return {
      success: false,
      error:
        "Please verify your email address before logging in. Check your inbox for the verification link.",
    };
  }

  // ── 6. Update last_login_at (fire-and-forget — don't block login) ─────

  adminClient
    .from("users")
    .update({ last_login_at: new Date().toISOString() })
    .eq("id", authData.user.id)
    .then(({ error }) => {
      if (error) {
        console.warn("[login] Failed to update last_login_at:", error.message);
      }
    });

  // ── 7. Determine post-login destination ───────────────────────────────

  const isAdmin =
    profile.role === "admin" || profile.role === "super_admin";

  let destination: string;

  if (redirectTo) {
    // Honor the stored redirect — but enforce admin redirect rules
    if (redirectTo.startsWith("/admin") && !isAdmin) {
      destination = "/dashboard";
    } else {
      destination = redirectTo;
    }
  } else {
    // Default landing page based on role
    destination = isAdmin ? "/admin" : "/dashboard";
  }

  return { success: true, redirectTo: destination };
}

// ─── Error mapping ─────────────────────────────────────────────────────────────

function mapSignInError(message: string): string {
  // Never expose whether the email or password was wrong specifically
  // (prevents user enumeration via login form)
  if (
    message.includes("Invalid login credentials") ||
    message.includes("invalid_credentials") ||
    message.includes("Email not confirmed")
  ) {
    return "Invalid email or password. Please try again.";
  }
  if (message.includes("rate limit") || message.includes("too many")) {
    return "Too many login attempts. Please wait a few minutes and try again.";
  }
  if (message.includes("network") || message.includes("fetch")) {
    return "Network error. Please check your connection and try again.";
  }
  console.error("[login] Unmapped Supabase sign-in error:", message);
  return "Login failed. Please try again.";
}

// ─── Logout action (included here — simple, no validation needed) ─────────────

export type LogoutResult =
  | { success: true }
  | { success: false; error: string };

export async function logoutAction(): Promise<LogoutResult> {
  const supabase = await createServerClient();
  const { error } = await supabase.auth.signOut();

  if (error) {
    console.error("[logout] Sign-out error:", error.message);
    return { success: false, error: "Logout failed. Please try again." };
  }

  return { success: true };
}