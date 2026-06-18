/**
 * FF Store — Supabase Auth Callback Route
 * src/app/(auth)/auth/callback/route.ts
 *
 * Handles the OAuth redirect and magic-link email verification callback.
 * Supabase sends users here after:
 *   - Google OAuth login
 *   - Email verification link click
 *   - Password reset link click
 *
 * Flow:
 *   1. Exchange the `code` param for a session (PKCE flow)
 *   2. Redirect to `next` param (or /dashboard by default)
 *   3. On error, redirect to /login with error message
 */

import { NextResponse, type NextRequest } from "next/server";
import { createServerClient } from "@/lib/supabase/server";
import { createAdminClient } from "@/lib/supabase/admin";

export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);

  const code = searchParams.get("code");
  const error = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");

  // `next` is the post-auth destination (set in emailRedirectTo / OAuth options)
  const next = searchParams.get("next") ?? "/dashboard";

  // ── Handle OAuth errors (e.g. user denied Google consent) ───────────────

  if (error) {
    console.error(`[auth/callback] OAuth error: ${error} — ${errorDescription}`);
    const loginUrl = new URL("/login", origin);
    loginUrl.searchParams.set("error", "oauth_failed");
    return NextResponse.redirect(loginUrl);
  }

  // ── Exchange code for session ─────────────────────────────────────────────

  if (!code) {
    console.error("[auth/callback] No code parameter received.");
    const loginUrl = new URL("/login", origin);
    loginUrl.searchParams.set("error", "missing_code");
    return NextResponse.redirect(loginUrl);
  }

  const supabase = await createServerClient();
  const { data, error: exchangeError } =
    await supabase.auth.exchangeCodeForSession(code);

  if (exchangeError || !data.user) {
    console.error("[auth/callback] Code exchange failed:", exchangeError?.message);
    const loginUrl = new URL("/login", origin);
    loginUrl.searchParams.set("error", "session_exchange_failed");
    return NextResponse.redirect(loginUrl);
  }

  // ── Ensure public.users profile exists (Google OAuth users bypass trigger) ─

  const adminClient = createAdminClient();

  const { data: existingProfile } = await adminClient
    .from("users")
    .select("id")
    .eq("id", data.user.id)
    .maybeSingle();

  if (!existingProfile) {
    // Profile missing — create it now (handle_new_user trigger may have missed it)
    const email = data.user.email ?? "";
    const meta = data.user.user_metadata ?? {};
    const referralCode = Math.random().toString(36).slice(2, 10).toUpperCase();

    await adminClient.from("users").insert({
      id: data.user.id,
      email,
      full_name: meta.full_name ?? meta.name ?? email.split("@")[0],
      avatar_url: meta.avatar_url ?? meta.picture ?? null,
      referral_code: referralCode,
    });
  }

  // ── Only allow safe relative redirects ───────────────────────────────────

  const safeNext =
    next.startsWith("/") && !next.startsWith("//") ? next : "/dashboard";

  // ── Check admin role for proper landing ──────────────────────────────────

  const { data: profile } = await adminClient
    .from("users")
    .select("role")
    .eq("id", data.user.id)
    .single();

  let destination = safeNext;
  const isAdmin = profile?.role === "admin" || profile?.role === "super_admin";

  // If the user is an admin and `next` is the generic dashboard, upgrade to /admin
  if (isAdmin && destination === "/dashboard") {
    destination = "/admin";
  }

  return NextResponse.redirect(new URL(destination, origin));
}