/**
 * FF Store — Root Middleware
 * src/middleware.ts
 *
 * Responsibilities:
 *  1. Refresh the Supabase session on every request (cookie rotation)
 *  2. Protect /dashboard/* — redirect unauthenticated users to /login
 *  3. Protect /admin/*    — redirect non-admin users to /dashboard
 *  4. Redirect authenticated users away from /login and /register
 *  5. Handle maintenance mode from settings (optional, enabled via env)
 *
 * IMPORTANT: getUser() (not getSession()) is used throughout.
 * getSession() reads from the JWT which can be stale. getUser() makes a
 * network call to Supabase Auth to validate the token server-side.
 * This is the secure pattern recommended by Supabase for middleware.
 */

import { type NextRequest, NextResponse } from "next/server";
import { createMiddlewareClient } from "@/lib/supabase/middleware";

// ─── Route configuration ───────────────────────────────────────────────────────

/** Routes that require an authenticated session */
const PROTECTED_USER_ROUTES = ["/dashboard"];

/** Routes that require admin role (super_admin or admin) */
const PROTECTED_ADMIN_ROUTES = ["/admin"];

/** Auth routes that authenticated users should be redirected away from */
const AUTH_ROUTES = ["/login", "/register", "/forgot-password"];

/** API routes and static assets — never intercept these */
const PUBLIC_FILE_REGEX = /\.(.*)$/;
const NEXT_INTERNAL_REGEX = /^\/_next\//;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function startsWithAny(pathname: string, prefixes: string[]): boolean {
  return prefixes.some((prefix) => pathname.startsWith(prefix));
}

/**
 * Builds a redirect response that preserves cookies from the
 * supabase response (so the session refresh isn't lost).
 */
function redirectWithCookies(
  to: string,
  request: NextRequest,
  supabaseResponse: NextResponse
): NextResponse {
  const redirectUrl = new URL(to, request.url);
  const redirectResponse = NextResponse.redirect(redirectUrl);

  // Copy all cookies from the supabase response onto the redirect
  // so that the refreshed session tokens are not lost.
  supabaseResponse.cookies.getAll().forEach((cookie) => {
    redirectResponse.cookies.set(cookie.name, cookie.value, {
      // Preserve original cookie attributes
      ...cookie,
    });
  });

  return redirectResponse;
}

// ─── Middleware ────────────────────────────────────────────────────────────────

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Skip middleware for Next.js internals and static files
  if (
    NEXT_INTERNAL_REGEX.test(pathname) ||
    PUBLIC_FILE_REGEX.test(pathname) ||
    pathname.startsWith("/api/webhooks") // Webhook handlers manage their own auth
  ) {
    return NextResponse.next();
  }

  // ── Create Supabase client & refresh session ─────────────────────────────
  const { supabase, response: supabaseResponse } =
    await createMiddlewareClient(request);

  // IMPORTANT: Always call getUser() — not getSession().
  // This validates the token with Supabase Auth servers.
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser();

  const isAuthenticated = !userError && user !== null;

  // ── Maintenance mode ─────────────────────────────────────────────────────
  // Read from env to avoid a DB call on every request.
  // Set MAINTENANCE_MODE=true in Vercel to enable without redeploying.
  if (
    process.env.MAINTENANCE_MODE === "true" &&
    !startsWithAny(pathname, PROTECTED_ADMIN_ROUTES) &&
    pathname !== "/maintenance"
  ) {
    // Allow admins through during maintenance
    if (!isAuthenticated) {
      return redirectWithCookies("/maintenance", request, supabaseResponse);
    }

    // Check admin status for maintenance bypass
    const { data: profile } = await supabase
      .from("users")
      .select("role")
      .eq("id", user!.id)
      .single();

    const isAdmin =
      profile?.role === "admin" || profile?.role === "super_admin";

    if (!isAdmin) {
      return redirectWithCookies("/maintenance", request, supabaseResponse);
    }
  }

  // ── Redirect authenticated users away from auth pages ────────────────────
  if (isAuthenticated && startsWithAny(pathname, AUTH_ROUTES)) {
    return redirectWithCookies("/dashboard", request, supabaseResponse);
  }

  // ── Protect user dashboard routes ────────────────────────────────────────
  if (startsWithAny(pathname, PROTECTED_USER_ROUTES)) {
    if (!isAuthenticated) {
      // Preserve the intended destination so we can redirect back after login
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("redirectTo", pathname);
      const redirectResponse = NextResponse.redirect(loginUrl);
      supabaseResponse.cookies.getAll().forEach((cookie) => {
        redirectResponse.cookies.set(cookie.name, cookie.value, { ...cookie });
      });
      return redirectResponse;
    }

    // Check if user is banned
    const { data: profile } = await supabase
      .from("users")
      .select("is_banned")
      .eq("id", user!.id)
      .single();

    if (profile?.is_banned) {
      // Sign out banned user and redirect to login with error
      await supabase.auth.signOut();
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("error", "account_suspended");
      return redirectWithCookies(loginUrl.toString(), request, supabaseResponse);
    }

    return supabaseResponse;
  }

  // ── Protect admin routes ─────────────────────────────────────────────────
  if (startsWithAny(pathname, PROTECTED_ADMIN_ROUTES)) {
    if (!isAuthenticated) {
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("redirectTo", pathname);
      const redirectResponse = NextResponse.redirect(loginUrl);
      supabaseResponse.cookies.getAll().forEach((cookie) => {
        redirectResponse.cookies.set(cookie.name, cookie.value, { ...cookie });
      });
      return redirectResponse;
    }

    // Fetch role — must hit DB because JWTs don't auto-update on role change
    const { data: profile, error: profileError } = await supabase
      .from("users")
      .select("role, is_banned")
      .eq("id", user!.id)
      .single();

    if (profileError || !profile) {
      // Profile missing — sign out and redirect
      await supabase.auth.signOut();
      return redirectWithCookies("/login", request, supabaseResponse);
    }

    if (profile.is_banned) {
      await supabase.auth.signOut();
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("error", "account_suspended");
      return redirectWithCookies(loginUrl.toString(), request, supabaseResponse);
    }

    const isAdmin =
      profile.role === "admin" || profile.role === "super_admin";

    if (!isAdmin) {
      // Authenticated but not admin — send to their dashboard
      return redirectWithCookies("/dashboard", request, supabaseResponse);
    }

    return supabaseResponse;
  }

  // ── Public routes — just pass through with refreshed cookies ────────────
  return supabaseResponse;
}

// ─── Matcher ──────────────────────────────────────────────────────────────────

export const config = {
  matcher: [
    /*
     * Match all request paths EXCEPT:
     *  - _next/static  (static files)
     *  - _next/image   (image optimization)
     *  - favicon.ico
     *  - public directory files (png, jpg, svg, etc.)
     *
     * This regex is the official Next.js recommended pattern.
     */
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};