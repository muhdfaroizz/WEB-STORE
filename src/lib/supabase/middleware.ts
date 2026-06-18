/**
 * FF Store — Supabase Auth Middleware Helper
 * src/lib/supabase/middleware.ts
 *
 * Creates a Supabase client that reads/writes cookies in a Next.js
 * middleware context. Handles automatic token refresh via cookie mutation.
 *
 * This file is intentionally thin — it only creates the client.
 * All routing logic lives in src/middleware.ts.
 *
 * Based on the official @supabase/ssr pattern for Next.js 15.
 */

import { createServerClient } from "@supabase/ssr";
import { type NextRequest, NextResponse } from "next/server";
import type { Database } from "@/lib/types"; // generated Supabase types

/**
 * Creates a Supabase client scoped to the middleware request/response pair.
 * Mutates the response to set refreshed auth cookies automatically.
 *
 * @returns { supabase, response }
 *   supabase — client to call getUser() on
 *   response — the NextResponse that must be returned from middleware
 *              (carries refreshed cookies)
 */
export async function createMiddlewareClient(request: NextRequest) {
  // Start with a passthrough response. We may replace it with a redirect,
  // but we always write refreshed cookies onto the final response.
  let response = NextResponse.next({
    request: {
      headers: request.headers,
    },
  });

  const supabase = createServerClient<Database>(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          // Write cookies onto both the request (so the current render sees them)
          // and the response (so the browser stores them).
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value)
          );
          // Re-create the response with the updated request headers
          response = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  return { supabase, response };
}