import { createClient } from "@supabase/supabase-js";
import type { Database } from "@/lib/types";

export function createAdminClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl) {
    throw new Error(
      "[supabase/admin] NEXT_PUBLIC_SUPABASE_URL is not set."
    );
  }

  if (!serviceRoleKey) {
    throw new Error(
      "[supabase/admin] SUPABASE_SERVICE_ROLE_KEY is not set. " +
        "This key must NEVER be exposed to the client or committed to version control."
    );
  }

  return createClient<Database>(supabaseUrl, serviceRoleKey, {
    auth: {
      // Disable automatic session persistence — admin client is stateless
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
}