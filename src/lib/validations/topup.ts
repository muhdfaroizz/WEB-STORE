import { z } from "zod";
 
export const PAYMENT_METHODS = [
  "duitnow_qr",
  "tng_ewallet",
  "maybank",
  "cimb",
  "bank_islam",
] as const;
 
export type PaymentMethod = (typeof PAYMENT_METHODS)[number];
 
export const PAYMENT_METHOD_LABELS: Record<PaymentMethod, string> = {
  duitnow_qr: "DuitNow QR",
  tng_ewallet: "Touch 'n Go eWallet",
  maybank: "Maybank (MAE)",
  cimb: "CIMB Clicks",
  bank_islam: "Bank Islam",
};
 
// Minimum and maximum topup amounts (Ikut Ringgit Malaysia)
const MIN_TOPUP = 50;
const MAX_TOPUP = 50_000;
 
export const CreateTopupSchema = z.object({
  amount: z
    .number({
      error: "Amount must be a number.",
    })
    .min(MIN_TOPUP, `Minimum top-up amount is RM ${MIN_TOPUP}.`)
    .max(MAX_TOPUP, `Maximum top-up amount is RM ${MAX_TOPUP.toLocaleString()}.`)
    .multipleOf(0.01, "Amount cannot have more than 2 decimal places."),
 
  payment_method: z.enum(PAYMENT_METHODS, {
    error: "Please select a valid payment method.",
  }),
 
  payment_ref: z
    .string()
    .trim()
    .min(4, "Reference/confirmation number must be at least 4 characters.")
    .max(64, "Reference number is too long.")
    .optional()
    .nullable()
    .transform((v) => (v === "" ? null : v)),
 
  payment_proof_path: z
    .string()
    .min(1, "Payment proof (receipt screenshot) is required.")
    .startsWith("topup-proofs/", "Invalid storage path."),
 
  note: z
    .string()
    .trim()
    .max(300, "Note cannot exceed 300 characters.")
    .optional()
    .nullable()
    .transform((v) => (v === "" ? null : v)),
});
 
export type CreateTopupInput = z.infer<typeof CreateTopupSchema>;