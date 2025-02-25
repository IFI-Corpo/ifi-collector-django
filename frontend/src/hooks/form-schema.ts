import { z } from "zod";

export const formSchema = z.object({
  name: z.string().min(1, "Name is required"),
  email: z.string().email("Invalid email address"),
  agree: z
    .boolean()
    .refine((val) => val === true, "You must agree to terms and conditions"),
  "Password-100": z.string().min(6, "Password must be at least 6 characters"),
  "Password-101": z.string().min(6, "Password must be at least 6 characters"),
  "OTP-101": z.string().length(6, "OTP must be 6 characters")
});
