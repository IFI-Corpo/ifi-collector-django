import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { motion, AnimatePresence } from "framer-motion";

const step1Schema = z.object({
  first_name: z.string().min(1, "First name is required"),
  last_name: z.string().min(1, "Last name is required"),
  email: z.string().email("Invalid email address"),
});

const step2Schema = z
  .object({
    password: z.string().min(8, "Password must be at least 8 characters"),
    confirm_password: z.string(),
  })
  .refine((data) => data.password === data.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

const step3Schema = z.object({
  otp: z.string().length(6, "OTP must be 6 characters"),
});

export default function SignUp() {
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    first_name: "",
    last_name: "",
    email: "",
    password: "",
    confirm_password: "",
    otp: "",
  });

  const form = useForm({
    resolver: zodResolver(
      step === 1 ? step1Schema : step === 2 ? step2Schema : step3Schema,
    ),
    defaultValues: formData,
  });

  const onSubmit = async (data: any) => {
    setLoading(true);
    setError(null);
    try {
      const mergedData = { ...formData, ...data };
      setFormData(mergedData);
      const response = await fetch("http://localhost:8000/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...mergedData, step }),
      });

      const contentType = response.headers.get("content-type");
      let responseData;
      if (contentType?.includes("application/json")) {
        responseData = await response.json();
      } else {
        const text = await response.text();
        throw new Error(`Server error: ${text}`);
      }

      if (!response.ok)
        throw new Error(responseData.detail || "Registration failed");

      if (step === 3) {
        alert("Registration successful!");
        window.location.href = "/";
      } else {
        setStep(step + 1);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-4">
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          className="space-y-6 p-6 border rounded-lg"
        >
          <div className="flex-col-start gap-1">
            <span>Step {step} of 3</span>
            <Progress value={(step / 3) * 100} />
          </div>

          <AnimatePresence mode="wait">
            <motion.div
              key={step}
              initial={{ opacity: 0, x: 15 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -15 }}
              transition={{ duration: 0.4, type: "spring" }}
              className="flex flex-col gap-2"
            >
              {step === 1 && (
                <>
                  <h2 className="text-2xl font-bold">Personal Details</h2>
                  <p className="text-muted-foreground">
                    Please provide your personal details
                  </p>
                  <FormField
                    control={form.control}
                    name="first_name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>First name *</FormLabel>
                        <FormControl>
                          <Input {...field} placeholder="First name" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="last_name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Last name *</FormLabel>
                        <FormControl>
                          <Input {...field} placeholder="Last name" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Email *</FormLabel>
                        <FormControl>
                          <Input
                            {...field}
                            type="email"
                            placeholder="Enter your email"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </>
              )}

              {step === 2 && (
                <>
                  <h2 className="text-2xl font-bold">Create a Password</h2>
                  <p className="text-muted-foreground">
                    Choose a secure password
                  </p>
                  <FormField
                    control={form.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Password *</FormLabel>
                        <FormControl>
                          <Input
                            {...field}
                            type="password"
                            placeholder="Enter your password"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="confirm_password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Confirm Password *</FormLabel>
                        <FormControl>
                          <Input
                            {...field}
                            type="password"
                            placeholder="Confirm your password"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </>
              )}

              {step === 3 && (
                <>
                  <h2 className="text-2xl font-bold">Verify Your Account</h2>
                  <p className="text-muted-foreground">
                    Enter the OTP sent to your email
                  </p>
                  <FormField
                    control={form.control}
                    name="otp"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>OTP *</FormLabel>
                        <FormControl>
                          <Input {...field} placeholder="Enter OTP" />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </>
              )}
            </motion.div>
          </AnimatePresence>

          {error && <div className="text-red-500 text-sm">{error}</div>}

          <div className="flex justify-between">
            <Button
              type="button"
              variant="outline"
              onClick={() => setStep(step - 1)}
              disabled={step === 1}
            >
              Previous
            </Button>
            <Button type="submit" disabled={loading}>
              {loading
                ? "Submitting..."
                : step === 3
                  ? "Complete Registration"
                  : "Next"}
            </Button>
          </div>
        </form>
      </Form>
    </div>
  );
}
