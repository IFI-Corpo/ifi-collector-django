import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

// Utility for merging Tailwind classes
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Utility for truncating text
export const truncateText = (text: string, limit: number): string => {
  return text.length > limit ? text.substring(0, limit) + "..." : text;
};
