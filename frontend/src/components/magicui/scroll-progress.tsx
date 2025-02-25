"use client";

import { cn } from "@/lib/utils";
import { motion, MotionProps, useScroll, useSpring } from "motion/react";
import React from "react";
export const ScrollProgress = React.forwardRef<
  HTMLDivElement,
  Omit<React.HTMLAttributes<HTMLElement>, keyof MotionProps>
>(({ className, ...props }, ref) => {
  const { scrollYProgress } = useScroll();

  const scaleX = useSpring(scrollYProgress, {
    stiffness: 200,
    damping: 50,
    restDelta: 0.001,
  });

  return (
    <motion.div
      ref={ref}
      className={cn(
        "fixed inset-x-0 top-0 z-[1000] h-[2px] origin-left bg-gradient-to-r from-[#262626] via-[#727272] to-[#b8b8b8]",
        className,
      )}
      style={{
        scaleX,
      }}
      {...props}
    />
  );
});

ScrollProgress.displayName = "ScrollProgress";

export default ScrollProgress;