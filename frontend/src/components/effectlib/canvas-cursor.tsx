"use client";

import { useEffect } from "react";
import useCanvasCursor from "@/hooks/canvasCursor";

const CanvasCursor = () => {
  useCanvasCursor();

  useEffect(() => {
    const canvas = document.getElementById("canvas") as HTMLCanvasElement;
    if (canvas) {
      setTimeout(() => {
        canvas.style.opacity = "1";
      }, 500);
    }
  }, []);

  return (
    <canvas
      className="invisible lg:visible duration-500 transition-opacity opacity-0 pointer-events-none fixed inset-0 z-0"
      id="canvas"
    />
  );
};

export default CanvasCursor;
