import React, { useEffect, useRef } from "react";
import Lenis from "lenis";

const SmoothScroller: React.FC = () => {
  const lenis = useRef<Lenis | null>(null);

  useEffect(() => {
    lenis.current = new Lenis({
      smoothWheel: true,
      touchMultiplier: 1.5,
      wheelMultiplier: 2,
      duration: 2,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t))
    });

    const resize = setInterval(() => {
      lenis.current?.resize();
    }, 150);

    function onFrame(time: number) {
      lenis.current?.raf(time);
    }

    requestAnimationFrame(function raf(time) {
      onFrame(time);
      requestAnimationFrame(raf);
    });

    return () => {
      clearInterval(resize);
      lenis.current?.destroy();
      lenis.current = null;
    };
  }, []);

  return null;
};

export default SmoothScroller;
