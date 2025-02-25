import { useEffect } from "react";

interface Position {
  x: number;
  y: number;
}

interface SpringConfig {
  debug: boolean;
  friction: number;
  trails: number;
  size: number;
  dampening: number;
  tension: number;
}

class Oscillator {
  private phase: number;
  private offset: number;
  private frequency: number;
  private amplitude: number;
  private currentValue: number = 0;

  constructor(config?: {
    phase?: number;
    offset?: number;
    frequency?: number;
    amplitude?: number;
  }) {
    this.phase = config?.phase || 0;
    this.offset = config?.offset || 0;
    this.frequency = config?.frequency || 0.001;
    this.amplitude = config?.amplitude || 1;
  }

  update(): number {
    this.phase += this.frequency;
    this.currentValue = this.offset + Math.sin(this.phase) * this.amplitude;
    return this.currentValue;
  }

  value(): number {
    return this.currentValue;
  }
}

class Node {
  x: number = 0;
  y: number = 0;
  vy: number = 0;
  vx: number = 0;
}

class Line {
  private spring: number;
  private friction: number;
  private nodes: Node[];
  private static readonly config: SpringConfig = {
    debug: true,
    friction: 0.5,
    trails: 20,
    size: 30,
    dampening: 0.25,
    tension: 0.98
  };

  constructor(spring: number, private pos: Position) {
    this.spring = spring;
    this.friction = Line.config.friction + 0.01 * Math.random() - 0.002;
    this.nodes = [];

    for (let i = 0; i < Line.config.size; i++) {
      const node = new Node();
      node.x = pos.x;
      node.y = pos.y;
      this.nodes.push(node);
    }
  }

  update(): void {
    let springFactor = this.spring;
    const firstNode = this.nodes[0];

    firstNode.vx += (this.pos.x - firstNode.x) * springFactor;
    firstNode.vy += (this.pos.y - firstNode.y) * springFactor;

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];

      if (i > 0) {
        const prevNode = this.nodes[i - 1];
        node.vx += (prevNode.x - node.x) * springFactor;
        node.vy += (prevNode.y - node.y) * springFactor;
        node.vx += prevNode.vx * Line.config.dampening;
        node.vy += prevNode.vy * Line.config.dampening;
      }

      node.vx *= this.friction;
      node.vy *= this.friction;
      node.x += node.vx;
      node.y += node.vy;
      springFactor *= Line.config.tension;
    }
  }

  draw(ctx: CanvasRenderingContext2D): void {
    let px = this.nodes[0].x;
    let py = this.nodes[0].y;

    ctx.beginPath();
    ctx.moveTo(px, py);

    for (let i = 1; i < this.nodes.length - 2; i++) {
      const currNode = this.nodes[i];
      const nextNode = this.nodes[i + 1];
      px = (currNode.x + nextNode.x) / 2;
      py = (currNode.y + nextNode.y) / 2;
      ctx.quadraticCurveTo(currNode.x, currNode.y, px, py);
    }

    const lastNode = this.nodes[this.nodes.length - 1];
    const prevNode = this.nodes[this.nodes.length - 2];
    ctx.quadraticCurveTo(prevNode.x, prevNode.y, lastNode.x, lastNode.y);
    ctx.stroke();
    ctx.closePath();
  }
}

const useCanvasCursor = () => {
  useEffect(() => {
    let ctx: CanvasRenderingContext2D;
    let oscillator: Oscillator;
    let animationFrameId: number;
    const pos: Position = { x: 0, y: 0 };
    let lines: Line[] = [];

    const handleMouseMove = (e: MouseEvent | TouchEvent) => {
      if ("touches" in e) {
        pos.x = e.touches[0].pageX;
        pos.y = e.touches[0].pageY;
      } else {
        pos.x = e.clientX;
        pos.y = e.clientY;
      }
      e.preventDefault();
    };

    const handleTouchStart = (e: TouchEvent) => {
      if (e.touches.length === 1) {
        pos.x = e.touches[0].pageX;
        pos.y = e.touches[0].pageY;
      }
    };

    const resizeCanvas = () => {
      if (ctx) {
        ctx.canvas.width = window.innerWidth - 20;
        ctx.canvas.height = window.innerHeight;
      }
    };

    const render = () => {
      if (ctx) {
        ctx.globalCompositeOperation = "source-over";
        ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
        ctx.globalCompositeOperation = "lighter";
        ctx.strokeStyle = `hsla(${Math.round(
          oscillator.update()
        )},50%,50%,0.2)`;
        ctx.lineWidth = 1;

        lines.forEach((line) => {
          line.update();
          line.draw(ctx);
        });

        animationFrameId = requestAnimationFrame(render);
      }
    };

    const init = () => {
      const canvas = document.getElementById("canvas") as HTMLCanvasElement;
      if (!canvas) return;

      ctx = canvas.getContext("2d")!;
      oscillator = new Oscillator({
        phase: Math.random() * 2 * Math.PI,
        amplitude: 85,
        frequency: 0.0095,
        offset: 285
      });

      lines = Array.from(
        { length: 20 },
        (_, i) => new Line(0.4 + (i / 20) * 0.025, pos)
      );

      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("touchmove", handleMouseMove);
      document.addEventListener("touchstart", handleTouchStart);
      window.addEventListener("resize", resizeCanvas);
      resizeCanvas();
      render();
    };

    init();

    return () => {
      cancelAnimationFrame(animationFrameId);
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("touchmove", handleMouseMove);
      document.removeEventListener("touchstart", handleTouchStart);
      window.removeEventListener("resize", resizeCanvas);
    };
  }, []);
};

export default useCanvasCursor;
