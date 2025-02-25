import { SparklesCore } from "../ui/sparkles";

export default function SparkCoreGr() {
  return (
    <div className="w-[40rem] relative mt-1">
      <div className="absolute inset-x-20 top-0 bg-gradient-to-r from-transparent via-zinc-100 to-transparent h-[2px] w-3/4 blur-sm" />
      <div className="absolute inset-x-20 top-0 bg-gradient-to-r from-transparent via-zinc-200 to-transparent h-px w-3/4" />
      <div className="absolute inset-x-60 top-0 bg-gradient-to-r from-transparent via-zinc-300 to-transparent h-[5px] w-1/4 blur-sm" />
      <div className="absolute inset-x-60 top-0 bg-gradient-to-r from-transparent via-zinc-400 to-transparent h-px w-1/4" />
      <SparklesCore
        background="transparent"
        minSize={0.4}
        maxSize={1}
        particleDensity={1200}
        className="w-full h-full"
        particleColor="#FFFFFF"
      />
      <div className="SparkBg absolute inset-0 w-full h-full [mask-image:radial-gradient(350px_200px_at_top,transparent_20%,white)]"></div>
    </div>
  );
}
