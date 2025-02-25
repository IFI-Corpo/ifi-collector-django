export default function ShimmerButton({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <button className="w-full inline-flex h-10 animate-shimmer items-center justify-center rounded-md border bg-[linear-gradient(110deg,#fff,45%,#f1f1f1,55%,#fff)] dark:bg-[linear-gradient(110deg,#09090b,45%,#333333,55%,#09090b)] bg-[length:200%_100%] px-6 font-medium text-gray-900 dark:text-gray-200 transition-colors focus:outline-none focus-visible:ring-2 focus:ring-gray-700 focus:ring-offset-2 focus:ring-offset-gray-400 dark:focus:ring-gray-300">
      {children}
    </button>
  );
}
