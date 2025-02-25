import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";

const NotFound = () => {
  const navigate = useNavigate();

  const handleReturnHome = () => {
    navigate("/ifi-collector-host");
  };

  return (
    <div className="min-h-[90vh] flex flex-col items-center justify-center p-4">
      <div className="max-w-lg w-full text-center space-y-8 relative">
        <div className="absolute -top-24 left-1/2 transform -translate-x-1/2 opacity-10">
          <span className="text-[15rem] font-bold animate-pulse">۴۰۴</span>
        </div>

        <div className="relative space-y-6">
          <div className="animate-float">
            <svg
              className="w-32 h-32 mx-auto text-zinc-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>

          <h1 className="text-4xl font-bold tracking-tight">
            صفحه مورد نظر یافت نشد
          </h1>
          <p className="text-xl text-zinc-600 mb-8">
            متأسفیم! صفحه‌ای که به دنبال آن هستید دیگر در دسترس نیست. بیایید شما
            را به صفحه اصلی بازگردانیم.
          </p>

          <Button
            onClick={handleReturnHome}
            className="inline-flex items-center px-8 py-3 border border-transparent text-base font-medium"
          >
            <ArrowLeft className="w-5 h-5 mr-2" />
            بازگشت به خانه
          </Button>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
