"use client";

import * as React from "react";
import {
  Popover,
  PopoverContent,
  PopoverTrigger
} from "@/components/ui/popover";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import {
  SlidersHorizontal,
  MessageSquare,
  Instagram,
  Twitter,
  Film,
  Youtube,
  Clock,
  ListVideo,
  Clapperboard,
  Activity,
  Monitor,
  Subtitles,
  CopyCheck,
  Image,
  Glasses,
  Box,
  MapPin,
  ShoppingCart,
  TrendingUp,
  Eye 
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Drawer, DrawerContent, DrawerTrigger } from "@/components/ui/drawer";

// Minimal useMediaQuery hook
function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = React.useState(false);
  React.useEffect(() => {
    const mediaQueryList = window.matchMedia(query);
    const listener = (e: MediaQueryListEvent) => setMatches(e.matches);
    mediaQueryList.addEventListener("change", listener);
    setMatches(mediaQueryList.matches);
    return () => {
      mediaQueryList.removeEventListener("change", listener);
    };
  }, [query]);
  return matches;
}

const FILTER_OPTIONS = {
  platforms: {
    type: "multiple" as const,
    options: ["تردز", "اینستاگرام", "X (توییتر)", "تیک تاک", "یوتوب"] as const
  },
  uploadDate: {
    type: "single" as const,
    options: ["یک ساعت گذشته", "امروز", "این هفته", "این ماه", "امسال"] as const
  },
  type: {
    type: "multiple" as const,
    options: ["ویدیو", "کانال", "لیست پخش", "فیلم"] as const
  },
  duration: {
    type: "multiple" as const,
    options: ["زیر ۴ دقیقه", "۴ تا ۲۰ دقیقه", "بالای ۲۰ دقیقه"] as const
  },
  features: {
    type: "multiple" as const,
    options: [
      "زنده",
      "۴K",
      "HD",
      "زیرنویس/متن",
      "کپی‌رایت آزاد",
      "۳۶۰ درجه",
      "VR180",
      "۳D",
      "HDR",
      "مکان",
      "خریداری شده"
    ] as const
  },
  sortBy: {
    type: "single" as const,
    options: ["ارتباط", "تاریخ آپلود", "تعداد بازدید", "رتبه‌بندی"] as const
  }
} as const;

const FILTER_LABELS: Record<string, string> = {
  platforms: "پلتفرم‌ها", 
  uploadDate: "تاریخ آپلود",
  type: "نوع",
  duration: "مدت زمان",
  features: "ویژگی‌ها",
  sortBy: "مرتب‌سازی بر اساس"
};

const PLATFORM_ICONS: Record<string, React.ElementType> = {
  تردز: MessageSquare,
  اینستاگرام: Instagram,
  "X (توییتر)": Twitter,
  "تیک تاک": Film,
  یوتوب: Youtube
};

const PLATFORM_COLORS: Record<string, string> = {
  تردز: "#1DA1F2",
  اینستاگرام: "#E1306C",
  "X (توییتر)": "#1DA1F2",
  "تیک تاک": "#69C9D0",
  یوتوب: "#FF0000"
};

const FILTER_ICONS: Record<string, Record<string, React.ElementType>> = {
  uploadDate: {
    "یک ساعت گذشته": Clock,
    امروز: Clock,
    "این هفته": Clock,
    "این ماه": Clock,
    امسال: Clock
  },
  type: {
    ویدیو: Film,
    کانال: Image,
    "لیست پخش": ListVideo,
    فیلم: Clapperboard
  },
  duration: {
    "زیر ۴ دقیقه": Clock,
    "۴ تا ۲۰ دقیقه": Clock,
    "بالای ۲۰ دقیقه": Clock
  },
  features: {
    زنده: Activity,
    "۴K": Monitor,
    HD: Monitor,
    "زیرنویس/متن": Subtitles,
    "کپی‌رایت آزاد": CopyCheck,
    "۳۶۰ درجه": Image,
    VR180: Glasses,
    "۳D": Box,
    HDR: Monitor,
    مکان: MapPin,
    "خریداری شده": ShoppingCart
  },
  sortBy: {
    ارتباط: MessageSquare,
    "تاریخ آپلود": Clock,
    "تعداد بازدید": Eye,
    رتبه‌بندی: TrendingUp
  }
};

const CustomToggleGroup = ToggleGroup as React.FC<{
  type: "single" | "multiple";
  value: string | string[];
  onValueChange: (value: string | string[]) => void;
  variant: "outline";
  className: string;
  children: React.ReactNode;
}>;

export function FilterMenu() {
  const [uploadDate, setUploadDate] = React.useState("");
  const [selectedType, setSelectedType] = React.useState<string[]>([]);
  const [selectedDuration, setSelectedDuration] = React.useState<string[]>([]);
  const [selectedFeatures, setSelectedFeatures] = React.useState<string[]>([]);
  const [sortBy, setSortBy] = React.useState("");
  const isDesktop = useMediaQuery("(min-width: 768px)");

  const renderFilterGroup = (
    label: string,
    items: readonly string[],
    value: string | string[],
    onChange: (value: string | string[]) => void,
    type: "single" | "multiple"
  ) => (
    <div className="space-y-2 px-4 md:px-[1px] flex flex-col justify-center items-start text-right">
      <h4 className="text-sm font-medium">{label}</h4>
      <CustomToggleGroup
        type={type}
        value={value}
        onValueChange={onChange}
        variant="outline"
        className="flex flex-wrap justify-end items-start text-right gap-1"
      >
        {(items as string[]).map((item) => {
          let IconComponent: React.ElementType | null = null;
          let iconColor = "currentColor";

          if (label === FILTER_LABELS.platforms) {
            IconComponent = PLATFORM_ICONS[item] || null;
            iconColor = PLATFORM_COLORS[item] || "currentColor";
          } else {
            const filterKey = Object.keys(FILTER_LABELS).find(
              (key) => FILTER_LABELS[key] === label
            );
            if (filterKey && FILTER_ICONS[filterKey]?.[item]) {
              IconComponent = FILTER_ICONS[filterKey]?.[item] || null;
            }
          }

          return (
            <ToggleGroupItem
              key={item}
              value={item.toLowerCase().replace(/\s+/g, "-")}
              aria-label={`انتخاب ${item}`}
              className="h-8 px-2 text-xs data-[state=on]:bg-primary data-[state=on]:text-primary-foreground flex items-center gap-1"
            >
              {IconComponent && (
                <IconComponent
                  size={16}
                  color={iconColor}
                  className="inline-block"
                />
              )}
              {item}
            </ToggleGroupItem>
          );
        })}
      </CustomToggleGroup>
    </div>
  );

  const FilterContent = () => (
    <div dir="rtl" className="grid gap-4 max-h-[80vh] overflow-y-auto">
      {Object.entries(FILTER_OPTIONS).map(([key, config]) => {
        const states: Record<string, any> = {
          uploadDate: uploadDate,
          type: selectedType,
          duration: selectedDuration,
          features: selectedFeatures,
          sortBy: sortBy
        };

        const handlers: Record<string, any> = {
          uploadDate: setUploadDate,
          type: setSelectedType,
          duration: setSelectedDuration,
          features: setSelectedFeatures,
          sortBy: setSortBy
        };

        return (
          <React.Fragment key={key}>
            {renderFilterGroup(
              FILTER_LABELS[key] || key,
              config.options,
              states[key],
              handlers[key],
              config.type
            )}
          </React.Fragment>
        );
      })}
      <div className="StickyBtn sticky bottom-0 bg-background">
        <Button className="w-full">اعمال فیلترها</Button>
      </div>
    </div>
  );

  if (isDesktop) {
    return (
      <Popover>
        <PopoverTrigger asChild>
          <button
            className="absolute inset-y-0 end-0 flex h-full w-9 items-center justify-center rounded-e-lg text-muted-foreground/80 outline-offset-2 transition-colors hover:text-foreground focus:z-10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring/70 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50"
            aria-label="فیلتر"
            type="button"
          >
            <SlidersHorizontal size={16} strokeWidth={2} aria-hidden="true" />
          </button>
        </PopoverTrigger>
        <PopoverContent dir="rtl" className="w-[80vw] max-w-3xl" align="end">
          <FilterContent />
        </PopoverContent>
      </Popover>
    );
  }

  return (
    <Drawer>
      <DrawerTrigger asChild>
        <button
          className="absolute inset-y-0 end-0 flex h-full w-9 items-center justify-center rounded-e-lg text-muted-foreground/80 outline-offset-2 transition-colors hover:text-foreground focus:z-10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring/70 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50"
          aria-label="فیلتر"
          type="button"
        >
          <SlidersHorizontal size={16} strokeWidth={2} aria-hidden="true" />
        </button>
      </DrawerTrigger>
      <DrawerContent dir="rtl" className="max-h-[90vh]">
        <FilterContent />
      </DrawerContent>
    </Drawer>
  );
}
