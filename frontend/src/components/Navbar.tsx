import { Link } from "react-router-dom";
import { useState } from "react";
import {
  MenuIcon,
  Youtube,
  Twitter,
  Instagram,
  MessageSquare
} from "lucide-react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import {
  NavigationMenu,
  NavigationMenuContent,
  NavigationMenuItem,
  NavigationMenuList,
  NavigationMenuTrigger,
  navigationMenuTriggerStyle
} from "@/components/ui/navigation-menu";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger
} from "@/components/ui/sheet";
import { ShinyButton } from "@/components/magicui/shiny-button";
import { RainbowButton } from "@/components/magicui/rainbow-button";
import ThemeToggle from "./effectlib/ThemeToggle";

const Navbar = () => {
  const overviews = [
    {
      title: "یوتوب",
      description: "قسمت خلاصات و برنامه‌های مربوط به تحلیل ویدیوهای یوتوب",
      to: "/youtube",
      icon: <Youtube size={16} color="#FF0000" />
    },
    {
      title: "توییتر",
      description:
        "قسمت خلاصات و برنامه‌های مربوط به تحلیل توییت‌ها و ویژگی‌های پلتفرم X",
      to: "/twitter",
      icon: <Twitter size={16} color="#1DA1F2" />
    },
    {
      title: "اینستاگرام",
      description: "قسمت خلاصات و برنامه‌های مربوط به تحلیل پست‌های اینستاگرام",
      to: "/instagram",
      icon: <Instagram size={16} color="#E4405F" />
    },
    {
      title: "تردز",
      description: "قسمت خلاصات و برنامه‌های مربوط به تحلیل پست‌های تردز",
      to: "/threads",
      icon: <MessageSquare size={16} color="#25D366" />
    }
  ];

  const [isSheetOpen, setIsSheetOpen] = useState(false);

  return (
    <nav className="Nav flex justify-center items-center py-4 bg-transparent z-50">
      <div className="container">
        <nav className="flex items-center justify-between">
          <div className="hidden items-center gap-4 lg:flex">
            <RainbowButton>درباره‌ما</RainbowButton>
            <ShinyButton>تماس‌باما</ShinyButton>
            <ThemeToggle />
          </div>
          <NavigationMenu className="hidden lg:block">
            <NavigationMenuList>
              <NavigationMenuItem>
                <Link to="/hot-videos" className={navigationMenuTriggerStyle()}>
                  ویدیوهای داغ
                </Link>
              </NavigationMenuItem>
              <NavigationMenuItem>
                <Link to="/search" className={navigationMenuTriggerStyle()}>
                  جستجوی پیشرفته
                </Link>
              </NavigationMenuItem>
              <NavigationMenuItem>
                <Link
                  to="/smart-summary"
                  className={navigationMenuTriggerStyle()}
                >
                  جمع‌بندی هوشمند
                </Link>
              </NavigationMenuItem>
              <NavigationMenuItem className="text-center">
                <NavigationMenuTrigger>دسته‌بندی‌ها</NavigationMenuTrigger>
                <NavigationMenuContent>
                  <div className="grid w-[600px] grid-cols-2 p-1">
                    {overviews.map((overview, index) => (
                      <Link
                        to={overview.to}
                        key={index}
                        className="CateBtn rounded-md text-center p-3 m-1 transition-colors hover:bg-muted/70"
                      >
                        <div className="flex flex-col justify-end items-end text-right">
                          <p className="flex flex-row items-center space-x-2 mb-1 font-semibold">
                            <span className="ml-2">{overview.icon}</span>
                            <span>{overview.title}</span>
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {overview.description}
                          </p>
                        </div>
                      </Link>
                    ))}
                  </div>
                </NavigationMenuContent>
              </NavigationMenuItem>
            </NavigationMenuList>
          </NavigationMenu>
          <div className="flex items-center gap-2">
            <span className="text-lg font-semibold">
              <Link to="/">IFI•Collector</Link>
            </span>
          </div>
          <Sheet open={isSheetOpen} onOpenChange={setIsSheetOpen}>
            <SheetTrigger asChild className="lg:hidden">
              <Button
                variant="outline"
                size="icon"
                onClick={() => setIsSheetOpen(true)}
              >
                <MenuIcon className="h-5 w-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" className="max-h-screen overflow-y-auto">
              <SheetHeader>
                <SheetTitle>
                  <div className="flex items-center gap-4">
                    <span className="text-lg font-semibold">IFI•Collector</span>
                  </div>
                </SheetTitle>
              </SheetHeader>
              <div className="flex flex-col" dir="rtl">
                <Accordion type="single" collapsible className="mb-2 mt-4">
                  <AccordionItem value="solutions" className="border-none">
                    <AccordionTrigger className="hover:no-underline">
                      دسته‌بندی‌ها
                    </AccordionTrigger>
                    <AccordionContent>
                      <div className="grid md:grid-cols-2">
                        {overviews.map((overview, index) => (
                          <Link
                            to={overview.to}
                            key={index}
                            className="rounded-md p-3 transition-colors hover:bg-muted/70"
                            onClick={() => setIsSheetOpen(false)} // Close Sheet on Click
                          >
                            <div>
                              <p className="flex flex-row items-center space-x-2 mb-1 font-semibold">
                                <span className="ml-2">{overview.icon}</span>
                                <span>{overview.title}</span>
                              </p>
                              <p className="text-sm text-muted-foreground">
                                {overview.description}
                              </p>
                            </div>
                          </Link>
                        ))}
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                </Accordion>
                <div className="flex flex-col gap-6">
                  <Link
                    to="/smart-summary"
                    className="font-medium"
                    onClick={() => setIsSheetOpen(false)}
                  >
                    جمع‌بندی هوشمند
                  </Link>
                  <Link
                    to="/search"
                    className="font-medium"
                    onClick={() => setIsSheetOpen(false)}
                  >
                    جستجوی پیشرفته
                  </Link>
                  <Link
                    to="/hot-videos"
                    className="font-medium"
                    onClick={() => setIsSheetOpen(false)}
                  >
                    ویدیوهای داغ
                  </Link>
                </div>
                <div className="flex flex-col mt-5 space-y-2">
                  <ThemeToggle />
                  <ShinyButton onClick={() => setIsSheetOpen(false)}>
                    تماس‌باما
                  </ShinyButton>
                  <RainbowButton onClick={() => setIsSheetOpen(false)}>
                    درباره‌ما
                  </RainbowButton>
                </div>
              </div>
            </SheetContent>
          </Sheet>
        </nav>
      </div>
    </nav>
  );
};

export default Navbar;
