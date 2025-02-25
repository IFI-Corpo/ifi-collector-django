import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { CheckIcon, MinusIcon, Check, X } from "lucide-react";
import React from "react";
import { BorderBeam } from "./magicui/border-beam";
import ShimmerButton from "@/components/effectlib/shimmerButton";
import AnimatedBadge from "@/components/ui/animated-badge";

interface PlanFeature {
  type: string;
  features: {
    name: string;
    free: boolean;
    startup: boolean;
    team: boolean;
    enterprise: boolean;
  }[];
}

const planFeatures: PlanFeature[] = [
  {
    type: "داده‌های شبکه‌های اجتماعی",
    features: [
      {
        name: "جمع‌آوری توییت‌ها/پست‌های ترند شده",
        free: true,
        startup: true,
        team: true,
        enterprise: true
      },
      {
        name: "تحلیل لایک‌ها/تعداد نمایش‌ها",
        free: true,
        startup: true,
        team: true,
        enterprise: true
      },
      {
        name: "خلاصه‌سازی رشته‌ها/پست‌ها/ویدیوها",
        free: false,
        startup: false,
        team: true,
        enterprise: true
      }
    ]
  },
  {
    type: "هوش مصنوعی و تحلیل محتوا",
    features: [
      {
        name: "خلاصه‌سازی پست‌ها (چت‌بات هوش مصنوعی)",
        free: false,
        startup: true,
        team: true,
        enterprise: true
      },
      {
        name: "تحلیل احساسات محتوا",
        free: false,
        startup: false,
        team: true,
        enterprise: true
      },
      {
        name: "تحلیل تعاملات (لایک‌ها، اشتراک‌گذاری‌ها، کامنت‌ها)",
        free: true,
        startup: true,
        team: true,
        enterprise: true
      },
      {
        name: "دلیل محبوبیت پست‌ها",
        free: false,
        startup: false,
        team: true,
        enterprise: true
      }
    ]
  },
  {
    type: "تعاملات کاربری و تجربه کاربری",
    features: [
      {
        name: "کارت‌های فهرستی برای پست‌ها",
        free: true,
        startup: true,
        team: true,
        enterprise: true
      },
      {
        name: "صفحه جزئیات پست با تحلیل‌ها",
        free: true,
        startup: true,
        team: true,
        enterprise: true
      },
      {
        name: "فیلتر موضوعات ترند (برنامه‌نویسی، تناسب اندام و ...)",
        free: true,
        startup: true,
        team: true,
        enterprise: true
      },
      {
        name: "زمان‌بندی تعاملات (5 تا 10 پست اخیر)",
        free: true,
        startup: true,
        team: true,
        enterprise: true
      }
    ]
  },
  {
    type: "جمع‌آوری داده‌ها و نظارت",
    features: [
      {
        name: "برنامه زمان‌بندی جمع‌آوری پست‌ها (5-10 پست هر 3-5 روز)",
        free: true,
        startup: true,
        team: true,
        enterprise: true
      },
      {
        name: "فرکانس پست‌های ترند (زمانبندی قابل تنظیم)",
        free: false,
        startup: false,
        team: true,
        enterprise: true
      },
      {
        name: "جمع‌آوری داده‌های تاریخی (ترندها و تحلیل‌های گذشته)",
        free: false,
        startup: false,
        team: true,
        enterprise: true
      }
    ]
  }
];

export default function Pricing() {
  return (
    <>
      {/* Pricing */}
      <div className="container mx-auto py-10 lg:py-10">
        {/* Title */}
        <div className="max-w-2xl mx-auto text-center mb-10 lg:mb-14">
          <h2 className="scroll-m-20 pb-2 text-3xl font-semibold tracking-tight transition-colors first:mt-0">
            قیمت‌گذاری
          </h2>
          <p className="mt-1 text-muted-foreground">
            چه در ابتدای راه باشید و چه در مسیر پیشرفته، پیشنهادات ما بر اساس
            نیازهای شما تغییر می‌کنند
          </p>
        </div>
        {/* End Title */}
        {/* Switch */}
        <div className="flex justify-center items-center">
          <Label htmlFor="payment-schedule" className="me-3">
            ماهانه
          </Label>
          <Switch id="payment-schedule" />
          <Label htmlFor="payment-schedule" className="relative ms-3">
            سالانه
            <span className="absolute -top-10 start-auto -end-28">
              <span className="flex items-center">
                <svg
                  className="w-14 h-8 -me-6"
                  width={45}
                  height={25}
                  viewBox="0 0 45 25"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M43.2951 3.47877C43.8357 3.59191 44.3656 3.24541 44.4788 2.70484C44.5919 2.16427 44.2454 1.63433 43.7049 1.52119L43.2951 3.47877ZM4.63031 24.4936C4.90293 24.9739 5.51329 25.1423 5.99361 24.8697L13.8208 20.4272C14.3011 20.1546 14.4695 19.5443 14.1969 19.0639C13.9242 18.5836 13.3139 18.4152 12.8336 18.6879L5.87608 22.6367L1.92723 15.6792C1.65462 15.1989 1.04426 15.0305 0.563943 15.3031C0.0836291 15.5757 -0.0847477 16.1861 0.187863 16.6664L4.63031 24.4936ZM43.7049 1.52119C32.7389 -0.77401 23.9595 0.99522 17.3905 5.28788C10.8356 9.57127 6.58742 16.2977 4.53601 23.7341L6.46399 24.2659C8.41258 17.2023 12.4144 10.9287 18.4845 6.96211C24.5405 3.00476 32.7611 1.27399 43.2951 3.47877L43.7049 1.52119Z"
                    fill="currentColor"
                    className="text-muted-foreground"
                  />
                </svg>
                <AnimatedBadge
                  text="صرفه‌جویی تا %۱۰"
                  bgColor="bg-[var(--Circ)]"
                  textColor="text-[var(--Ic)]"
                  gradientColor="from-transparent via-[var(--Ic)] to-transparent"
                  className="w-[8rem] text-center"
                />
              </span>
            </span>
          </Label>
        </div>

        <div className="mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 lg:items-center">
          {/* Free Card */}
          <Card className="PriceCard flex flex-col w-full h-auto max-w-xs mx-auto p-2">
            <CardHeader className="text-center pb-2">
              <CardTitle className="mb-7 mt-3">رایگان</CardTitle>
              <span className="font-bold text-5xl">رایگان</span>
            </CardHeader>
            <CardDescription className="text-center mx-3 mt-3">
              همیشه رایگان و برای همیشه در دسترس شما خواهد بود
            </CardDescription>
            <CardContent className="h-full">
              <ul className="mt-7 m-3 space-y-2.5 text-sm">
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">یک کاربر</span>
                </li>
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">ویژگی‌های طرح</span>
                </li>
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">پشتیبانی محصول</span>
                </li>
              </ul>
            </CardContent>
            <CardFooter>
              <ShimmerButton>ثبت‌نام</ShimmerButton>
            </CardFooter>
          </Card>

          {/* Startup Card */}
          <div className="PriceCard rounded-xl relative overflow-hidden border-[0.1px] border-muted">
            <BorderBeam
              className="absolute inset-0"
              size={500}
              duration={6}
              delay={0}
              colorFrom="#cccccc"
              colorTo="#000"
              reverse={false}
              initialOffset={0}
            />
            <Card className="border-none flex flex-col w-full h-auto max-w-xs mx-auto p-2">
              <CardHeader className="text-center pb-2">
                <Badge className="uppercase w-max self-center mb-3">
                  محبوب‌ترین
                </Badge>
                <CardTitle className="!mb-7 mt-3">استارتاپ</CardTitle>
                <span className="font-bold text-5xl relative">
                  1,900
                  <span className="absolute top-0 right-[11.5rem] lg:right-[13.5rem] text-xs px-1 rounded-full">
                    میلیون تومان
                  </span>
                </span>
              </CardHeader>
              <CardDescription className="text-center w-11/12 mx-auto">
                تمام نیازهای پایه برای شروع یک کسب‌وکار جدید
              </CardDescription>
              <CardContent>
                <ul className="mt-7 m-3 space-y-2.5 text-sm">
                  <li className="flex space-x-2">
                    <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                    <span className="text-muted-foreground">۲ کاربر</span>
                  </li>
                  <li className="flex space-x-2">
                    <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                    <span className="text-muted-foreground">ویژگی‌های طرح</span>
                  </li>
                  <li className="flex space-x-2">
                    <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                    <span className="text-muted-foreground">
                      پشتیبانی محصول
                    </span>
                  </li>
                </ul>
              </CardContent>
              <CardFooter>
                <Button className="w-full">ثبت‌نام</Button>
              </CardFooter>
            </Card>
          </div>

          {/* Team Card */}
          <Card className="PriceCard flex flex-col w-full h-auto max-w-xs mx-auto p-2">
            <CardHeader className="text-center pb-2">
              <CardTitle className="mb-7 mt-3">تیم</CardTitle>
              <span className="font-bold text-5xl relative">
                1,900
                <span className="absolute top-0 right-[11.5rem] lg:right-[13.5rem] text-xs px-1 rounded-full">
                  میلیون تومان
                </span>
              </span>
            </CardHeader>
            <CardDescription className="text-center w-11/12 mx-auto">
              تمام نیازهای شما برای یک کسب‌وکار در حال رشد
            </CardDescription>
            <CardContent>
              <ul className="mt-7 m-3 space-y-2.5 text-sm">
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">۵ کاربر</span>
                </li>
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">ویژگی‌های طرح</span>
                </li>
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">پشتیبانی محصول</span>
                </li>
              </ul>
            </CardContent>
            <CardFooter>
              <ShimmerButton>ثبت‌نام</ShimmerButton>
            </CardFooter>
          </Card>

          {/* Enterprise Card */}
          <Card className="PriceCard flex flex-col w-full h-auto max-w-xs mx-auto p-2">
            <CardHeader className="text-center pb-2">
              <CardTitle className="mb-7 mt-3">شرکت</CardTitle>
              <span className="font-bold text-5xl relative">
                1,900
                <span className="absolute top-0 right-[11.5rem] lg:right-[13.5rem] text-xs px-1 rounded-full">
                  میلیون تومان
                </span>
              </span>
            </CardHeader>
            <CardDescription className="text-center w-11/12 mx-auto">
              ویژگی‌های پیشرفته برای مقیاس‌پذیری کسب‌ شما
            </CardDescription>
            <CardContent>
              <ul className="mt-7 m-3 space-y-2.5 text-sm">
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">۱۰ کاربر</span>
                </li>
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">ویژگی‌های طرح</span>
                </li>
                <li className="flex space-x-2">
                  <CheckIcon className="flex-shrink-0 mt-0.5 h-4 w-4" />
                  <span className="text-muted-foreground">پشتیبانی محصول</span>
                </li>
              </ul>
            </CardContent>
            <CardFooter>
              <ShimmerButton>ثبت‌نام</ShimmerButton>
            </CardFooter>
          </Card>
        </div>

        <div className="mt-20 lg:mt-32">
          <div className="text-center mb-10 lg:mb-20">
            <h3 className="text-2xl font-semibold dark:text-white">
              مقایسه طرح‌ها
            </h3>
          </div>

          <Table
            className="hidden lg:table overflow-hidden rounded-lg"
            dir="rtl"
          >
            <TableHeader>
              <TableRow className="bg-muted hover:bg-muted/80 transition-all">
                <TableHead className="text-primary w-3/12 p-4 text-center">
                  طرح‌ها
                </TableHead>
                <TableHead className="text-primary text-lg font-medium p-4 text-center w-2/12">
                  رایگان
                </TableHead>
                <TableHead className="text-primary text-lg font-medium p-4 text-center w-2/12">
                  استارتاپ
                </TableHead>
                <TableHead className="text-primary text-lg font-medium p-4 text-center w-2/12">
                  تیم
                </TableHead>
                <TableHead className="text-primary text-lg font-medium p-4 text-center w-2/12">
                  شرکت
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody className="">
              {planFeatures.map((featureType) => (
                <React.Fragment key={featureType.type}>
                  <TableRow className="bg-muted/20 hover:bg-muted/30 transition-all">
                    <TableCell
                      colSpan={5}
                      className="font-bold text-lg p-4 text-muted-foreground"
                    >
                      {featureType.type}
                    </TableCell>
                  </TableRow>
                  {featureType.features.map((feature) => (
                    <TableRow
                      key={feature.name}
                      className="hover:bg-muted/10 transition-all"
                    >
                      <TableCell className="p-4 text-muted-foreground">
                        {feature.name}
                      </TableCell>
                      <TableCell className="p-4 text-center">
                        <div className="mx-auto w-min">
                          {feature.free ? (
                            <Check className="h-5 w-5 text-green-500" />
                          ) : (
                            <X className="h-5 w-5 text-red-500" />
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="p-4 text-center">
                        <div className="mx-auto w-min">
                          {feature.startup ? (
                            <Check className="h-5 w-5 text-green-500" />
                          ) : (
                            <X className="h-5 w-5 text-red-500" />
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="p-4 text-center">
                        <div className="mx-auto w-min">
                          {feature.team ? (
                            <Check className="h-5 w-5 text-green-500" />
                          ) : (
                            <X className="h-5 w-5 text-red-500" />
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="p-4 text-center">
                        <div className="mx-auto w-min">
                          {feature.enterprise ? (
                            <Check className="h-5 w-5 text-green-500" />
                          ) : (
                            <X className="h-5 w-5 text-red-500" />
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </React.Fragment>
              ))}
            </TableBody>
          </Table>

          <div className="space-y-24 lg:hidden">
            <section>
              <div className="mb-4 text-center">
                <h4 className="text-xl font-medium">رایگان</h4>
              </div>
              <Table>
                {planFeatures.map((featureType) => (
                  <>
                    <TableRow
                      key={featureType.type}
                      className="bg-muted hover:bg-muted"
                    >
                      <TableCell
                        colSpan={2}
                        className="w-10/12 text-primary font-bold"
                      >
                        {featureType.type}
                      </TableCell>
                    </TableRow>
                    {featureType.features.map((feature) => (
                      <TableRow
                        className="text-muted-foreground"
                        key={feature.name}
                      >
                        <TableCell className="w-11/12">
                          {feature.name}
                        </TableCell>
                        <TableCell className="text-right">
                          {feature.enterprise ? (
                            <CheckIcon className="h-5 w-5" />
                          ) : (
                            <MinusIcon className="h-5 w-5" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </>
                ))}
              </Table>
            </section>
            <section>
              <div className="mb-4 text-center">
                <h4 className="text-xl font-medium">استارتاپ</h4>
              </div>
              <Table>
                {planFeatures.map((featureType) => (
                  <>
                    <TableRow
                      key={featureType.type}
                      className="bg-muted hover:bg-muted"
                    >
                      <TableCell
                        colSpan={2}
                        className="w-10/12 text-primary font-bold"
                      >
                        {featureType.type}
                      </TableCell>
                    </TableRow>
                    {featureType.features.map((feature) => (
                      <TableRow
                        className="text-muted-foreground"
                        key={feature.name}
                      >
                        <TableCell className="w-11/12">
                          {feature.name}
                        </TableCell>
                        <TableCell className="text-right">
                          {feature.startup ? (
                            <CheckIcon className="h-5 w-5" />
                          ) : (
                            <MinusIcon className="h-5 w-5" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </>
                ))}
              </Table>
            </section>
            <section>
              <div className="mb-4 text-center">
                <h4 className="text-xl font-medium">تیم</h4>
              </div>
              <Table>
                {planFeatures.map((featureType) => (
                  <>
                    <TableRow
                      key={featureType.type}
                      className="bg-muted hover:bg-muted"
                    >
                      <TableCell
                        colSpan={2}
                        className="w-10/12 text-primary font-bold"
                      >
                        {featureType.type}
                      </TableCell>
                    </TableRow>
                    {featureType.features.map((feature) => (
                      <TableRow
                        className="text-muted-foreground"
                        key={feature.name}
                      >
                        <TableCell className="w-11/12">
                          {feature.name}
                        </TableCell>
                        <TableCell className="text-right">
                          {feature.team ? (
                            <CheckIcon className="h-5 w-5" />
                          ) : (
                            <MinusIcon className="h-5 w-5" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </>
                ))}
              </Table>
            </section>
            <section>
              <div className="mb-4 text-center">
                <h4 className="text-xl font-medium">شرکت</h4>
              </div>
              <Table>
                {planFeatures.map((featureType) => (
                  <>
                    <TableRow
                      key={featureType.type}
                      className="bg-muted hover:bg-muted"
                    >
                      <TableCell
                        colSpan={2}
                        className="w-10/12 text-primary font-bold"
                      >
                        {featureType.type}
                      </TableCell>
                    </TableRow>
                    {featureType.features.map((feature) => (
                      <TableRow
                        className="text-muted-foreground"
                        key={feature.name}
                      >
                        <TableCell className="w-11/12">
                          {feature.name}
                        </TableCell>
                        <TableCell className="text-right">
                          {feature.enterprise ? (
                            <CheckIcon className="h-5 w-5" />
                          ) : (
                            <MinusIcon className="h-5 w-5" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </>
                ))}
              </Table>
            </section>
          </div>
          {/* End xs to lg */}
        </div>
        {/* End Comparison table */}
      </div>
      {/* End Pricing */}
    </>
  );
}
