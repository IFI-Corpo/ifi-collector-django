import { Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollProgress } from "@/components/magicui/scroll-progress";
import { SparklesText } from "@/components/magicui/sparkles-text";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger
} from "@/components/ui/accordion";
import { AnimatedBeamSection } from "@/components/effectlib/AnimatedBeamSection";
import Bounce from "@/components/effectlib/Bounce";
import { TextShine } from "@/components/effectlib/TextShine";
import CanvasCursor from "@/components/effectlib/canvas-cursor";
import Pricing from "@/components/pricingSection";
import { Separator } from "@/components/ui/separator";
import { Footer } from "@/components/Footer";


interface FaqItem {
  question: string;
  answer: string;
}

interface HomeProps {
  icon?: React.ReactNode;
  heading?: string;
  descriptionOne?: React.ReactNode;
  descriptionTwo?: React.ReactNode;
  button?: {
    text: string;
    icon?: React.ReactNode;
    url: string;
  };
  trustText?: string;
  imageSrc?: string;
  imageAlt?: string;
}

const faqItems: FaqItem[] = [
  {
    question:
      "این وب‌سایت چگونه پست‌ها و ویدیوها را از پلتفرم‌های مختلف جمع‌آوری می‌کند؟",
    answer:
      "وب‌سایت با استفاده از APIهای رسمی پلتفرم‌ها مانند توییتر، اینستاگرام و تردز، پست‌ها و ویدیوهای محبوب را بر اساس تعداد لایک‌ها و بازدیدها جمع‌آوری می‌کند."
  },
  {
    question: "چگونه می‌توانم پست‌های مرتبط با موضوعات خاص را پیدا کنم؟",
    answer:
      "شما می‌توانید از فیلترهای موجود در وب‌سایت برای جستجوی پست‌ها بر اساس موضوعاتی مانند برنامه‌نویسی، تناسب اندام و غیره استفاده کنید."
  },
  {
    question: "آیا می‌توانم جزئیات بیشتری درباره‌ی یک پست یا ویدیو ببینم؟",
    answer:
      "بله، با کلیک بر روی کارت هر پست، می‌توانید جزئیات بیشتری مانند تعداد لایک‌ها، نظرات، اشتراک‌گذاری‌ها و تحلیل‌های مرتبط را مشاهده کنید."
  },
  {
    question: "چگونه وب‌سایت دلیل محبوبیت یک پست را تحلیل می‌کند؟",
    answer:
      "وب‌سایت با استفاده از الگوریتم‌های هوش مصنوعی و تحلیل محتوا، دلایل احتمالی محبوبیت یک پست را شناسایی کرده و به شما نمایش می‌دهد."
  },
  {
    question: "آیا می‌توانم خلاصه‌ای از پست‌ها یا ویدیوها دریافت کنم؟",
    answer:
      "بله، وب‌سایت با استفاده از یک چت‌بات مبتنی بر هوش مصنوعی، خلاصه‌ای از پست‌ها و ویدیوها را در اختیار شما قرار می‌دهد."
  },
  {
    question:
      "هر چند وقت یک‌بار پست‌ها و ویدیوهای جدید به وب‌سایت اضافه می‌شوند؟",
    answer:
      "وب‌سایت به‌صورت دوره‌ای، هر ۳ تا ۵ روز، پست‌ها و ویدیوهای جدید را جمع‌آوری کرده و به لیست اضافه می‌کند."
  }
];

const Home = ({
  heading = "بهترین‌ها رو از دست نده برگزیده‌ای از شبکه‌های اجتماعی",
  descriptionOne = (
    <>
      پلتفرم هوشمند ما با استفاده از{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        هوش مصنوعی
      </span>
      ، محتوای شبکه‌های اجتماعی مانند{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        توییت‌ها
      </span>
      ،{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        پست‌ها
      </span>{" "}
      و{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        ویدیوهای یوتیوب
      </span>{" "}
      را با دقت مورد تحلیل قرار می‌دهد. این تحلیل به ما کمک می‌کند تا دریابیم چه
      عواملی باعث{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        افزایش بازدید
      </span>{" "}
      و{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        تعامل با محتوا
      </span>{" "}
      شده‌اند.
    </>
  ),

  descriptionTwo = (
    <>
      با{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        پلتفرم هوشمند
      </span>{" "}
      ما، دیگر نیازی نیست{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        زمان
      </span>{" "}
      زیادی را صرف{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        جستجو
      </span>{" "}
      و{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        تحلیل محتوا‌های
      </span>{" "}
      مختلف کنید. ما{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        خلاصه‌ای جامع
      </span>{" "}
      از مطالب اصلی و{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        عوامل موفقیت
      </span>{" "}
      آن‌ها را در اختیار شما قرار می‌دهیم. با استفاده از این اطلاعات می‌توانید{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        استراتژی‌های محتوایی
      </span>{" "}
      خود را بهبود بخشید و محتوایی{" "}
      <span className="txtshadow font-[Doran] text-[var(--text-color)]">
        جذاب‌تر و مؤثرتر
      </span>{" "}
      تولید کنید.
    </>
  ),
  button = {
    text: "مشاهده امکانات",
    icon: <Zap className="ml-2 size-4" />,
    url: ""
  },
  trustText = "اعتماد بیش از 0 کسب‌وکار در سراسر جهان"
}: HomeProps) => {
  return (
    <>
      <CanvasCursor />
      <ScrollProgress className="top-0" />
      <div className="flex flex-col justify-center items-center text-center mt-10 md:mt-20">
        <Bounce className="Row-1" delay={0.2} duration={0.6} bounceHeight={30}>
          <h2 className="mx-10 max-w-screen-lg text-balance font-[Doran]">
            <SparklesText text={heading} className="text-3xl lg:text-5xl" />
          </h2>
        </Bounce>

        <Bounce className="Row-1" delay={0.3} duration={0.6} bounceHeight={30}>
          <p className="mx-10 mt-10 max-w-screen-md text-center text-muted-foreground md:text-lg">
            {descriptionOne}
          </p>
        </Bounce>

        <Bounce className="Row-1" delay={0.4} duration={0.6} bounceHeight={30}>
          <p className="mx-10 mt-3 max-w-screen-md text-center text-muted-foreground md:text-lg">
            {descriptionTwo}
          </p>
        </Bounce>

        <Bounce className="Row-1" delay={0.5} duration={0.6} bounceHeight={30}>
          <Button
            size="lg"
            asChild
            effect="expandIcon"
            icon={Zap}
            iconPlacement="left"
            className="rounded-full mt-16"
          >
            <a href={button.url}>{button.text}</a>
          </Button>
          {trustText && (
            <div className="text-xs mt-3 text-muted-foreground">
              <TextShine
                text={trustText}
                shineColor="var(--Circ)"
                duration={2}
              />
            </div>
          )}
        </Bounce>

        <Bounce
          className="Row-1 mt-20"
          delay={0.6}
          duration={0.6}
          bounceHeight={30}
        >
          <AnimatedBeamSection />
        </Bounce>
      </div>

      <Bounce
        className="Row-1 mt-20"
        delay={0.6}
        duration={0.6}
        bounceHeight={30}
      >
        <Separator className="mt-10 bg-[var(--Separator)] w-[70%] lg:w-[50%] mx-auto" />
      </Bounce>

      <Bounce
        className="Row-1 mt-10"
        delay={0.8}
        duration={0.6}
        bounceHeight={30}
      >
        <Pricing />
      </Bounce>

      <Bounce
        className="Row-1 mt-20"
        delay={0.8}
        duration={0.6}
        bounceHeight={30}
      >
        <Separator className="mt-10 bg-[var(--Separator)] w-[70%] lg:w-[50%] mx-auto" />
      </Bounce>

      <Bounce
        className="Row-1 my-20"
        delay={0.7}
        duration={0.6}
        bounceHeight={30}
      >
        <div className="container mx-auto" dir="rtl">
          <h1 className="text-center mb-4 text-3xl font-semibold md:mb-11 md:text-5xl">
            سوالات متداول
          </h1>
          <Accordion
            dir="rtl"
            type="single"
            collapsible
            className="flex flex-col justify-start text-right w-full"
          >
            {faqItems.map((item, index) => (
              <AccordionItem key={index} value={`item-${index}`}>
                <AccordionTrigger className="hover:text-foreground/60 hover:no-underline">
                  {item.question}
                </AccordionTrigger>
                <AccordionContent>{item.answer}</AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </div>
      </Bounce>

      <Bounce
        className="Row-1 my-20"
        delay={0.8}
        duration={0.6}
        bounceHeight={30}
      >
        <Footer />
      </Bounce>
    </>
  );
};

export default Home;
