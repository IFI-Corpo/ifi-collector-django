interface MenuItem {
  title: string;
  links: {
    text: string;
    url: string;
  }[];
}

interface FooterProps {
  logo?: {
    url: string;
    src: string;
    alt: string;
    title: string;
  };
  tagline?: string;
  menuItems?: MenuItem[];
  copyright?: string;
  bottomLinks?: {
    text: string;
    url: string;
  }[];
}

const Footer = ({
  logo = {
    src: "",
    alt: "Aggregator of Social Media Content",
    title: "IFI Collector",
    url: ""
  },
  tagline = "با ترندها و تحلیل‌های جدید همیشه به‌روز باشید.",
  menuItems = [
    {
      title: "پلتفرم",
      links: [
        { text: "معرفی", url: "#" },
        { text: "چگونه کار می‌کند", url: "#" },
        { text: "ویژگی‌ها", url: "#" },
        { text: "تحلیل‌های هوش مصنوعی", url: "#" },
        { text: "قیمت‌گذاری", url: "#" },
        { text: "ادغام‌ها", url: "#" }
      ]
    },
    {
      title: "شرکت",
      links: [
        { text: "درباره ما", url: "#" },
        { text: "تیم ما", url: "#" },
        { text: "وبلاگ", url: "#" },
        { text: "فرصت‌های شغلی", url: "#" },
        { text: "تماس با ما", url: "#" },
        { text: "سیاست حریم خصوصی", url: "#" }
      ]
    },
    {
      title: "منابع",
      links: [
        { text: "مرکز کمک", url: "#" },
        { text: "درخواست فروش", url: "#" },
        { text: "تبلیغات با ما", url: "#" },
        { text: "مستندات API", url: "#" }
      ]
    },
    {
      title: "شبکه‌های اجتماعی",
      links: [
        { text: "توییتر", url: "#" },
        { text: "اینستاگرام", url: "#" },
        { text: "لینکدین", url: "#" },
        { text: "یوتیوب", url: "#" },
        { text: "فیس‌بوک", url: "#" }
      ]
    }
  ],
  copyright = "© 2025 IFI Collector کلیه حقوق محفوظ است.",
  bottomLinks = [
    { text: "شرایط استفاده", url: "#" },
    { text: "سیاست حریم خصوصی", url: "#" },
    { text: "سیاست کوکی‌ها", url: "#" }
  ]
}: FooterProps) => {
  return (
    <section className="pt-32 mx-auto">
      <div className="container mx-auto" dir="rtl">
        <footer>
          <div className="grid grid-cols-2 gap-8 lg:grid-cols-6">
            <div className="col-span-2 mb-8 lg:mb-0">
              <div className="flex items-center text-center gap-2 lg:justify-start">
                <p className="text-xl text-center font-[Doran]">{logo.title}</p>
              </div>
              <p className="mt-4 font-bold">{tagline}</p>
            </div>
            {menuItems.map((section, sectionIdx) => (
              <div key={sectionIdx}>
                <h3 className="mb-4 font-bold">{section.title}</h3>
                <ul className="space-y-4 text-muted-foreground">
                  {section.links.map((link, linkIdx) => (
                    <li
                      key={linkIdx}
                      className="font-medium transition-all duration-300 hover:text-primary"
                    >
                      <a href={link.url}>{link.text}</a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <div className="mt-24 flex flex-col justify-between gap-4 border-t pt-8 text-sm font-medium text-muted-foreground md:flex-row md:items-center">
            <p>{copyright}</p>
            <ul className="flex gap-4">
              {bottomLinks.map((link, linkIdx) => (
                <li key={linkIdx} className="underline transition-all duration-300 hover:text-primary">
                  <a href={link.url}>{link.text}</a>
                </li>
              ))}
            </ul>
          </div>
        </footer>
      </div>
    </section>
  );
};

export { Footer };
