"use client";
import { useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Heart, MessageSquare, Share, Eye } from "lucide-react";
import { getVideoSummary } from "@/lib/youtube-api";
import { ArrowUpLeft } from "lucide-react";
import { cn } from "@/lib/utils";
import { AnimatedShinyText } from "@/components/magicui/animated-shiny-text";
import { ScrollProgress } from "@/components/magicui/scroll-progress";
import Bounce from "@/components/effectlib/Bounce";
import { ExpandableCard } from "@/components/ExpandableCard";

interface CardDetailProps {
  title: string;
  description: string;
  summary?: string;
  views: string;
  likes: string;
  comments: string;
  shares: string;
  publishedAt: string;
  thumbnail: string;
  url: string;
}

export default function CardDetail() {
  const location = useLocation();
  const {
    title,
    description,
    summary: initialSummary,
    views,
    likes,
    comments,
    shares,
    publishedAt,
    thumbnail,
    url
  } = location.state as CardDetailProps;

  const [summary, setSummary] = useState<string>(
    initialSummary || "Loading summary..."
  );

  const isPersian = (text: string): boolean => {
    const persianRegex = /[\u0600-\u06FF]/;
    return persianRegex.test(text);
  };

  useEffect(() => {
    const fetchSummary = async () => {
      const fetchedSummary = await getVideoSummary(url);
      setSummary(fetchedSummary);
    };
    fetchSummary();
  }, [url]);

  return (
    <div className="flex flex-col justify-center items-center text-center my-2 lg:my-5 mx-2">
      <ScrollProgress className="top-0" />
      <Bounce className="Row-1" delay={0.2} duration={0.6} bounceHeight={30}>
        <Card className="w-full max-w-4xl border-b-0 border-t-0 p-2">
          <img
            src={thumbnail}
            alt="Video Thumbnail"
            className="w-full h-64 object-cover rounded-md mb-2"
            onError={(e) => {
              e.currentTarget.src = "/fallback-thumbnail.jpg";
            }}
          />
          <CardHeader>
            <CardTitle className="flex flex-row justify-center items-center text-center text-3xl mt-5 font-bold">
              <h1>{title}</h1>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ExpandableCard height="8rem">
              <div dir={isPersian(description) ? "rtl" : "ltr"}>
                <p
                  className={`text-xs md:text-base text-foreground ${
                    isPersian(description) ? "text-right" : "text-left"
                  }`}
                >
                  {description}
                </p>
              </div>
            </ExpandableCard>

            <div className="flex flex-wrap justify-center items-center gap-4 mb-4">
              <div className="flex items-center gap-1 text-purple-500">
                <Eye size={20} />
                <span className="text-sm">{views}</span>
              </div>
              <div className="flex items-center gap-1 text-red-500">
                <Heart size={20} />
                <span className="text-sm">{likes}</span>
              </div>
              <div className="flex items-center gap-1 text-blue-500">
                <MessageSquare size={20} />
                <span className="text-sm">{comments}</span>
              </div>
              <div className="flex items-center gap-1 text-green-500">
                <Share size={20} />
                <span className="text-sm">{shares}</span>
              </div>
            </div>
            <div className="flex flex-col justify-center items-center text-center space-y-2 mb-4">
              <Badge variant="secondary" className="mx-auto mb-2">
                {publishedAt}
              </Badge>

              <div
                className={cn(
                  "group rounded-lg border border-black/5 bg-neutral-100 text-base text-white transition-all ease-in hover:cursor-pointer hover:bg-neutral-200 dark:border-white/5 dark:bg-neutral-900 dark:hover:bg-neutral-800"
                )}
              >
                <AnimatedShinyText className="inline-flex items-center justify-center px-4 py-1 transition ease-out hover:text-neutral-600 hover:duration-300 hover:dark:text-neutral-400">
                  <ArrowUpLeft className="mr-3 size-5 transition-transform duration-300 ease-in-out group-hover:translate-x-0.5" />
                  <a href={url} target="_blank" rel="noopener noreferrer">
                    لینک مشاهده در یوتیوب
                  </a>
                </AnimatedShinyText>
              </div>
            </div>
            <div className="border rounded-lg px-3 py-2">
              <p className="mb-2 font-medium">Ai Summary</p>
              <p className="text-sm md:text-base">{summary}</p>
            </div>
          </CardContent>
        </Card>
      </Bounce>
    </div>
  );
}
