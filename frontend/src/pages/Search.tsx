"use client";
import { useState } from "react";
import SearchInput from "@/components/searchinput";
import CardModule from "@/components/CardModule";
import { ScrollProgress } from "@/components/magicui/scroll-progress";
import { VideoItem } from "@/lib/youtube-api";
import Bounce from "@/components/effectlib/Bounce";

export default function Search() {
  const [results, setResults] = useState<VideoItem[]>([]);

  return (
    <div className="SearchCon flex flex-col justify-center items-center text-center space-y-9">
      <ScrollProgress className="top-0" />
      <Bounce className="Row-1" delay={0.2} duration={0.6} bounceHeight={30}>
        <div className="mt-10">
          <SearchInput onSearch={setResults} />
        </div>
      </Bounce>

      <Bounce className="Row-1" delay={0.4} duration={0.6} bounceHeight={30}>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 container mb-10">
          {results.length > 0 ? (
            results.map((video) => (
              <CardModule
                key={video.id}
                title={video.title}
                description={video.description}
                views={video.views}
                likes={video.likes}
                comments={video.comments}
                shares="N/A"
                publishedAt={video.publishedAt}
                thumbnail={video.thumbnail}
                url={video.url}
              />
            ))
          ) : (
            <p className="text-center text-muted-foreground mx-auto col-span-full flex items-center justify-center h-32">
              !هنوز هیچ نتیجه ای وجود ندارد. شروع به جستجو کنید
            </p>
          )}
        </div>
      </Bounce>
    </div>
  );
}
