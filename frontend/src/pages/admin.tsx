"use client"; // Required for client-side interactivity

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger
} from "@/components/ui/accordion";
import {
  updateYoutubeApiKey,
  updateGeminiApiKey,
  updateInstagramApiKey,
  updateTwitterApiKey,
  getYoutubeApiKey,
  getGeminiApiKey,
  getInstagramApiKey,
  getTwitterApiKey
} from "@/lib/youtube-api";
import Bounce from "@/components/effectlib/Bounce";

export default function Admin() {
  const [apiKeys, setApiKeys] = useState({
    youtube: getYoutubeApiKey(),
    gemini: getGeminiApiKey(),
    instagram: getInstagramApiKey(),
    twitter: getTwitterApiKey()
  });

  const handleInputChange = (key: string, value: string) => {
    setApiKeys((prev) => ({ ...prev, [key]: value }));
  };

  const handleApplyKey = (type: string) => {
    switch (type) {
      case "youtube":
        updateYoutubeApiKey(apiKeys.youtube);
        break;
      case "gemini":
        updateGeminiApiKey(apiKeys.gemini);
        break;
      case "instagram":
        updateInstagramApiKey(apiKeys.instagram);
        break;
      case "twitter":
        updateTwitterApiKey(apiKeys.twitter);
        break;
      default:
        break;
    }
    alert(`${type.toUpperCase()} API Key Updated!`);
  };

  return (
    <div className="lg:container lg:mx-auto flex flex-col justify-center text-center mx-5 mt-10">
      <Bounce className="Row-1" delay={0.2} duration={0.6} bounceHeight={30}>
        <h1 className="text-xl mb-5">API Recovery Entry</h1>
      </Bounce>
      <Bounce className="Row-1" delay={0.4} duration={0.6} bounceHeight={30}>
        <Accordion type="single" collapsible>
          <AccordionItem value="item-1">
            <AccordionTrigger>Recovery Set 1</AccordionTrigger>
            <AccordionContent className="space-y-2 m-2">
              {/* YouTube API Input */}
              <div className="flex gap-2 *:not-first:mt-2 flex-row justify-center items-center">
                <Input
                  className="flex-1 w-[250px]"
                  placeholder="Youtube API Entry"
                  value={apiKeys.youtube}
                  onChange={(e) => handleInputChange("youtube", e.target.value)}
                />
                <Button
                  className="h-[36px]"
                  variant="outline"
                  onClick={() => handleApplyKey("youtube")}
                >
                  Apply
                </Button>
              </div>

              {/* Gemini API Input */}
              <div className="flex gap-2 *:not-first:mt-2 flex-row justify-center items-center">
                <Input
                  className="flex-1 w-[250px]"
                  placeholder="Gemini API Entry"
                  value={apiKeys.gemini}
                  onChange={(e) => handleInputChange("gemini", e.target.value)}
                />
                <Button
                  className="h-[36px]"
                  variant="outline"
                  onClick={() => handleApplyKey("gemini")}
                >
                  Apply
                </Button>
              </div>

              {/* Instagram API Input */}
              <div className="flex gap-2 *:not-first:mt-2 flex-row justify-center items-center">
                <Input
                  className="flex-1 w-[250px]"
                  placeholder="Instagram API Entry"
                  value={apiKeys.instagram}
                  onChange={(e) =>
                    handleInputChange("instagram", e.target.value)
                  }
                />
                <Button
                  className="h-[36px]"
                  variant="outline"
                  onClick={() => handleApplyKey("instagram")}
                >
                  Apply
                </Button>
              </div>

              {/* Twitter API Input */}
              <div className="flex gap-2 *:not-first:mt-2 flex-row justify-center items-center">
                <Input
                  className="flex-1 w-[250px]"
                  placeholder="Twitter API Entry"
                  value={apiKeys.twitter}
                  onChange={(e) => handleInputChange("twitter", e.target.value)}
                />
                <Button
                  className="h-[36px]"
                  variant="outline"
                  onClick={() => handleApplyKey("twitter")}
                >
                  Apply
                </Button>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </Bounce>
      <Bounce className="Row-1" delay={0.6} duration={0.6} bounceHeight={30}>
        <Accordion type="single" collapsible>
          <AccordionItem value="item-1">
            <AccordionTrigger>Recovery Set 2</AccordionTrigger>
            <AccordionContent className="space-y-2 m-2">
              {/* YouTube API Input */}
              <div className="flex gap-2 *:not-first:mt-2 flex-row justify-center items-center">
                <Input
                  className="flex-1 w-[250px]"
                  placeholder="Youtube API Entry"
                  value={apiKeys.youtube}
                  onChange={(e) => handleInputChange("youtube", e.target.value)}
                />
                <Button
                  className="h-[36px]"
                  variant="outline"
                  onClick={() => handleApplyKey("youtube")}
                >
                  Apply
                </Button>
              </div>

              {/* Gemini API Input */}
              <div className="flex gap-2 *:not-first:mt-2 flex-row justify-center items-center">
                <Input
                  className="flex-1 w-[250px]"
                  placeholder="Gemini API Entry"
                  value={apiKeys.gemini}
                  onChange={(e) => handleInputChange("gemini", e.target.value)}
                />
                <Button
                  className="h-[36px]"
                  variant="outline"
                  onClick={() => handleApplyKey("gemini")}
                >
                  Apply
                </Button>
              </div>

              {/* Instagram API Input */}
              <div className="flex gap-2 *:not-first:mt-2 flex-row justify-center items-center">
                <Input
                  className="flex-1 w-[250px]"
                  placeholder="Instagram API Entry"
                  value={apiKeys.instagram}
                  onChange={(e) =>
                    handleInputChange("instagram", e.target.value)
                  }
                />
                <Button
                  className="h-[36px]"
                  variant="outline"
                  onClick={() => handleApplyKey("instagram")}
                >
                  Apply
                </Button>
              </div>

              {/* Twitter API Input */}
              <div className="flex gap-2 *:not-first:mt-2 flex-row justify-center items-center">
                <Input
                  className="flex-1 w-[250px]"
                  placeholder="Twitter API Entry"
                  value={apiKeys.twitter}
                  onChange={(e) => handleInputChange("twitter", e.target.value)}
                />
                <Button
                  className="h-[36px]"
                  variant="outline"
                  onClick={() => handleApplyKey("twitter")}
                >
                  Apply
                </Button>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </Bounce>
    </div>
  );
}
