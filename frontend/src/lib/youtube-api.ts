/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-case-declarations */
let YOUTUBE_API_KEY =
  localStorage.getItem("YOUTUBE_API_KEY") ||
  "AIzaSyAeAfT6USQFiWCgNOazeBiPl3IabD27l2k";
let GEMINI_API_KEY =
  localStorage.getItem("GEMINI_API_KEY") ||
  "AIzaSyDMm6SM7x9zKkxV_5WdpwG-wJRusN7xm0E";
let INSTAGRAM_API_KEY = localStorage.getItem("INSTAGRAM_API_KEY") || "";
let TWITTER_API_KEY = localStorage.getItem("TWITTER_API_KEY") || "";

export const updateYoutubeApiKey = (newKey: string) => {
  YOUTUBE_API_KEY = newKey;
  localStorage.setItem("YOUTUBE_API_KEY", newKey);
};

export const updateGeminiApiKey = (newKey: string) => {
  GEMINI_API_KEY = newKey;
  localStorage.setItem("GEMINI_API_KEY", newKey);
};

export const updateInstagramApiKey = (newKey: string) => {
  INSTAGRAM_API_KEY = newKey;
  localStorage.setItem("INSTAGRAM_API_KEY", newKey);
};

export const updateTwitterApiKey = (newKey: string) => {
  TWITTER_API_KEY = newKey;
  localStorage.setItem("TWITTER_API_KEY", newKey);
};

export const getYoutubeApiKey = () => YOUTUBE_API_KEY;
export const getGeminiApiKey = () => GEMINI_API_KEY;
export const getInstagramApiKey = () => INSTAGRAM_API_KEY;
export const getTwitterApiKey = () => TWITTER_API_KEY;

type Filters = {
  sortBy?: string;
  uploadDate?: string;
  platforms?: string[];
  type?: string;
};

export interface VideoItem {
  kind: string;
  id: string;
  title: string;
  description: string;
  publishedAt: string;
  thumbnail: string;
  url: string;
  views: string;
  likes: string;
  comments: string;
  duration: number;
  channelTitle: string;
}

export const formatNumber = (number?: string | number): string => {
  if (!number) return "N/A";
  const num = typeof number === "string" ? parseInt(number) : number;
  if (isNaN(num)) return "N/A";

  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return num.toLocaleString();
};

export const formatDate = (date: Date): string => {
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
};

const getISODate = (filter: string): string => {
  const now = new Date();
  switch (filter) {
    case "یک ساعت گذشته":
      now.setHours(now.getHours() - 1);
      break;
    case "امروز":
      now.setHours(0, 0, 0, 0);
      break;
    case "این هفته":
      const dayOfWeek = now.getDay();
      now.setDate(now.getDate() - dayOfWeek);
      now.setHours(0, 0, 0, 0);
      break;
    case "این ماه":
      now.setDate(1);
      now.setHours(0, 0, 0, 0);
      break;
    case "امسال":
      now.setFullYear(new Date().getFullYear());
      now.setMonth(0, 1);
      now.setHours(0, 0, 0, 0);
      break;
    default:
      return "";
  }
  return now.toISOString();
};

const parseISODuration = (duration: string): number => {
  const match = duration.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
  if (!match) return 0;
  const hours = parseInt(match[1] || "0", 10);
  const minutes = parseInt(match[2] || "0", 10);
  const seconds = parseInt(match[3] || "0", 10);
  return hours * 3600 + minutes * 60 + seconds;
};

export const getVideoSummary = async (videoUrl: string): Promise<string> => {
  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: `Provide a concise summary of this YouTube video: ${videoUrl}`,
                },
              ],
            },
          ],
        }),
      },
    );

    const data = await response.json();
    return (
      data.candidates?.[0]?.content?.parts?.[0]?.text || "No summary available."
    );
  } catch (error) {
    console.error("Gemini API error:", error);
    return "Error generating summary.";
  }
};

export const youtubeSearch = async (
  query: string,
  maxResults = 10,
  filters: Filters = {},
): Promise<VideoItem[]> => {
  try {
    const params = new URLSearchParams({
      part: "snippet",
      maxResults: maxResults.toString(),
      q: query,
      key: YOUTUBE_API_KEY,
    });

    if (filters.type === "کانال") {
      params.set("type", "channel");
    } else {
      params.set("type", "video");
    }

    if (filters.sortBy) {
      switch (filters.sortBy) {
        case "تعداد بازدید":
          params.set("order", "viewCount");
          break;
        case "تعداد نظرات":
          params.set("order", "relevance");
          break;
        case "تعداد لایک‌ها":
          params.set("order", "relevance");
          break;
        default:
          params.set("order", "relevance");
      }
    }

    if (filters.uploadDate) {
      const isoDate = getISODate(filters.uploadDate);
      if (isoDate) {
        params.set("publishedAfter", isoDate);
      }
    }

    const searchRes = await fetch(
      `https://www.googleapis.com/youtube/v3/search?${params}`,
    );
    const searchData = await searchRes.json();
    if (!searchData.items?.length) return [];

    const itemIds = searchData.items
      .map((item: any) => {
        if (!item.id) return null;
        return filters.type === "کانال" ? item.id.channelId : item.id.videoId;
      })
      .filter((id: string | null) => id !== null);

    const detailsRes = await fetch(
      `https://www.googleapis.com/youtube/v3/${
        filters.type === "کانال" ? "channels" : "videos"
      }?part=snippet,statistics${
        filters.type !== "کانال" ? ",contentDetails" : ""
      }&id=${itemIds.join(",")}&key=${YOUTUBE_API_KEY}`,
    );
    const detailsData = await detailsRes.json();

    const results: VideoItem[] = searchData.items
      .map((item: any) => {
        if (!item.id) return null;

        const details = detailsData.items.find(
          (detail: any) =>
            detail.id ===
            (filters.type === "کانال" ? item.id.channelId : item.id.videoId),
        );
        if (!details) return null;

        let durationSeconds = 0;
        if (filters.type !== "کانال") {
          durationSeconds = parseISODuration(details.contentDetails.duration);
        }

        const stats = details.statistics || {};
        const url =
          filters.type === "کانال"
            ? `https://www.youtube.com/channel/${details.id}`
            : `https://www.youtube.com/watch?v=${details.id}`;

        return {
          title: details.snippet.title,
          description: details.snippet.description,
          summary: "",
          url,
          views: formatNumber(stats.viewCount),
          likes: formatNumber(stats.likeCount),
          comments: formatNumber(stats.commentCount),
          publishedAt: formatDate(new Date(details.snippet.publishedAt)),
          thumbnail:
            details.snippet.thumbnails?.medium?.url ||
            "/fallback-thumbnail.jpg",
          duration: durationSeconds,
        };
      })
      .filter((item: VideoItem | null) => item !== null);

    if (filters.type === "کوتاه") {
      return results.filter((item) => item.duration <= 60);
    } else if (filters.type === "بلند") {
      return results.filter((item) => item.duration > 60);
    }

    return results;
  } catch (error) {
    console.error("YouTube API error:", error);
    return [];
  }
};
