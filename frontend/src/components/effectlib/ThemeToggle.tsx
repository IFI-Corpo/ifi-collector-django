import React, { useContext } from "react";
// import { Moon, Sun } from "lucide-react";
import { ThemeContext } from "../../context/ThemeContext";
import { Button } from "@/components/ui/button";
import { MoonIcon } from "../ui/moon";
import { SunIcon } from "../ui/sun";

const ThemeToggle: React.FC = () => {
  const themeContext = useContext(ThemeContext);

  if (!themeContext) {
    throw new Error("ThemeContext must be used within a ThemeProvider");
  }

  const { darkMode, toggleDarkMode } = themeContext;

  return (
    <Button
      className="lg:w-9 lg:h-9"
      variant="outline"
      effect="ringHover"
      onClick={toggleDarkMode}
    >
      {darkMode ? (
        // <Sun size={28} strokeWidth={1.5} />
        <SunIcon />
      ) : (
        // <Moon size={28} strokeWidth={1.5} />
        <MoonIcon />
      )}
    </Button>
  );
};

export default ThemeToggle;
