/** @type {import('tailwindcss').Config} */
const svgToDataUri = require("mini-svg-data-uri");
const {
  default: flattenColorPalette
} = require("tailwindcss/lib/util/flattenColorPalette");

function addVariablesForColors({ addBase, theme }) {
  let allColors = flattenColorPalette(theme("colors"));
  let newVars = Object.fromEntries(
    Object.entries(allColors).map(([key, val]) => [`--${key}`, val])
  );

  addBase({
    ":root": newVars
  });
}

module.exports = {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx,js,jsx}"],
  theme: {
    extend: {
      screens: {
        xs: "300px",
        xss: "250px",
        sm: "640px",
        md: "768px",
        lg: "1024px",
        xl: "1240px"
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)"
      },
      colors: {
        filter: {
          "blur-20": "blur(20px)",
          "blur-25": "blur(25px)"
        },
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))"
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))"
        },
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))"
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))"
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))"
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))"
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))"
        },
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        chart: {
          1: "hsl(var(--chart-1))",
          2: "hsl(var(--chart-2))",
          3: "hsl(var(--chart-3))",
          4: "hsl(var(--chart-4))",
          5: "hsl(var(--chart-5))"
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar-background))",
          foreground: "hsl(var(--sidebar-foreground))",
          primary: "hsl(var(--sidebar-primary))",
          "primary-foreground": "hsl(var(--sidebar-primary-foreground))",
          accent: "hsl(var(--sidebar-accent))",
          "accent-foreground": "hsl(var(--sidebar-accent-foreground))",
          border: "hsl(var(--sidebar-border))",
          ring: "hsl(var(--sidebar-ring))"
        },
        shiki: {
          light: "var(--shiki-light)",
          "light-bg": "var(--shiki-light-bg)",
          dark: "var(--shiki-dark)",
          "dark-bg": "var(--shiki-dark-bg)"
        }
      },
      container: {
        padding: {
          DEFAULT: "1rem",
          sm: "2rem",
          lg: "4rem",
          xl: "5rem",
          "2xl": "6rem"
        }
      },
      keyframes: {
        "pop-blob": {
          "0%": { transform: "scale(1)" },
          "33%": { transform: "scale(1.2)" },
          "66%": { transform: "scale(0.8)" },
          "100%": { transform: "scale(1)" }
        },
        "accordion-down": {
          from: {
            height: "0"
          },
          to: {
            height: "var(--radix-accordion-content-height)"
          }
        },
        "accordion-up": {
          from: {
            height: "var(--radix-accordion-content-height)"
          },
          to: {
            height: "0"
          }
        },
        "shiny-text": {
          "0%, 90%, 100%": {
            "background-position": "calc(-100% - var(--shiny-width)) 0"
          },
          "30%, 60%": {
            "background-position": "calc(100% + var(--shiny-width)) 0"
          }
        },
        shine: {
          "0%": {
            backgroundPosition: "200% 0",
            "background-position": "0% 0%"
          },
          "25%": {
            backgroundPosition: "-200% 0"
          },
          "100%": {
            backgroundPosition: "-200% 0"
          },
          "50%": {
            "background-position": "100% 100%"
          },
          to: {
            "background-position": "0% 0%"
          }
        },
        "typing-dot-bounce": {
          "0%,40%": {
            transform: "translateY(0)"
          },
          "20%": {
            transform: "translateY(-0.25rem)"
          }
        },
        ripple: {
          "0%, 100%": {
            transform: "translate(-50%, -50%) scale(1)"
          },
          "50%": {
            transform: "translate(-50%, -50%) scale(0.9)"
          }
        },
        shimmer: {
          from: {
            backgroundPosition: "0 0"
          },
          to: {
            backgroundPosition: "-200% 0"
          }
        },
        aurora: {
          from: {
            backgroundPosition: "50% 50%, 50% 50%"
          },
          to: {
            backgroundPosition: "350% 50%, 350% 50%"
          }
        }
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "shiny-text": "shiny-text 8s infinite",
        shine: "shine var(--duration) infinite linear",
        "typing-dot-bounce": "typing-dot-bounce 1.25s ease-out infinite",
        ripple: "ripple 3400ms ease infinite",
        aurora: "aurora 60s linear infinite",
        "pop-blob": "pop-blob 5s infinite",
        shimmer: "shimmer 2s linear infinite"
      }
    }
  },
  plugins: [
    require("tailwindcss-animate"),
    addVariablesForColors,
    function ({ matchUtilities, theme }) {
      matchUtilities(
        {
          "bg-grid": (value) => ({
            backgroundImage: `url("${svgToDataUri(
              `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32" fill="none" stroke="${value}"><path d="M0 .5H31.5V32"/></svg>`
            )}")`
          }),
          "bg-grid-small": (value) => ({
            backgroundImage: `url("${svgToDataUri(
              `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="8" height="8" fill="none" stroke="${value}"><path d="M0 .5H31.5V32"/></svg>`
            )}")`
          }),
          "bg-dot": (value) => ({
            backgroundImage: `url("${svgToDataUri(
              `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="16" height="16" fill="none"><circle fill="${value}" id="pattern-circle" cx="10" cy="10" r="1.6257413380501518"></circle></svg>`
            )}")`
          })
        },
        { values: flattenColorPalette(theme("backgroundColor")), type: "color" }
      );
    }
  ]
};
