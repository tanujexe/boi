/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: "#0b0c10",
          darker: "#050608",
          card: "rgba(17, 20, 28, 0.75)",
          text: "#c5c6c7",
          primary: "#66fcf1",
          secondary: "#45f3ff",
          border: "rgba(102, 252, 241, 0.15)",
          glow: "rgba(69, 243, 255, 0.35)",
        },
        severity: {
          low: "#10b981",       // Emerald
          medium: "#f59e0b",    // Amber
          high: "#f43f5e",      // Rose
          critical: "#ef4444",  // Red
        }
      },
      fontFamily: {
        sans: ["Outfit", "system-ui", "sans-serif"],
        mono: ["Fira Code", "monospace"],
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
      },
      keyframes: {
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 5px rgba(69, 243, 255, 0.2), inset 0 0 5px rgba(69, 243, 255, 0.1)' },
          '50%': { boxShadow: '0 0 15px rgba(69, 243, 255, 0.5), inset 0 0 10px rgba(69, 243, 255, 0.2)' },
        }
      }
    },
  },
  plugins: [],
}
