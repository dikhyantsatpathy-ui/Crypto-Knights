// ---------------------------------------------------------------------------
// Theme toggle — localStorage-backed, OS-prefers-color-scheme default.
// ---------------------------------------------------------------------------

import { useState, useEffect } from "react";

export type Theme = "light" | "dark";

/**
 * Returns the current theme and a toggle function.
 * Persists choice in localStorage; defaults to the OS preference.
 */
export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const stored = localStorage.getItem("nocap-theme");
      if (stored === "dark" || stored === "light") return stored;
    } catch { /* SSR / private mode */ }
    try {
      return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    } catch { /* SSR */ }
    return "light";
  });

  // Apply to <html> and persist
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("nocap-theme", theme); } catch { /* ignore */ }
  }, [theme]);

  // Respect OS changes unless the user has explicitly chosen
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = (e: MediaQueryListEvent) => {
      try {
        if (!localStorage.getItem("nocap-theme")) setTheme(e.matches ? "dark" : "light");
      } catch { /* ignore */ }
    };
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  const toggle = () => setTheme((t) => (t === "light" ? "dark" : "light"));
  return [theme, toggle];
}
