// ============================================================================
// Motion engine — zero dependencies, compositor-friendly.
//
// `useGlobalReveals` — classic scroll-reveal (`.rv` + `.rv--in`). Content is
// only hidden while `document.body.fx` is set, which JS adds on mount — if JS
// ever fails, everything stays visible (no invisible pages).
// ============================================================================

import { useEffect } from "react";

export function enableFx() {
  document.body.classList.add("fx");
}

/** Reveal-on-scroll for `.rv` elements. Re-scans when `dep` changes so view
 *  switches re-arm the new page's elements. Elements already within the
 *  viewport on mount are revealed immediately (nothing stays hidden). */
export function useGlobalReveals(dep?: unknown) {
  useEffect(() => {
    enableFx();
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            (e.target as HTMLElement).classList.add("rv--in");
            io.unobserve(e.target);
          }
        }
      },
      { threshold: 0.08, rootMargin: "0px 0px -6% 0px" }
    );

    const revealAll = () => {
      document.querySelectorAll<HTMLElement>(".rv:not(.rv--in)").forEach((el) => io.observe(el));
    };
    revealAll();

    const mo = new MutationObserver(revealAll);
    mo.observe(document.body, { childList: true, subtree: true });
    return () => {
      io.disconnect();
      mo.disconnect();
    };
  }, [dep]);
}