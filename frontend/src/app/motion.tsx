// ============================================================================
// Motion engine — two cooperating reveal systems, zero dependencies.
//
// 1. `useSlideDeck`   — PowerPoint-style section transitions on the public
//    page. Every `.slide` fills the viewport; the one whose center is nearest
//    the viewport center gets `.is-active`. Content inside a slide (`.rv`
//    children) is hidden UNLESS its slide is active, so the outgoing section
//    dissolves as the incoming one rises — one screen at a time, like slides.
//
// 2. `useGlobalReveals` — classic scrolly-reveal for everything else (all
//    non-slide views). Observes `.rv` elements, adds `.rv--in` once they enter
//    the viewport, and keeps scanning for late-rendered nodes.
//
// Both only hide content while `document.body.fx` is set, which JS adds on
// mount — if JS ever fails, everything stays visible (no invisible pages).
// ============================================================================

import { useEffect, type RefObject } from "react";

export function enableFx() {
  document.body.classList.add("fx");
}

/** Pick the single `.slide` whose vertical center is closest to the viewport
 * center and mark it `.is-active` (removing it from every other slide). */
export function useSlideDeck(ref: RefObject<HTMLElement | null>) {
  useEffect(() => {
    enableFx();
    const root = ref.current;
    if (!root) return;
    const slides = Array.from(root.querySelectorAll<HTMLElement>(".slide"));
    if (!slides.length) return;

    let current: HTMLElement | null = null;
    const pick = () => {
      const center = window.innerHeight / 2;
      let best: HTMLElement | null = null;
      let bestDist = Infinity;
      for (const s of slides) {
        const r = s.getBoundingClientRect();
        const mid = r.top + r.height / 2;
        const dist = Math.abs(mid - center);
        if (dist < bestDist) {
          bestDist = dist;
          best = s;
        }
      }
      if (best && best !== current) {
        current?.classList.remove("is-active");
        best.classList.add("is-active");
        current = best;
      }
    };

    let raf = 0;
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(() => {
        raf = 0;
        pick();
      });
    };

    pick();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    // safety net: re-pick when async data changes section heights
    const t = window.setInterval(pick, 1200);
    return () => {
      window.clearInterval(t);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
    };
  }, [ref]);
}

/** Reveal-on-scroll for `.rv` elements outside slide decks. Re-scans when
 * `dep` changes so view switches re-arm the new page's elements. */
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
      { threshold: 0.12, rootMargin: "0px 0px -6% 0px" }
    );

    const scan = () => {
      document.querySelectorAll<HTMLElement>(".rv").forEach((el) => {
        if (el.closest(".slide")) return; // slides gate their own children
        if (!el.classList.contains("rv--in")) io.observe(el);
      });
    };
    scan();

    const mo = new MutationObserver(scan);
    mo.observe(document.body, { childList: true, subtree: true });
    return () => {
      io.disconnect();
      mo.disconnect();
    };
  }, [dep]);
}