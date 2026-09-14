// ============================================================================
// Motion engine — zero dependencies.
//
// 1. `useScrolly` — the public page is a *scroll-scrubbed video*. Each scene
//    (`.scrolly-section`) reserves scroll room; its `.scrolly-stage` sticks to
//    the viewport while you scroll through that room. JS writes the section's
//    progress (`0..1`) into `--p` on the stage every frame; `.sc-enter`
//    children fade/rise in as `--p` grows and drop away as it approaches 1, so
//    scrolling down plays the scene forward and scrolling up rewinds it —
//    exactly like scrubbing a timeline.
//
// 2. `useGlobalReveals` — classic scroll-reveal for the console views
//    (`.rv` + `.rv--in`), kept for Authority/Analytics.
//
// Both only hide content while `document.body.fx` is set, which JS adds on
// mount — if JS ever fails, everything stays visible (no invisible pages).
// ============================================================================

import { useEffect, type RefObject } from "react";

export function enableFx() {
  document.body.classList.add("fx");
}

/** Scrub-drove, sticky-stage scrollytelling. Reads scroll position (rAF
 * throttled), computes per-`.scrolly-section` progress and sets `--p` on the
 * matching `.scrolly-stage`. Pure JS — CSS turns `--p` into the animation. */
export function useScrolly(ref: RefObject<HTMLElement | null>) {
  useEffect(() => {
    enableFx();
    const root = ref.current;
    if (!root) return;

    const stages = Array.from(root.querySelectorAll<HTMLElement>(".scrolly-stage"));
    if (!stages.length) return;

    let raf = 0;
    const tick = () => {
      const vh = window.innerHeight;
      for (const stage of stages) {
        const section = stage.parentElement;
        if (!section) continue;
        const rect = section.getBoundingClientRect();
        const scrollable = section.offsetHeight - vh; // how far the scene can travel
        if (scrollable <= 0) {
          stage.style.setProperty("--p", "0.5"); // short sections: mid-animation
          continue;
        }
        // The intro scene starts mid-animation so the hero is already visible
        // when the page loads (there is no scroll room above the top of page).
        const intro = stage.classList.contains("scrolly-stage--intro");
        const raw = -rect.top / scrollable;
        const p = intro
          ? Math.max(0.3, Math.min(1, raw))
          : Math.max(0, Math.min(1, raw));
        stage.style.setProperty("--p", p.toFixed(4));
      }
    };

    let pending = false;
    const onScroll = () => {
      if (pending) return;
      pending = true;
      raf = requestAnimationFrame(() => {
        pending = false;
        tick();
      });
    };

    tick();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      cancelAnimationFrame(raf);
    };
  }, [ref]);
}

/** Reveal-on-scroll for `.rv` elements (console views). Re-scans when `dep`
 * changes so view switches re-arm the new page's elements. */
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
        if (el.closest(".rv--no-reveal")) return; // opt-out (scrolly relies on --p)
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