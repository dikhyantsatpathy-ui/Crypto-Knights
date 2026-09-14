// ============================================================================
// Motion engine — zero dependencies, compositor-friendly.
//
// 1. `useScrolly` — the public page is a *scroll-scrubbed video*. Each scene
//    (`.scrolly-section`) reserves scroll room; its `.scrolly-stage` sticks to
//    the viewport while you scroll through that room. JS writes the scene's
//    progress (`0..1`) into `--p` on the stage every frame; `.sc-cam` (the
//    scene's single promoted layer) drifts and `.sc-enter` children fade/rise
//    in as `--p` grows and dissolve as it approaches 1 — so scrolling down
//    plays the scene forward and scrolling up rewinds it, like scrub-bing a
//    timeline. Layout is measured ONCE (cached) and refreshed by a
//    ResizeObserver — the scroll loop reads only `scrollY`, so it never
//    triggers layout, and updates land only when the value actually changes.
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

interface Scene {
  stage: HTMLElement;
  top: number; // document-relative scroll offset of the section
  room: number; // how far the scene can travel before its stage un-pins
  intro: boolean;
}

/** Scroll-scrubbed sticky-stage scrollytelling. Progress = how far the viewport
 * has travelled through the section's scroll room, written to `--p` on the
 * stage. O(1) per frame — no layout reads, no allocations. */
export function useScrolly(ref: RefObject<HTMLElement | null>) {
  useEffect(() => {
    enableFx();
    const root = ref.current;
    if (!root) return;

    let scenes: Scene[] = [];

    const measure = () => {
      const vh = window.innerHeight;
      scenes = Array.from(root.querySelectorAll<HTMLElement>(".scrolly-stage"))
        .map((stage) => {
          const section = stage.parentElement as HTMLElement | null;
          const room = section ? section.offsetHeight - vh : 0;
          return {
            stage,
            top: section ? section.getBoundingClientRect().top + window.scrollY : 0,
            room: Math.max(1, room),
            intro: stage.classList.contains("scrolly-stage--intro"),
          };
        });
    };

    let raf = 0;
    let pending = false;
    const tick = () => {
      const y = window.scrollY;
      for (const { stage, top, room, intro } of scenes) {
        const raw = (y - top) / room;
        // intro scene starts mid-animation so the hero is visible on load
        const p = intro ? Math.max(0.3, Math.min(1, raw)) : Math.max(0, Math.min(1, raw));
        const v = p.toFixed(4);
        if (stage.dataset.p !== v) {
          stage.dataset.p = v;
          stage.style.setProperty("--p", v);
        }
      }
    };
    const onScroll = () => {
      if (pending) return;
      pending = true;
      raf = requestAnimationFrame(() => {
        pending = false;
        tick();
      });
    };

    measure();
    tick();
    window.addEventListener("scroll", onScroll, { passive: true });
    const ro = new ResizeObserver(() => {
      measure();
      tick();
    });
    ro.observe(root);
    // fall back to window resize for robustness across browsers
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      cancelAnimationFrame(raf);
      ro.disconnect();
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