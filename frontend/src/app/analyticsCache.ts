// ============================================================================
// Analytics cache — load-once at site boot + live refresh.
//
// The dashboard numbers are fetched ONCE when the website loads (see App.tsx),
// served instantly from memory whenever the Analytics tab opens, and refreshed
// live: on every mount, every 30s while mounted, and whenever the tab becomes
// visible again. The server also caches aggregates for ~20s and invalidates on
// every new verification, so refreshes are cheap.
// ============================================================================

import { useEffect, useState } from "react";
import { getAnalyticsSummary, type AnalyticsSummary } from "../api";

let snapshot: AnalyticsSummary | null = null;
let inflight: Promise<void> | null = null;
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((cb) => {
    try {
      cb();
    } catch {
      /* a stale listener must never break the refresh loop */
    }
  });
}

/** Last fetched dashboard payload, or null if nothing fetched yet. */
export function getAnalyticsSnapshot(): AnalyticsSummary | null {
  return snapshot;
}

/** Fetch the summary in the background; concurrent callers share one flight. */
export function prefetchAnalyticsSummary(): Promise<void> {
  if (inflight) return inflight;
  inflight = getAnalyticsSummary()
    .then((res) => {
      if (res.ok) {
        snapshot = res.data;
        emit();
      }
    })
    .finally(() => {
      inflight = null;
    });
  return inflight;
}

/**
 * Instant snapshot (may be null on first paint) + background revalidation.
 * Polls every `pollMs` while mounted and refreshes on tab-visibility return.
 */
export function useAnalyticsSummary(pollMs = 30000): AnalyticsSummary | null {
  const [snap, setSnap] = useState<AnalyticsSummary | null>(snapshot);

  useEffect(() => {
    const onSnap = () => setSnap(snapshot);
    listeners.add(onSnap);
    void prefetchAnalyticsSummary();
    const id = window.setInterval(() => {
      void prefetchAnalyticsSummary();
    }, pollMs);
    const onVis = () => {
      if (document.visibilityState === "visible") void prefetchAnalyticsSummary();
    };
    document.addEventListener("visibilitychange", onVis);
    return () => {
      listeners.delete(onSnap);
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [pollMs]);

  return snap;
}
