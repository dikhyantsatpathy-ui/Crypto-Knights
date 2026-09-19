// ============================================================================
// Explain mode — tap any control and get a plain-language "what & why" card.
// Activated from the top-bar toggle or by pressing ESC to leave. The marker on
// <html> is `data-explain-mode="1"` (NOT `data-explain`, which is reserved for
// per-element custom descriptions carriable via [data-explain]).
// ============================================================================

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

type Tip = { title: string; body: string; x: number; y: number };

type ExplainCtx = { on: boolean; toggle: () => void };
const ExplainContext = createContext<ExplainCtx>({ on: false, toggle: () => {} });

export function useExplain() {
  return useContext(ExplainContext);
}

const TOOLTIP_W = 292;

const norm = (s: string) => s.replace(/\s+/g, " ").trim().toLowerCase().replace(/[\u2019']/g, "'");

/** Map keyed by normalized visible text of common app controls.
 *  Written in plain, layman language — this is the "explain it to my
 *  grandparent / the judge" layer. */
const EXPLAIN_MAP: Record<string, { t: string; b: string }> = {
  "verify": {
    t: "Verify — the lookup counter",
    b: "The front desk of the whole app. Pick any file, message or fingerprint, drop it here, and the app tells you if it's the genuine original, has been tampered with, was cancelled, or was never official at all. If you're unsure whether something is real, this is where you check.",
  },
  "authority": {
    t: "Authority — the officials' room",
    b: "A locked staff area. Officials sign in with a Google account, wait for an admin to approve their job title, then use it to sign files, post emergency notices, manage the records, and screen identity documents. Regular readers can't get in.",
  },
  "analytics": {
    t: "Analytics — the scoreboard",
    b: "Shows how many checks the system has run and what it found — real files, fakes, cancelled ones, unofficial ones — plus today's AI-detector usage. Only summary numbers, no personal details.",
  },
  "sign out": {
    t: "Sign out",
    b: "Logs the official out and closes their secure session — like locking the desk drawer when you leave for lunch.",
  },
  "verify health": {
    t: "Verify / run the check",
    b: "Press this after choosing a file. It acts like a security hologram check: the app compares the file's unique fingerprint (its SHA-256 digest) against the official record, checks the signature, and instantly tells you — genuine, tampered, cancelled, or never registered.",
  },
  "verify another file": {
    t: "Verify another file",
    b: "Clears the current result so you can check a different file. Handy when you're going through a batch of suspicious messages.",
  },
  "report this fake": {
    t: "Report this fake",
    b: "For a result that came back as a forgery: it logs that exact copy as a scam so others can see it circulated, and the network learns from it.",
  },
  "trust this file": {
    t: "Trust this file",
    b: "A confirmation after a positive check: you ran the scan, the app says AUTHENTIC, so you can safely treat the file as the real thing.",
  },
  "verify who signed this": {
    t: "Verify who signed this",
    b: "Reveals the person behind the signature — name, job title and organisation. These details are assigned by an admin, not typed by the signer, so nobody can make themselves look important.",
  },
  "check with the issuer": {
    t: "Check with the issuer",
    b: "Shows the office that supposedly issued the file, so you can call them directly and double-check before you trust or share it.",
  },
  "no official source": {
    t: "No official source",
    b: "This button is greyed out on purpose: the file was never signed by any authority, so there is no official source to check yet.",
  },
  "compare": {
    t: "Compare a copy",
    b: "Paste another fingerprint (or drop a second copy) and the app immediately says match or mismatch. Perfect for spotting a slightly different 'copy' of a real file.",
  },
  "google single sign-in": {
    t: "Google sign-in",
    b: "The officials' unlock button. Sign in with Google, the server quietly creates a private signing key inside a locked vault, and gives you a session cookie. Your private key never leaves the server — you never see it, so nobody can steal it from you.",
  },
  "sign & anchor": {
    t: "Sign & anchor",
    b: "The official's 'make it official' button. It stamps the file with an invisible mark, records a receipt in the public ledger, and locks a summary onto the blockchain. You get the signed file back to distribute.",
  },
  "issue signed broadcast": {
    t: "Issue signed broadcast",
    b: "The official's 'announce it' button. Takes the text message, signs it, timestamps it, and puts it on the public bulletin board so everyone can verify it's really from that office.",
  },
  "issue broadcast": {
    t: "Issue broadcast",
    b: "Publishes the draft message as a signed, timestamped emergency notice on the public board.",
  },
  "assign role": {
    t: "Assign role (admin only)",
    b: "Admin-only: gives an official their job title and organisation. Whatever is typed here is what shows up on everything they sign. Officials can't write their own title, which stops impostors.",
  },
  "set pin": {
    t: "Set PIN",
    b: "Sets a secret 5-digit code. If the official's account is ever hijacked, this PIN is the emergency kill switch to shut down their signing key.",
  },
  "revoke access": {
    t: "Revoke (kill switch)",
    b: "The emergency stop button. Using the PIN, an official can permanently retire a signing key — and every file that key ever signed turns into REVOKED across the whole network, instantly. Old copies suddenly can't be trusted, which is exactly what you want if someone's keys were stolen.",
  },
  "reinstate": {
    t: "Reinstate",
    b: "The admin's undo button. Brings a revoked key back to life — but only with the original PIN, so one careless click can't un-retire a whole batch by accident.",
  },
  "batch anchor": {
    t: "Batch anchor (L2 sync)",
    b: "Admin command: bundles all unsealed records into one tree, then stamps its summary onto the blockchain — the permanent public receipt book that nobody can quietly edit.",
  },
  "inject demo attack": {
    t: "Inject demo attack",
    b: "A demo-only toy button. It plants fake 'caught a fake!' records so a judge can watch the fraud dashboard light up. The data is invented and harmless.",
  },
  "rollback ledger": {
    t: "Rollback ledger",
    b: "An admin emergency drill: wipes every record newer than a chosen time. It deliberately works while staying visible on the blockchain, so it can't be abused in secret.",
  },
  "screen document": {
    t: "Screen document",
    b: "For officials checking IDs like a passport or driving licence. Upload the photo or PDF, and the app reads the details, checks the numbers follow the official rules, and gives a clear score — CLEAR, REVIEW, or FLAGGED — with plain-English reasons for every point.",
  },
  "clear": {
    t: "Clear (supervisor's call)",
    b: "The supervisor says 'this document looks genuine'. The decision is recorded permanently — it becomes part of the official paper trail.",
  },
  "confirm fraud": {
    t: "Confirm fraud",
    b: "The supervisor agrees the document is a fake. The evidence and reasoning stay attached to the report permanently.",
  },
  "inconclusive": {
    t: "Inconclusive",
    b: "The supervisor can't decide, so the case is handed to a human for a closer look — better than guessing.",
  },
  "add to watchlist": {
    t: "Add to watchlist (admin only)",
    b: "Stores a hidden fingerprint of a known-bad number — never the number itself, for privacy. If that number ever shows up in a screening again, it instantly glows red as a risk.",
  },
  "remove": {
    t: "Remove",
    b: "Takes a number off the watchlist so it no longer raises flags in screening.",
  },
  "check previous broadcasts": {
    t: "Check previous broadcasts",
    b: "Opens the full history of past official notices, each with an exact date and time, so you can scroll back further than today.",
  },
  "view all": {
    t: "View all",
    b: "Shows every past official notice instead of just today's.",
  },
  "view archive": {
    t: "View archive",
    b: "Expands this card to show every official notice ever posted, not just today's. Click again to shrink back. Nothing underneath is blocked — you can keep using the page.",
  },
  "show recent only": {
    t: "Show recent only",
    b: "Collapses the list back to today's notices.",
  },
  "theme-toggle": {
    t: "Theme toggle",
    b: "Switches between light and dark mode, whichever is easier on your eyes. Your choice is remembered.",
  },
  "switch to dark mode": { t: "Dark mode", b: "Switches the whole app to a dark screen — easier on the eyes at night." },
  "switch to light mode": { t: "Light mode", b: "Switches back to the bright, paper-like look." },
  "guide": {
    t: "Project guide (chatbot)",
    b: "Opens this little help chat. Ask anything about the project in plain English — it answers from a built-in set of explainer notes, no internet needed.",
  },
  "explain": {
    t: "Explain mode",
    b: "Switches explain mode on or off. While it's on, tapping any button, tab or text box shows this kind of plain-English explanation instead of doing the thing. Press ESC or tap Explain again to turn it off and use the site normally.",
  },
  "live notices": {
    t: "Live notices",
    b: "Today's official announcements, shown as a strip. Pause it with your mouse to read, or click 'View archive' to see everything ever posted.",
  },
};

function inputExplain(el: Element): { t: string; b: string } | null {
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) {
    const label =
      el instanceof HTMLSelectElement
        ? "Drop-down"
        : el.type === "checkbox"
          ? "Checkbox"
          : el.type === "date"
            ? "Date picker"
            : "Text box";
    const hint =
      (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) && el.placeholder
        ? ` It says "${el.placeholder.slice(0, 70)}" to guide you.`
        : "";
    return {
      t: label,
      b: `${label}: this is where you type or choose information. It's sent to the server only when you press the button right next to it.${hint}`,
    };
  }
  if (el instanceof HTMLAnchorElement) {
    return { t: "Link", b: "Opens the linked page — opened in a new tab so you never lose your place." };
  }
  return null;
}

function elementExplanation(el: Element): Tip | null {
  const own = el.closest<HTMLElement>("[data-explain]");
  if (own?.dataset.explain) {
    let parsed: { t: string; b: string } | null = null;
    try {
      const raw = JSON.parse(own.dataset.explain);
      if (typeof raw.t === "string" && typeof raw.b === "string") parsed = raw;
    } catch {
      /* treat as raw text */
    }
    if (parsed) return { title: parsed.t, body: parsed.b, x: 0, y: 0 };
    return { title: "Custom control", body: own.dataset.explain, x: 0, y: 0 };
  }
  const textRaw = (el.textContent || "").trim();
  const text = norm(textRaw);
  const label =
    el instanceof HTMLElement
      ? (el.getAttribute("aria-label") || (el as HTMLInputElement).placeholder || "").trim()
      : "";
  const candidates = [text, label ? norm(label) : ""].filter(Boolean);
  // Longest-key first so "verify health" beats "verify", "view archive (2)"
  // beats "view all", etc.
  const keys = Object.keys(EXPLAIN_MAP).sort((a, b) => b.length - a.length);
  for (const cand of candidates) {
    for (const key of keys) {
      if (cand === key || cand.startsWith(key + " ") || cand.startsWith(key + "(")) {
        const hit = EXPLAIN_MAP[key];
        return { title: hit.t, body: hit.b, x: 0, y: 0 };
      }
    }
  }
  const fallback = inputExplain(el);
  return fallback ? { title: fallback.t, body: fallback.b, x: 0, y: 0 } : null;
}

export function ExplainProvider({ children }: { children: ReactNode }) {
  const [on, setOn] = useState<boolean>(() => {
    try {
      return localStorage.getItem("nocap-explain") === "1";
    } catch {
      return false;
    }
  });
  const [tip, setTip] = useState<Tip | null>(null);
  const enabledRef = useRef(on);
  enabledRef.current = on;

  const toggle = useCallback(() => setOn((v) => !v), []);

  // persist
  useEffect(() => {
    try {
      localStorage.setItem("nocap-explain", on ? "1" : "0");
    } catch {
      /* ignore */
    }
    document.documentElement.dataset.explainMode = on ? "1" : "0";
    if (!on) setTip(null);
  }, [on]);

  // close tooltip on scroll / resize / escape
  useEffect(() => {
    if (!tip) return;
    const close = () => setTip(null);
    window.addEventListener("scroll", close, { capture: true, passive: true });
    window.addEventListener("resize", close);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setTip(null);
        setOn(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("scroll", close, { capture: true });
      window.removeEventListener("resize", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [tip]);

  // delegated interception
  useEffect(() => {
    if (!on) return;
    const onClick = (e: MouseEvent) => {
      const t = e.target as Element | null;
      if (!t) return;
      if (t.closest(".explain-tip") || t.closest(".guide-bot") || t.closest("[data-explain-toggle]")) return;
      const el = t.closest<HTMLElement>(
        "button, input, select, textarea, a[href], [role='button'], [tabindex], [data-explain]",
      );
      if (!el) return;
      // Never block the native file picker: a file input (or a label that
      // wraps one, e.g. the dropzone) must always open the chooser, even in
      // explain mode — otherwise nothing can ever be uploaded to demo it.
      const isFilePicker =
        el.matches('input[type="file"]') ||
        (el.tagName === "LABEL" && !!el.querySelector('input[type="file"]'));
      if (isFilePicker) return;
      // Resolve the tip BEFORE swallowing the click: controls that have no
      // explanation (Copy, Copy hash, Clear, pagination …) must behave normally
      // in explain mode, not become silently inert.
      const ex = elementExplanation(el);
      if (!ex) return;
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      const r = el.getBoundingClientRect();
      let x = Math.max(8, Math.min(window.innerWidth - TOOLTIP_W - 8, r.left + r.width / 2 - TOOLTIP_W / 2));
      let y = r.bottom + 10;
      if (y + 160 > window.innerHeight && r.top > 190) y = r.top - 150;
      setTip({ ...ex, x: Math.round(x), y: Math.round(y) });
    };
    document.addEventListener("click", onClick, true);
    return () => document.removeEventListener("click", onClick, true);
  }, [on]);

  const value = useMemo(() => ({ on, toggle }), [on, toggle]);

  return (
    <ExplainContext.Provider value={value}>
      {children}
      {tip && (
        <div
          className="explain-tip"
          style={{ left: tip.x, top: tip.y, width: TOOLTIP_W }}
          role="status"
          aria-live="polite"
        >
          <div className="explain-tip__title">?</div>
          <strong className="explain-tip__head">{tip.title}</strong>
          <p className="explain-tip__body">{tip.body}</p>
          <span className="explain-tip__hint">
            ESC exits explain mode — every control is disabled while you learn.
          </span>
        </div>
      )}
    </ExplainContext.Provider>
  );
}