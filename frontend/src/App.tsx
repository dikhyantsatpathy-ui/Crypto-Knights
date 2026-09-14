// ============================================================================
// App shell — navigation, session chip, status band, footer.
// The whole site is three views: Verify (public), Authority (console), and
// Analytics (telemetry, signed-in).
// ============================================================================

import { useEffect, useRef, useState } from "react";
import { getDetectionUsage, type DetectionUsage } from "./api";
import { useAuth, useToast } from "./app/state";
import { useTheme } from "./app/theme";
import { useGlobalReveals } from "./app/motion";
import { initials } from "./app/util";
import { IconMoon, IconSun } from "./components/ui";
import { AuthorityView } from "./views/AuthorityView";
import { AnalyticsView } from "./views/AnalyticsView";
import { PublicView } from "./views/PublicView";

type View = "verify" | "authority" | "analytics";

const NAV: { key: View; label: string }[] = [
  { key: "verify", label: "Verify" },
  { key: "authority", label: "Authority" },
  { key: "analytics", label: "Analytics" },
];

function BrandMark() {
  // The upside-down cap-lock — a padlock whose body carries a knurled
  // bottle-cap rim. Nothing gets in, and nothing gets out unverified.
  return (
    <svg className="brand__mark" viewBox="0 0 64 64" aria-hidden="true">
      <rect width="64" height="64" rx="14" fill="var(--seal)" />
      <g
        transform="rotate(180 32 32)"
        fill="none"
        stroke="var(--paper)"
        strokeWidth="3.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <rect x="15" y="31" width="34" height="23" rx="5" />
        <path d="M20 48 v7 M26 51 v4 M32 51 v4 M38 51 v4 M44 48 v7" />
        <path d="M21 31 v-8 a11 11 0 0 1 22 0 v8" />
      </g>
      <circle cx="32" cy="21" r="2.7" fill="var(--paper)" />
    </svg>
  );
}

/** Fixed top progress bar + page-wide `--scroll` (0..1) custom property used
 *  by parallax / reactive elements. Both update on the same rAF. */
function ScrollProgress() {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let raf = 0;
    const update = () => {
      raf = 0;
      const doc = document.documentElement;
      const max = doc.scrollHeight - window.innerHeight;
      const p = max > 0 ? Math.min(1, window.scrollY / max) : 0;
      doc.style.setProperty("--scroll", p.toFixed(4));
      if (ref.current) ref.current.style.transform = `scaleX(${p})`;
    };
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(update);
    };
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  return <div className="scroll-progress" ref={ref} aria-hidden="true" />;
}

function TopBar({ view, onView }: { view: View; onView: (v: View) => void }) {
  const { me, signedIn, signOut } = useAuth();
  const { toast } = useToast();
  const [theme, toggleTheme] = useTheme();

  const doLogout = async () => {
    await signOut();
    toast("Authority session ended.", "info");
  };

  return (
    <header className="topbar">
      <div className="shell topbar__inner">
        <a className="brand" href="#" onClick={(e) => e.preventDefault()}>
          <BrandMark />
          <span>
            <span className="brand__name">nocap</span>
            <span className="brand__sub">provenance ledger</span>
          </span>
        </a>

        <nav className="nav" aria-label="Primary">
          {NAV.map((n) => (
            <button
              key={n.key}
              className={`nav__link${view === n.key ? " nav__link--active" : ""}`}
              onClick={() => onView(n.key)}
            >
              {n.label}
            </button>
          ))}
        </nav>

        {me && signedIn && (
          <span className="session-chip">
            <span className="dot" aria-hidden="true" />
            {initials(me.name)} {me.name}
            {me.is_super_admin ? " · S-ADMIN" : ""}
          </span>
        )}
        {me && signedIn && (
          <button className="link-btn" onClick={() => void doLogout()}>
            Sign out
          </button>
        )}

        <button
          className="theme-toggle"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          title={theme === "dark" ? "Light mode" : "Dark mode"}
        >
          {theme === "dark" ? <IconSun size={15} /> : <IconMoon size={15} />}
        </button>
      </div>
    </header>
  );
}

function StatusBand() {
  const [usage, setUsage] = useState<DetectionUsage | null>(null);

  useEffect(() => {
    let alive = true;
    getDetectionUsage().then((res) => {
      if (res.ok && alive) setUsage(res.data);
    });
    return () => {
      alive = false;
    };
  }, []);

  const model = usage?.model || "built-in detector";

  return (
    <div className="status-band">
      <div className="shell status-band__inner">
        <span>
          <span className="dot" style={{ background: "var(--status-dot)" }} aria-hidden="true" />
          PROVENANCE LEDGER — OPERATIONAL
        </span>
        <span className="sep">|</span>
        <span>
          AI DETECTOR <b style={{ color: "var(--status-strong)" }}>{model}</b>
          {usage ? ` · ${usage.remaining_today}/${usage.limit_today} today` : ""}
        </span>
        <span className="sep">|</span>
        <span>L2 ANCHORING ACTIVE</span>
        <span className="sep">|</span>
        <span>ZERO-STORAGE VERIFICATION</span>
      </div>
    </div>
  );
}

function SiteFooter() {
  return (
    <footer className="site-footer">
      The Public Record — built on a cryptographic provenance ledger. Verify before you forward.
      <div className="team">
        Dikhyant Satapathy · Supriya Mandal · Asutosh Nayak · Sushumna Meghavaram · Ayush Kumar Lenka · Sidharth Priyadarshi
      </div>
    </footer>
  );
}

export function App() {
  const [view, setView] = useState<View>("verify");

  // full-page scroll snapping only on the public page's one-screen bands;
  // reset scroll so each view starts at its top (smooth, per scroll-behavior)
  useEffect(() => {
    document.body.classList.toggle("snap-home", view === "verify");
    window.scrollTo({ top: 0 });
  }, [view]);

  // scrolly-reveals for every non-slide view (Authority / Analytics)
  useGlobalReveals(view);

  return (
    <div className="app">
      <ScrollProgress />
      <TopBar view={view} onView={setView} />

      <main className="shell app__main">
        {view === "verify" && <PublicView />}
        {view === "authority" && <AuthorityView />}
        {view === "analytics" && <AnalyticsView />}
      </main>

      <StatusBand />
      <SiteFooter />
    </div>
  );
}