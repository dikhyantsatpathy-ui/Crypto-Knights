// ============================================================================
// App shell — navigation, session chip, status band, footer.
// The whole site is three views: Verify (public), Authority (signed-in
// console), and Analytics (public analytics, aggregate counters only).
// ============================================================================

import { useEffect, useRef, useState } from "react";
import { getDetectionUsage, type DetectionUsage } from "./api";
import { useAuth, useToast } from "./app/state";
import { prefetchAnalyticsSummary } from "./app/analyticsCache";
import { useExplain } from "./app/explain";
import { useTheme } from "./app/theme";
import { useGlobalReveals } from "./app/motion";
import { initials } from "./app/util";
import { IconMoon, IconQuestion, IconSun } from "./components/ui";
import ProjectChatbot from "./components/ProjectChatbot";
import { AuthorityView } from "./views/AuthorityView";
import { AnalyticsView } from "./views/AnalyticsView";
import { PublicView } from "./views/PublicView";

type View = "screening" | "authority" | "analytics";

const NAV: { key: View; label: string }[] = [
  { key: "screening", label: "🛂 Screening Desk" },
  { key: "authority", label: "🏛️ Authority Console" },
  { key: "analytics", label: "📊 Analytics & Audit" },
];

function BrandMark() {
  // Border Shield emblem with checkpoint checkmark
  return (
    <svg className="brand__mark" viewBox="0 0 64 64" aria-hidden="true">
      <rect width="64" height="64" rx="14" fill="var(--seal)" />
      <g
        fill="none"
        stroke="var(--paper)"
        strokeWidth="3.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M32 10 L48 18 V34 C48 44 32 54 32 54 C32 54 16 44 16 34 V18 Z" />
        <path d="M24 32 L30 38 L40 26" />
      </g>
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
  const { on, toggle } = useExplain();
  const [theme, toggleTheme] = useTheme();

  const doLogout = async () => {
    await signOut();
    toast("Authority session ended.", "info");
  };

  return (
    <header className="topbar">
      <div className="shell topbar__inner">
        <a className="brand" href="#" onClick={(e) => { e.preventDefault(); onView("screening"); }}>
          <BrandMark />
          <span>
            <span className="brand__name">SSB NISCHAY</span>
            <span className="brand__sub">Border Screening Desk · SIH26188</span>
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
          className={`ex-toggle ${on ? "ex-toggle--on" : "ex-toggle--off"}`}
          data-explain-toggle
          onClick={toggle}
          aria-pressed={on}
          title={on ? "Explain mode is active — click to turn off" : "Explain mode is disabled — click to turn on"}
        >
          <IconQuestion size={15} />
          <span className="ex-toggle__label">Explain</span>
          <span className="toggle-track" aria-hidden="true">
            <span className="toggle-thumb" />
          </span>
          <span className="ex-toggle__status">{on ? "ON" : "OFF"}</span>
        </button>

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

  const model = usage?.model || "MHA Ensemble (OCR + ELA + PRNU + Face)";

  return (
    <div className="status-band">
      <div className="shell status-band__inner">
        <span>
          <span className="dot" style={{ background: "var(--status-dot)" }} aria-hidden="true" />
          SSB NISCHAY — CHECKPOINT OPERATIONAL
        </span>
        <span className="sep">|</span>
        <span>
          ICAO 9303 MRZ <b style={{ color: "var(--status-strong)" }}>TD1 / TD2 / TD3</b>
        </span>
        <span className="sep">|</span>
        <span>
          AI FORENSICS <b style={{ color: "var(--status-strong)" }}>{model}</b>
        </span>
        <span className="sep">|</span>
        <span>ZERO-STORAGE PRIVACY ENFORCED</span>
      </div>
    </div>
  );
}

function SiteFooter() {
  return (
    <footer className="site-footer">
      SSB NISCHAY — AI-Based Fake Identity &amp; Document Screening System · Ministry of Home Affairs (MHA), Sashastra Seema Bal (SSB), Police II Division (SIH26188).
      <div className="team">
        Dikhyant Satapathy · Supriya Mandal · Asutosh Nayak · Sushumna Meghavaram · Ayush Kumar Lenka · Sidharth Priyadarshi
      </div>
    </footer>
  );
}

export function App() {
  const [view, setView] = useState<View>("screening");

  // Warm the analytics numbers once at site load: by the time anyone opens the
  // dashboard tab, the figures are already in memory and render instantly.
  useEffect(() => {
    void prefetchAnalyticsSummary();
  }, []);

  // Reset scroll so each view starts at the top. Use 'instant' (not smooth)
  // to avoid briefly revealing the previous view's scroll position during tab
  // switching — the CSS scroll-behavior is overridden per this explicit option.
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "instant" as ScrollBehavior });
  }, [view]);

  // scroll-reveals for the console views (Authority / Analytics)
  useGlobalReveals(view);

  return (
    <div className="app">
      <ScrollProgress />
      <TopBar view={view} onView={setView} />

      <main className="shell app__main">
        {view === "screening" && <PublicView />}
        {view === "authority" && <AuthorityView />}
        {view === "analytics" && <AnalyticsView />}
      </main>

      <StatusBand />
      <SiteFooter />
      <ProjectChatbot />
    </div>
  );
}
