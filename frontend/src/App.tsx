// ============================================================================
// App shell — navigation, session chip, status band, footer.
// The whole site is three views: Verify (public), Authority (console), and
// Analytics (telemetry, signed-in).
// ============================================================================

import { useEffect, useState } from "react";
import { getDetectionUsage, type DetectionUsage } from "./api";
import { useAuth, useToast } from "./app/state";
import { useTheme } from "./app/theme";
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
  return (
    <svg className="brand__mark" viewBox="0 0 64 64" aria-hidden="true">
      <rect width="64" height="64" rx="12" fill="var(--seal)" />
      <path
        d="M32 12l13 14v12c0 9-5.4 14-13 16-7.6-2-13-7-13-16V26z"
        fill="none"
        stroke="var(--paper)"
        strokeWidth="3.5"
      />
      <path d="M26 32l4 4 8-9" fill="none" stroke="var(--paper)" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
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

  return (
    <div className="app">
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