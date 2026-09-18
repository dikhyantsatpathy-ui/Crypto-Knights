// ============================================================================
// AnalyticsView — Analytics dashboard: scope stats, verdict breakdown, engine
// timing, AI-detector quota and recent ledger activity.
// ============================================================================

import { useEffect, useMemo, useState } from "react";
import {
  getAnalytics,
  getDetectionUsage,
  getLedger,
  type AnalyticsPayload,
  type DetectionUsage,
  type LedgerBlock,
} from "../api";
import { getLocalMetrics, getSessionMetrics, useAuth } from "../app/state";
import { copyText, shortHash, timeLabel } from "../app/util";
import { BarChart, HBarChart, type BarDatum } from "../components/Charts";
import {
  Card,
  CountUp,
  EmptyNote,
  IconBar,
  IconCheck,
  IconClock,
  IconCopy,
  IconGrid,
  IconShield,
  Kicker,
  Pill,
} from "../components/ui";

type Scope = "session" | "local" | "global";

const SCOPE_META: Record<Scope, { title: string; subtitle: string; badge: string }> = {
  session: {
    title: "Session",
    subtitle: "Counts from this browser tab only",
    badge: "Session",
  },
  local: {
    title: "This device",
    subtitle: "All checks run on this browser, across tabs and visits",
    badge: "Local",
  },
  global: {
    title: "Network-wide",
    subtitle: "All verifications recorded in the shared ledger",
    badge: "Global",
  },
};

const VERDICT_CONFIG: Record<
  string,
  {
    label: string;
    name: string;
    chips: string[];
    statusNote: string;
    color: string;
    tone: "seal" | "danger" | "amber" | "slate";
  }
> = {
  AUTHENTIC: {
    label: "Authentic",
    name: "Authentic",
    chips: ["Signature checks out", "Merkle root valid", "No tampering"],
    statusNote: "News and content checks agree",
    color: "var(--seal-2)",
    tone: "seal",
  },
  PROVEN_FAKE: {
    label: "Proven fake",
    name: "Proven fake",
    chips: ["Hash mismatch", "Synthetic noise", "Altered headers"],
    statusNote: "Flagged — fails the checks",
    color: "var(--danger)",
    tone: "danger",
  },
  REVOKED: {
    label: "Revoked",
    name: "Revoked",
    chips: ["Retracted by issuer", "Kept on record"],
    statusNote: "Signature was cancelled",
    color: "var(--warn)",
    tone: "amber",
  },
  UNSIGNED: {
    label: "Unsigned",
    name: "Unsigned",
    chips: ["No authority signature", "No ledger record"],
    statusNote: "Nothing links it to an authority",
    color: "var(--slate)",
    tone: "slate",
  },
};

export function AnalyticsView() {
  const { signedIn } = useAuth();
  const [scope, setScope] = useState<Scope>("global");
  const [global, setGlobal] = useState<AnalyticsPayload | null>(null);
  const [usage, setUsage] = useState<DetectionUsage | null>(null);
  const [blocks, setBlocks] = useState<LedgerBlock[]>([]);
  const [loading, setLoading] = useState(true);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const [g, u] = await Promise.all([getAnalytics(), getDetectionUsage()]);
      let l: Awaited<ReturnType<typeof getLedger>> = { ok: false, error: "sign-in required" };
      if (signedIn) {
        l = await getLedger();
      }
      if (alive) {
        if (g.ok) setGlobal(g.data);
        if (u.ok) setUsage(u.data);
        setBlocks(l.ok ? (l.data.blocks || []) : []);
        setLoading(false);
      }
    };
    void load();
    return () => {
      alive = false;
    };
  }, [signedIn]);

  const counts = useMemo(() => {
    if (scope === "session") return getSessionMetrics();
    if (scope === "local") return getLocalMetrics();
    return global?.stats || { AUTHENTIC: 0, PROVEN_FAKE: 0, REVOKED: 0, UNSIGNED: 0 };
  }, [scope, global]);

  const total = useMemo(
    () => Object.values(counts).reduce((a, b) => a + (b || 0), 0),
    [counts],
  );

  const bars: BarDatum[] = useMemo(
    () =>
      (["AUTHENTIC", "PROVEN_FAKE", "REVOKED", "UNSIGNED"] as const).map((k) => {
        const conf = VERDICT_CONFIG[k];
        return { label: conf.label, value: counts[k] || 0, color: conf.color };
      }),
    [counts],
  );

  const latencyBars: BarDatum[] = useMemo(() => {
    const l = global?.latency;
    if (!l) return [];
    return [
      { label: "Fastest", value: l.min_ms, color: "var(--seal-2)" },
      { label: "Average", value: l.avg_ms, color: "var(--seal)" },
      { label: "Slowest", value: l.max_ms, color: "var(--warn)" },
    ];
  }, [global]);

  const aiTotal = Object.values(global?.providers || {}).reduce((a, b) => a + (b || 0), 0);
  const model = usage?.model || "genai";

  const handleCopy = (hash: string) => {
    void copyText(hash);
    setCopiedHash(hash);
    window.setTimeout(() => setCopiedHash(null), 1800);
  };

  // Distribution shares
  const authenticShare = total ? ((counts.AUTHENTIC || 0) / total) * 100 : 0;
  const provenFakeShare = total ? ((counts.PROVEN_FAKE || 0) / total) * 100 : 0;
  const revokedShare = total ? ((counts.REVOKED || 0) / total) * 100 : 0;
  const unsignedShare = total ? ((counts.UNSIGNED || 0) / total) * 100 : 0;

  return (
    <section className="section analytics-page">
      {/* ---------------------------------------------------- Hero Header */}
      <div className="section__head rv">
        <div>
          <Kicker>Analytics</Kicker>
          <h2>Verification statistics</h2>
        </div>
        <p>
          How many files have been checked, what the checks found, and how the detection engines are doing.
        </p>
      </div>

      {loading ? (
        <EmptyNote>Loading figures…</EmptyNote>
      ) : (
        <>
          {/* ------------------------------------------------ Scope Selector */}
          <div className="filter-toolbar mt-5 rv rv--d1">
            <div className="filter-strip" role="radiogroup" aria-label="Analytics scope">
              {(["global", "local", "session"] as const).map((s) => {
                const active = scope === s;
                const c = s === "session" ? getSessionMetrics() : s === "local" ? getLocalMetrics() : global?.stats || {};
                const sTotal = Object.values(c).reduce((a, b) => a + (b || 0), 0);
                return (
                  <button
                    key={s}
                    type="button"
                    className={`filter-btn${active ? " filter-btn--active" : ""}`}
                    onClick={() => setScope(s)}
                  >
                    <span className="filter-btn__label">{s.toUpperCase()}</span>
                    <span className="filter-btn__badge"><CountUp target={sTotal} /></span>
                  </button>
                );
              })}
            </div>
            <div className="filter-desc">
              <span className="stat-note">Showing:</span>
              <strong>{SCOPE_META[scope].title}</strong> — {SCOPE_META[scope].subtitle}
            </div>
          </div>

          {/* ------------------------------------------------ Verdict Share Bar */}
          <div className="distribution-card mt-5 rv rv--d2">
            <div className="distribution-card__head">
              <div className="row" style={{ gap: 8 }}>
                <span style={{ color: "var(--seal-2)", display: "inline-flex" }}>
                  <IconShield size={15} />
                </span>
                <span className="distribution-card__title">Verification Results</span>
              </div>
              <span className="stat-note"><CountUp target={total} /> verifications</span>
            </div>

            <div className="distribution-bar" role="meter" aria-label="Verdict distribution" aria-valuenow={total}>
              <div
                className="distribution-bar__seg distribution-bar__seg--auth"
                style={{ width: `${authenticShare}%` }}
                title={`Authentic: ${authenticShare.toFixed(1)}%`}
              />
              <div
                className="distribution-bar__seg distribution-bar__seg--fake"
                style={{ width: `${provenFakeShare}%` }}
                title={`Proven fake: ${provenFakeShare.toFixed(1)}%`}
              />
              <div
                className="distribution-bar__seg distribution-bar__seg--rev"
                style={{ width: `${revokedShare}%` }}
                title={`Revoked: ${revokedShare.toFixed(1)}%`}
              />
              <div
                className="distribution-bar__seg distribution-bar__seg--uns"
                style={{ width: `${unsignedShare}%` }}
                title={`Unsigned: ${unsignedShare.toFixed(1)}%`}
              />
            </div>

            <div className="distribution-legend">
              <div className="distribution-legend__item">
                <span className="dot" style={{ background: "var(--seal-2)" }} />
                <span>Authentic</span>
                <strong>{authenticShare.toFixed(1)}%</strong>
              </div>
              <div className="distribution-legend__item">
                <span className="dot" style={{ background: "var(--danger)" }} />
                <span>Proven fake</span>
                <strong>{provenFakeShare.toFixed(1)}%</strong>
              </div>
              <div className="distribution-legend__item">
                <span className="dot" style={{ background: "var(--warn)" }} />
                <span>Revoked</span>
                <strong>{revokedShare.toFixed(1)}%</strong>
              </div>
              <div className="distribution-legend__item">
                <span className="dot" style={{ background: "var(--slate)" }} />
                <span>Unsigned</span>
                <strong>{unsignedShare.toFixed(1)}%</strong>
              </div>
            </div>
          </div>

          {/* ------------------------------------------------ Metric Cards */}
          <div className="metrics-grid mt-5">
            {(Object.keys(VERDICT_CONFIG) as Array<keyof typeof VERDICT_CONFIG>).map((k, i) => {
              const conf = VERDICT_CONFIG[k];
              const val = (counts as Record<string, number>)[k] || 0;
              const share = total ? Math.round((val / total) * 100) : 0;

              return (
                <div className={`metric-card metric-card--${conf.tone} rv rv--d${i + 1}`} key={k}>
                  <div className="metric-card__top">
                    <span className="metric-card__badge">
                      <span className="dot" style={{ background: conf.color }} />
                      {conf.label}
                    </span>
                    <span className="metric-card__share">{share}%</span>
                  </div>
                  <div className="metric-card__value"><CountUp target={val} /></div>
                  <div className="metric-card__name">{conf.name}</div>
                  <div className="metric-card__chips">
                    {conf.chips.map((chip) => (
                      <span key={chip} className="metric-chip">
                        {chip}
                      </span>
                    ))}
                  </div>
                  <div className="metric-card__status-note">
                    <span className="dot" style={{ background: conf.color }} />
                    <span>{conf.statusNote}</span>
                  </div>
                  <div className="metric-card__progress-wrap">
                    <div
                      className="metric-card__progress-bar"
                      style={{ width: `${share}%`, background: conf.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          {/* ------------------------------------------------ Charts */}
          <div className="grid-2 mt-5">
            <Card title="Verdict distribution" icon={<IconBar size={14} />}>
              <BarChart data={bars} height={240} />
              <div className="insight-strip mt-3">
                <span style={{ color: "var(--seal-2)", display: "inline-flex" }}>
                  <IconCheck size={13} />
                </span>
                <span><CountUp target={counts.AUTHENTIC || 0} /> verified and trusted — signature and content checks passed.</span>
              </div>
            </Card>

            <Card title="Check time" icon={<IconClock size={14} />}>
              {latencyBars.length ? (
                <>
                  <HBarChart data={latencyBars} unit="ms" />
                  <div className="latency-stages mt-4">
                    <div className="latency-stage">
                      <span className="latency-stage__dot" />
                      <div>
                        <div className="latency-stage__name">Hash the file</div>
                        <div className="latency-stage__val">SHA-256 digest in your browser</div>
                      </div>
                    </div>
                    <div className="latency-stage">
                      <span className="latency-stage__dot" style={{ background: "var(--seal-2)" }} />
                      <div>
                        <div className="latency-stage__name">Look up the ledger</div>
                        <div className="latency-stage__val">Check if this digest is signed and recorded</div>
                      </div>
                    </div>
                    <div className="latency-stage">
                      <span className="latency-stage__dot" style={{ background: "var(--slate)" }} />
                      <div>
                        <div className="latency-stage__name">Run AI image screening</div>
                        <div className="latency-stage__val">Detect AI-generated or edited content</div>
                      </div>
                    </div>
                  </div>
                  <p className="stat-note mt-3">
                    Built from the last <CountUp target={global!.latency!.samples} /> verifications · <CountUp target={aiTotal} /> AI screens
                    run{Object.keys(global!.providers || {}).length
                      ? ` across ${Object.entries(global!.providers)
                          .map(([p, n]) => `${p}${n ? ` (${n})` : ""}`)
                          .join(", ")}`
                      : ""}
                  </p>
                </>
              ) : (
                <EmptyNote>
                  No timing data yet.
                  <br />
                  Run a few verifications and the timings will show up here.
                </EmptyNote>
              )}
            </Card>
          </div>

          {/* ------------------------------------------------ API Quota */}
          {usage && (
            <div className="mt-5 rv rv--d3">
              <Card
                title="AI screening allowance"
                icon={<IconShield size={14} />}
                aside={<Pill tone="seal">{usage.provider.toUpperCase()} · {model}</Pill>}
              >
                <div className="quota-container">
                  <div className="quota-track">
                    <div className="quota-track__head">
                      <span>Used today</span>
                      <strong>
                        <CountUp target={usage.ops_used_today} /> / <CountUp target={usage.limit_today} />
                      </strong>
                    </div>
                    <div className="quota-meter">
                      <div
                        className="quota-meter__fill"
                        style={{
                          width: `${Math.min(100, Math.round((usage.ops_used_today / (usage.limit_today || 1)) * 100))}%`,
                        }}
                      />
                    </div>
                    <div className="quota-track__foot">
                      <span><CountUp target={usage.remaining_today} /> remaining today</span>
                      <span>{usage.period_day}</span>
                    </div>
                  </div>

                  <div className="quota-track">
                    <div className="quota-track__head">
                      <span>Used this month</span>
                      <strong>
                        <CountUp target={usage.ops_used_month} /> / <CountUp target={usage.limit_month} />
                      </strong>
                    </div>
                    <div className="quota-meter">
                      <div
                        className="quota-meter__fill quota-meter__fill--month"
                        style={{
                          width: `${Math.min(100, Math.round((usage.ops_used_month / (usage.limit_month || 1)) * 100))}%`,
                        }}
                      />
                    </div>
                    <div className="quota-track__foot">
                      <span><CountUp target={usage.remaining_month} /> remaining this month</span>
                      <span>{usage.period_month}</span>
                    </div>
                  </div>
                </div>

                <div className="failopen-banner mt-4">
                  <span className="live-chip">
                    <span className="dot" aria-hidden="true" />
                    Verification always works
                  </span>
                  <span className="failopen-banner__desc">
                    If the AI allowance runs out, image screening falls back to rule-based checks. Signing and
                    signature verification are never affected.
                  </span>
                </div>
              </Card>
            </div>
          )}

          {/* ------------------------------------------------ Recent Ledger Activity */}
          <div className="mt-5 rv rv--d4">
            <Card
              title="Recent verifications"
              icon={<IconGrid size={14} />}
              aside={<span className="stat-note">Newest first</span>}
            >
              <div className="ledger-stream">
                {!signedIn ? (
                  <EmptyNote>
                    <span className="big">Sign-in required</span>
                    <br />
                    The recent-record list is limited to signed-in authorities. The overall figures above stay
                    visible to everyone.
                  </EmptyNote>
                ) : blocks.length === 0 ? (
                  <EmptyNote>Nothing verified yet.</EmptyNote>
                ) : (
                  <div className="ledger-stream__list">
                    {blocks.slice(0, 7).map((b) => (
                      <div className="ledger-stream__row" key={b.file_hash}>
                        <div className="ledger-stream__status">
                          {b.is_revoked ? (
                            <Pill tone="danger">REVOKED</Pill>
                          ) : (
                            <Pill tone="seal">ANCHORED</Pill>
                          )}
                        </div>
                        <div className="ledger-stream__meta">
                          <div className="ledger-stream__name">
                            <strong>{b.filename || "Signed Payload"}</strong>
                            <span className="stat-note" style={{ marginLeft: 8 }}>
                              {b.signer_institution || "Authority"} · {b.signer_name}
                            </span>
                          </div>
                          <div className="ledger-stream__hash">
                            <span className="mono">{shortHash(b.file_hash, 24)}</span>
                            <button
                              type="button"
                              className="stream-copy-btn"
                              onClick={() => handleCopy(b.file_hash)}
                              title="Copy SHA-256 digest"
                            >
                              <IconCopy size={11} /> {copiedHash === b.file_hash ? "Copied" : "Copy"}
                            </button>
                          </div>
                        </div>
                        <div className="ledger-stream__time mono stat-note">
                          <IconClock size={11} /> {timeLabel(b.timestamp)}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          </div>
        </>
      )}

      <div style={{ height: 20 }} />
    </section>
  );
}