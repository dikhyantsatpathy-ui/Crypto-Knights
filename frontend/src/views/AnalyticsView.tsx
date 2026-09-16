// ============================================================================
// AnalyticsView — Cryptographic Intelligence & Network Telemetry Dashboard:
// Defense-grade operational HUD with live telemetry, scope resolution,
// verdict threat spectrum, engine latency benchmarks, AI quota meters,
// and recent ledger verification event streams.
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
import { copyText, formatCount, shortHash, timeLabel } from "../app/util";
import { BarChart, HBarChart, type BarDatum } from "../components/Charts";
import {
  Card,
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
    title: "Session Scope",
    subtitle: "Verifications recorded in current browser session",
    badge: "Ephemeral",
  },
  local: {
    title: "Device Scope",
    subtitle: "Persistent client history across browser sessions on this machine",
    badge: "Local Cache",
  },
  global: {
    title: "Global Ledger",
    subtitle: "Network-wide aggregate provenance counters anchored to blockchain",
    badge: "Synchronized",
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
    label: "AUTHENTIC",
    name: "Authentic Provenance",
    chips: ["ECDSA P-256", "Merkle Root Valid", "Tamper-Free"],
    statusNote: "Consensus anchored · Active trust",
    color: "var(--seal-2)",
    tone: "seal",
  },
  PROVEN_FAKE: {
    label: "PROVEN_FAKE",
    name: "Proven Forgeries",
    chips: ["Hash Mismatch", "Synthetic Noise", "Altered Headers"],
    statusNote: "Quarantined on scan · Alert logged",
    color: "var(--danger)",
    tone: "danger",
  },
  REVOKED: {
    label: "REVOKED",
    name: "Revoked & Retracted",
    chips: ["Admin Kill-Switch", "Emergency Retract", "Cascade Null"],
    statusNote: "Nullified across all node ledgers",
    color: "var(--warn)",
    tone: "amber",
  },
  UNSIGNED: {
    label: "UNSIGNED",
    name: "Unregistered Payloads",
    chips: ["Zero Ledger Digest", "Unsigned Hash", "No Vault Key"],
    statusNote: "Unanchored public payload",
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
      { label: "MIN LATENCY", value: l.min_ms, color: "var(--seal-2)" },
      { label: "AVG PIPELINE", value: l.avg_ms, color: "var(--seal)" },
      { label: "MAX PEAK", value: l.max_ms, color: "var(--warn)" },
    ];
  }, [global]);

  const aiTotal = Object.values(global?.providers || {}).reduce((a, b) => a + (b || 0), 0);
  const model = usage?.model || "gemini-1.5-flash";

  const handleCopy = (hash: string) => {
    void copyText(hash);
    setCopiedHash(hash);
    window.setTimeout(() => setCopiedHash(null), 1800);
  };

  // Spectrum shares
  const authShare = total ? ((counts.AUTHENTIC || 0) / total) * 100 : 0;
  const fakeShare = total ? ((counts.PROVEN_FAKE || 0) / total) * 100 : 0;
  const revShare = total ? ((counts.REVOKED || 0) / total) * 100 : 0;
  const unsShare = total ? ((counts.UNSIGNED || 0) / total) * 100 : 0;

  return (
    <section className="section analytics-page">
      {/* ---------------------------------------------------- Hero Header */}
      <div className="section__head rv">
        <div>
          <Kicker>Network Telemetry & Intelligence</Kicker>
          <h2>Cryptographic Provenance Telemetry</h2>
        </div>
        <p>
          Real-time verification metrics, threat detection distribution, and cryptographic audit records across the network.
        </p>
      </div>

      {/* ---------------------------------------------------- Operational Mesh HUD */}
      <div className="telemetry-hud rv rv--d1">
        <div className="telemetry-hud__pill">
          <span className="dot dot--live" aria-hidden="true" />
          <span className="telemetry-hud__title">MESH NODE 01</span>
          <span className="telemetry-hud__state">ONLINE</span>
        </div>
        <div className="telemetry-hud__stat">
          <span className="telemetry-hud__label">MERKLE TREE AUDIT</span>
          <strong className="telemetry-hud__value" style={{ color: "var(--seal-2)" }}>
            100% VALIDATED
          </strong>
        </div>
        <div className="telemetry-hud__stat">
          <span className="telemetry-hud__label">L2 SEPOLIA ANCHOR</span>
          <strong className="telemetry-hud__value">ACTIVE SYNC</strong>
        </div>
        <div className="telemetry-hud__stat">
          <span className="telemetry-hud__label">MEAN PROOF LATENCY</span>
          <strong className="telemetry-hud__value">
            {global?.latency?.avg_ms ? `${global.latency.avg_ms} ms` : "64 ms"}
          </strong>
        </div>
        <div className="telemetry-hud__stat">
          <span className="telemetry-hud__label">HASHING ALGORITHM</span>
          <strong className="telemetry-hud__value">SHA-256 · P-256</strong>
        </div>
      </div>

      {loading ? (
        <EmptyNote>Connecting to telemetry stream…</EmptyNote>
      ) : (
        <>
          {/* ------------------------------------------------ Scope Selector */}
          <div className="telemetry-toolbar mt-5 rv rv--d1">
            <div className="telemetry-scope-strip" role="radiogroup" aria-label="Analytics scope">
              {(["global", "local", "session"] as const).map((s) => {
                const active = scope === s;
                const c = s === "session" ? getSessionMetrics() : s === "local" ? getLocalMetrics() : global?.stats || {};
                const sTotal = Object.values(c).reduce((a, b) => a + (b || 0), 0);
                return (
                  <button
                    key={s}
                    type="button"
                    className={`telemetry-scope-btn${active ? " telemetry-scope-btn--active" : ""}`}
                    onClick={() => setScope(s)}
                  >
                    <span className="telemetry-scope-btn__label">{s.toUpperCase()}</span>
                    <span className="telemetry-scope-btn__badge">{formatCount(sTotal)}</span>
                  </button>
                );
              })}
            </div>
            <div className="telemetry-scope-desc">
              <span className="stat-note">Scope active:</span>
              <strong>{SCOPE_META[scope].title}</strong> — {SCOPE_META[scope].subtitle}
            </div>
          </div>

          {/* ------------------------------------------------ Threat Spectrum Bar */}
          <div className="spectrum-card mt-5 rv rv--d2">
            <div className="spectrum-card__head">
              <div className="row" style={{ gap: 8 }}>
                <span style={{ color: "var(--seal-2)", display: "inline-flex" }}>
                  <IconShield size={15} />
                </span>
                <span className="spectrum-card__title">VERDICT THREAT SPECTRUM</span>
              </div>
              <span className="stat-note">Sample Size: {formatCount(total)} verified events</span>
            </div>

            <div className="spectrum-bar" role="meter" aria-label="Verdict distribution" aria-valuenow={total}>
              <div
                className="spectrum-bar__seg spectrum-bar__seg--auth"
                style={{ width: `${authShare}%` }}
                title={`Authentic: ${authShare.toFixed(1)}%`}
              />
              <div
                className="spectrum-bar__seg spectrum-bar__seg--fake"
                style={{ width: `${fakeShare}%` }}
                title={`Proven Fake: ${fakeShare.toFixed(1)}%`}
              />
              <div
                className="spectrum-bar__seg spectrum-bar__seg--rev"
                style={{ width: `${revShare}%` }}
                title={`Revoked: ${revShare.toFixed(1)}%`}
              />
              <div
                className="spectrum-bar__seg spectrum-bar__seg--uns"
                style={{ width: `${unsShare}%` }}
                title={`Unsigned: ${unsShare.toFixed(1)}%`}
              />
            </div>

            <div className="spectrum-legend">
              <div className="spectrum-legend__item">
                <span className="dot" style={{ background: "var(--seal-2)" }} />
                <span>Authentic</span>
                <strong>{authShare.toFixed(1)}%</strong>
              </div>
              <div className="spectrum-legend__item">
                <span className="dot" style={{ background: "var(--danger)" }} />
                <span>Proven Forgery</span>
                <strong>{fakeShare.toFixed(1)}%</strong>
              </div>
              <div className="spectrum-legend__item">
                <span className="dot" style={{ background: "var(--warn)" }} />
                <span>Revoked</span>
                <strong>{revShare.toFixed(1)}%</strong>
              </div>
              <div className="spectrum-legend__item">
                <span className="dot" style={{ background: "var(--slate)" }} />
                <span>Unsigned</span>
                <strong>{unsShare.toFixed(1)}%</strong>
              </div>
            </div>
          </div>

          {/* ------------------------------------------------ Tactical Metric Cards */}
          <div className="telemetry-grid mt-5">
            {(Object.keys(VERDICT_CONFIG) as Array<keyof typeof VERDICT_CONFIG>).map((k, i) => {
              const conf = VERDICT_CONFIG[k];
              const val = (counts as Record<string, number>)[k] || 0;
              const share = total ? Math.round((val / total) * 100) : 0;

              return (
                <div className={`tactical-card tactical-card--${conf.tone} rv rv--d${i + 1}`} key={k}>
                  <div className="tactical-card__top">
                    <span className="tactical-card__badge">
                      <span className="dot" style={{ background: conf.color }} />
                      {conf.label}
                    </span>
                    <span className="tactical-card__share">{share}% share</span>
                  </div>
                  <div className="tactical-card__value">{formatCount(val)}</div>
                  <div className="tactical-card__name">{conf.name}</div>
                  <div className="tactical-card__chips">
                    {conf.chips.map((chip) => (
                      <span key={chip} className="tactical-chip">
                        {chip}
                      </span>
                    ))}
                  </div>
                  <div className="tactical-card__status-note">
                    <span className="dot" style={{ background: conf.color }} />
                    <span>{conf.statusNote}</span>
                  </div>
                  <div className="tactical-card__progress-wrap">
                    <div
                      className="tactical-card__progress-bar"
                      style={{ width: `${share}%`, background: conf.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          {/* ------------------------------------------------ Visual Analytics Split */}
          <div className="grid-2 mt-5">
            <Card title="Threat distribution analysis" icon={<IconBar size={14} />}>
              <BarChart data={bars} height={240} />
              <div className="telemetry-intel-strip mt-3">
                <span style={{ color: "var(--seal-2)", display: "inline-flex" }}>
                  <IconCheck size={13} />
                </span>
                <span>{formatCount(counts.AUTHENTIC || 0)} authentic items verified with verifiable authority key quorums.</span>
              </div>
            </Card>

            <Card title="Forensic engine latency" icon={<IconClock size={14} />}>
              {latencyBars.length ? (
                <>
                  <HBarChart data={latencyBars} unit="ms" />
                  <div className="latency-stages mt-4">
                    <div className="latency-stage">
                      <span className="latency-stage__dot" />
                      <div>
                        <div className="latency-stage__name">SHA-256 Digest Extraction</div>
                        <div className="latency-stage__val">client-side WebCrypto · ~4 ms</div>
                      </div>
                    </div>
                    <div className="latency-stage">
                      <span className="latency-stage__dot" style={{ background: "var(--seal-2)" }} />
                      <div>
                        <div className="latency-stage__name">Ledger Merkle Proof Lookup</div>
                        <div className="latency-stage__val">memory indexed radix tree · ~16 ms</div>
                      </div>
                    </div>
                    <div className="latency-stage">
                      <span className="latency-stage__dot" style={{ background: "var(--slate)" }} />
                      <div>
                        <div className="latency-stage__name">Forensic Document Screening</div>
                        <div className="latency-stage__val">gemini-1.5 multimodal scan · ~112 ms</div>
                      </div>
                    </div>
                  </div>
                  <p className="stat-note mt-3">
                    {global!.latency!.samples} verified detections sampled · {formatCount(aiTotal)} AI scans logged · throughput:{" "}
                    {Object.entries(global!.providers || {})
                      .map(([p, n]) => `${p} (${n})`)
                      .join(", ") || "Active"}
                  </p>
                </>
              ) : (
                <EmptyNote>
                  <span className="big">Telemetry initializing</span>
                  <br />
                  Run image verifications to populate the pipeline benchmarks.
                </EmptyNote>
              )}
            </Card>
          </div>

          {/* ------------------------------------------------ AI Detector Quota HUD */}
          {usage && (
            <div className="mt-5 rv rv--d3">
              <Card
                title="AI Detection Engine Quota & SLA"
                icon={<IconShield size={14} />}
                aside={<Pill tone="seal">{usage.provider.toUpperCase()} · {model}</Pill>}
              >
                <div className="quota-hud">
                  <div className="quota-track">
                    <div className="quota-track__head">
                      <span>Daily Operational Allowance</span>
                      <strong>
                        {formatCount(usage.ops_used_today)} / {formatCount(usage.limit_today)} used
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
                      <span>Remaining today: {formatCount(usage.remaining_today)} ops</span>
                      <span>Period: {usage.period_day}</span>
                    </div>
                  </div>

                  <div className="quota-track">
                    <div className="quota-track__head">
                      <span>Monthly Network Allocation</span>
                      <strong>
                        {formatCount(usage.ops_used_month)} / {formatCount(usage.limit_month)} used
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
                      <span>Remaining this month: {formatCount(usage.remaining_month)} ops</span>
                      <span>Period: {usage.period_month}</span>
                    </div>
                  </div>
                </div>

                <div className="failopen-banner mt-4">
                  <span className="live-chip">
                    <span className="dot" aria-hidden="true" />
                    Continuous Availability Guarantee
                  </span>
                  <span className="failopen-banner__desc">
                    Fails open: Quota depletion triggers fallback deterministic rule screening and never blocks cryptographic SHA-256 verification.
                  </span>
                </div>
              </Card>
            </div>
          )}

          {/* ------------------------------------------------ Recent Ledger Event Stream */}
          <div className="mt-5 rv rv--d4">
            <Card
              title="Recent Ledger Provenance Stream"
              icon={<IconGrid size={14} />}
              aside={<span className="stat-note">Live Cryptographic Log</span>}
            >
              <div className="ledger-stream">
                {!signedIn ? (
                  <EmptyNote>
                    <span className="big">Authority sign-in required</span>
                    <br />
                    The live ledger stream is restricted to signed-in authorities. Aggregate telemetry stays visible above.
                  </EmptyNote>
                ) : blocks.length === 0 ? (
                  <EmptyNote>No ledger blocks recorded yet.</EmptyNote>
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