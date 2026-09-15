// ============================================================================
// AnalyticsView — public telemetry (no sign-in required): verdict KPIs across
// session / local / global scopes, a threat-distribution chart, AI-detection
// latency bars, and the detector quota panel. All global numbers are
// aggregate-only counters — no PII, no raw records.
// ============================================================================

import { useEffect, useMemo, useState } from "react";
import {
  getAnalytics,
  getDetectionUsage,
  type AnalyticsPayload,
  type DetectionUsage,
} from "../api";
import { getLocalMetrics, getSessionMetrics } from "../app/state";
import { formatCount } from "../app/util";
import { BarChart, HBarChart, type BarDatum } from "../components/Charts";
import { Card, EmptyNote, IconBar, IconBolt, IconClock, IconShield, Kicker, Pill } from "../components/ui";

type Scope = "session" | "local" | "global";

const SCOPE_LABEL: Record<Scope, string> = {
  session: "this browser session",
  local: "this device (all sessions)",
  global: "whole ledger — aggregate counters, no PII",
};

const VERDICT_STYLE: Record<string, { label: string; color: string; tone: string }> = {
  AUTHENTIC: { label: "AUTHENTIC", color: "var(--seal-2)", tone: "auth" },
  PROVEN_FAKE: { label: "PROVEN_FAKE", color: "var(--danger)", tone: "fake" },
  REVOKED: { label: "REVOKED", color: "var(--warn)", tone: "rev" },
  UNSIGNED: { label: "UNSIGNED", color: "var(--slate)", tone: "uns" },
};

export function AnalyticsView() {
  const [scope, setScope] = useState<Scope>("session");
  const [global, setGlobal] = useState<AnalyticsPayload | null>(null);
  const [usage, setUsage] = useState<DetectionUsage | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      const [g, u] = await Promise.all([getAnalytics(), getDetectionUsage()]);
      if (g.ok) setGlobal(g.data);
      if (u.ok) setUsage(u.data);
      setLoading(false);
    };
    void load();
  }, []);

  // ---- scope resolution ----------------------------------------------------
  const counts = useMemo(() => {
    if (scope === "session") return getSessionMetrics();
    if (scope === "local") return getLocalMetrics();
    return global?.stats || { AUTHENTIC: 0, PROVEN_FAKE: 0, REVOKED: 0, UNSIGNED: 0 };
  }, [scope, global]);

  const total = Object.values(counts).reduce((a, b) => a + (b || 0), 0);

  const bars: BarDatum[] = useMemo(
    () =>
      (["AUTHENTIC", "PROVEN_FAKE", "REVOKED", "UNSIGNED"] as const).map((k) => {
        const style = VERDICT_STYLE[k];
        return { label: style.label, value: counts[k] || 0, color: style.color };
      }),
    [counts],
  );

  const latencyBars: BarDatum[] = useMemo(() => {
    const l = global?.latency;
    if (!l) return [];
    return [
      { label: "avg", value: l.avg_ms, color: "var(--seal-2)" },
      { label: "min", value: l.min_ms, color: "var(--slate)" },
      { label: "max", value: l.max_ms, color: "var(--warn)" },
    ];
  }, [global]);

  const aiTotal = Object.values(global?.providers || {}).reduce((a, b) => a + (b || 0), 0);
  const model = usage?.model || "genai";

  return (
    <section className="section">
      <div className="section__head rv">
        <div>
          <Kicker>Telemetry</Kicker>
          <h2>Analytics — what the detector has seen</h2>
        </div>
        <p>
          Verdict mix and detector performance across three scopes. Session and
          device numbers are local to this browser; the global scope reads the
          whole ledger as aggregate counters.
        </p>
      </div>

      {loading ? (
        <EmptyNote>Loading analytics…</EmptyNote>
      ) : (
        <>
          {/* scope selector */}
          <div className="analytics-bars rv rv--d1">
            <div className="seg" role="radiogroup" aria-label="Analytics scope">
              {(["session", "local", "global"] as const).map((s) => (
                <button
                  key={s}
                  className={`seg__btn${scope === s ? " seg__btn--active" : ""}`}
                  onClick={() => setScope(s)}
                >
                  {s}
                </button>
              ))}
            </div>
            <span className="stat-note">
              scope: {SCOPE_LABEL[scope]} · {formatCount(total)} verdicts
            </span>
          </div>

          {/* KPI tiles */}
          <div className="kpi-grid mt-6">
            {(Object.keys(VERDICT_STYLE) as Array<keyof typeof VERDICT_STYLE>).map((k, i) => {
              const style = VERDICT_STYLE[k];
              const v = (counts as Record<string, number>)[k] || 0;
              const share = total ? Math.round((v / total) * 100) : 0;
              return (
                <div className={`kpi kpi--${style.tone} rv rv--d${i + 1}`} key={k}>
                  <div className="kpi__label">{style.label}</div>
                  <div className="kpi__value">{formatCount(v)}</div>
                  <div className="kpi__delta">{share}% of total</div>
                </div>
              );
            })}
          </div>

          {/* charts */}
          <div className="grid-2 mt-6">
            <Card title="Threat distribution" icon={<IconBar size={14} />}>
              <BarChart data={bars} height={230} />
            </Card>
            <Card title="AI detection latency" icon={<IconClock size={14} />}>
              {latencyBars.length ? (
                <>
                  <HBarChart data={latencyBars} unit="ms" />
                  <p className="stat-note mt-3">
                    {global!.latency!.samples} detections sampled · provider mix:{" "}
                    {Object.entries(global!.providers || {})
                      .map(([p, n]) => `${p}×${n}`)
                      .join(", ") || "—"}
                  </p>
                </>
              ) : (
                <EmptyNote>
                  <span className="big">No detection latency recorded yet</span>
                  <br />
                  Run a few image verifications to populate this chart.
                </EmptyNote>
              )}
            </Card>
          </div>

          {/* AI quota panel */}
          {usage && (
            <div className="rv rv--d3">
              <Card
                title="AI detector quota"
                icon={<IconShield size={14} />}
                aside={<Pill tone="seal">{usage.provider} · {model}</Pill>}
              >
                <div className="ai-quota">
                  <b>{formatCount(usage.remaining_today)}</b> operations left today{" "}
                  <span style={{ opacity: 0.6 }}>({formatCount(usage.ops_used_today)}/{formatCount(usage.limit_today)})</span>
                  {" · "}
                  <b>{formatCount(usage.remaining_month)}</b> left this month{" "}
                  <span style={{ opacity: 0.6 }}>({formatCount(usage.ops_used_month)}/{formatCount(usage.limit_month)})</span>
                </div>
                <p className="stat-note">
                  {usage.period_day} · {usage.period_month} · fails open: quota exhaustion never blocks a verdict
                </p>
              </Card>
            </div>
          )}

          {/* detector status strip */}
          <div className="kms-strip mt-6 rv rv--d4">
            <span>
              <IconBolt size={13} /> AI detector: <b>{model}</b>
            </span>
            <span>checks logged: {formatCount(aiTotal)}</span>
            <span>ledger-wide telemetry · aggregate counters only</span>
          </div>
        </>
      )}
    </section>
  );
}