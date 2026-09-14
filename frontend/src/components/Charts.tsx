// ============================================================================
// Hand-built SVG charts — threat distribution bars + AI latency bars.
// Dependency-free and perfectly matched to the design system.
// ============================================================================

export interface BarDatum {
  label: string;
  value: number;
  color: string;
}

/** Vertical bar chart with value labels and a baseline. */
export function BarChart({ data, height = 260 }: { data: BarDatum[]; height?: number }) {
  const padL = 8;
  const padT = 22;
  const padR = 8;
  const padB = 34;
  const max = Math.max(1, ...data.map((d) => d.value));

  return (
    <div>
      <svg
        className="chart"
        viewBox={`0 0 600 ${height}`}
        role="img"
        aria-label="Bar chart of verification verdicts"
      >
        {/* baseline */}
        <line x1={padL} y1={height - padB} x2={600 - padR} y2={height - padB} stroke="#c9c2ab" />
        {data.map((d, i) => {
          const n = data.length;
          const slot = (600 - padL - padR) / n;
          const bw = Math.min(64, slot * 0.55);
          const x = padL + slot * i + (slot - bw) / 2;
          const h = (d.value / max) * (height - padT - padB);
          const y = height - padB - h;
          return (
            <g key={d.label}>
              {h > 0 && (
                <rect
                  x={x}
                  y={y}
                  width={bw}
                  height={Math.max(h, 3)}
                  rx={3}
                  fill={d.color}
                  opacity={0.9}
                />
              )}
              <text
                x={x + bw / 2}
                y={y - 7}
                textAnchor="middle"
                fontFamily="IBM Plex Mono, monospace"
                fontSize="11"
                fontWeight="600"
                fill="#1c1a15"
              >
                {d.value}
              </text>
              <text
                x={x + bw / 2}
                y={height - padB + 20}
                textAnchor="middle"
                fontFamily="IBM Plex Mono, monospace"
                fontSize="9.5"
                letterSpacing="0.06em"
                fill="#8d8774"
              >
                {d.label}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="chart__legend">
        {data.map((d) => (
          <span key={d.label}>
            <span className="swatch" style={{ background: d.color }} />
            {d.label}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Horizontal bar chart for the AI-detection latency trio (avg / min / max). */
export function HBarChart({
  data,
  unit = "ms",
}: {
  data: BarDatum[];
  unit?: string;
}) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div className="stack-sm">
      {data.map((d) => (
        <div key={d.label}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              fontFamily: "IBM Plex Mono, monospace",
              fontSize: 10.5,
              color: "#55503f",
              marginBottom: 4,
            }}
          >
            <span>{d.label}</span>
            <span>
              {d.value} {unit}
            </span>
          </div>
          <div style={{ background: "#ece8dc", borderRadius: 4, height: 12, overflow: "hidden" }}>
            <div
              style={{
                width: `${(d.value / max) * 100}%`,
                minWidth: 4,
                height: "100%",
                background: d.color,
                borderRadius: 4,
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}