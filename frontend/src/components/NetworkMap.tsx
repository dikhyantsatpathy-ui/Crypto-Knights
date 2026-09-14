// ============================================================================
// Dependency map — a hand-laid SVG "who signed what" graph.
// Authorities sit on the left, signed artifacts on the right; a curve connects
// each signer to each file they signed. Revoked identities and compromised
// files are tinted accordingly.
// ============================================================================

import type { NetworkNode, NetworkEdge } from "../api";

const AUTHORITY_X = 220;
const FILE_X = 920;
const HEIGHT_PER_ROW = 46;
const TOP_PAD = 40;

export function NetworkMap({ nodes, edges }: { nodes: NetworkNode[]; edges: NetworkEdge[] }) {
  const authorities = nodes.filter((n) => n.group === "authority");
  const files = nodes.filter((n) => n.group === "file");

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const yOf = (id: string) => {
    const group = byId.get(id)?.group ?? "file";
    const list = group === "authority" ? authorities : files;
    const i = list.findIndex((n) => n.id === id);
    const mid = list.length === 1 ? list.length / 2 : (i + 0.5) / list.length;
    return TOP_PAD + mid * list.length * HEIGHT_PER_ROW;
  };
  const xOf = (id: string) => (byId.get(id)?.group === "authority" ? AUTHORITY_X : FILE_X);

  const height = Math.max(160, TOP_PAD + nodes.length * HEIGHT_PER_ROW + 30);

  // Label the file nodes with a compact styled chip-like text; labels longer
  // than ~24 chars get truncated with an ellipsis in a <text> with tspans.
  const shortLabel = (label: string, max = 26) =>
    label.length > max ? `${label.slice(0, max - 1)}…` : label;

  return (
    <div style={{ overflowX: "auto" }}>
      <svg className="chart" viewBox={`0 0 1140 ${height}`} role="img" aria-label="Authority-to-file dependency map" style={{ minWidth: 860 }}>
        <defs>
          <marker id="arc" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#8d8774" />
          </marker>
        </defs>

        {/* edges */}
        {edges.map((e, i) => {
          const from = byId.get(e.from);
          const to = byId.get(e.to);
          if (!from || !to) return null;
          const revoked = !!(from.is_revoked || to.is_revoked);
          const color = revoked ? "#a31621" : "#8d8774";
          const x1 = xOf(e.from);
          const y1 = yOf(e.from);
          const x2 = xOf(e.to);
          const y2 = yOf(e.to);
          const midX = (x1 + x2) / 2;
          return (
            <path
              key={`${e.from}-${e.to}-${i}`}
              d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke={color}
              strokeWidth={revoked ? 2 : 1.2}
              strokeOpacity={revoked ? 0.85 : 0.5}
              markerEnd="url(#arc)"
            />
          );
        })}

        {/* authority nodes */}
        {authorities.map((n) => {
          const y = yOf(n.id);
          return (
            <g key={n.id}>
              <circle
                cx={AUTHORITY_X}
                cy={y}
                r={16}
                fill={n.is_revoked ? "#f9e7e4" : "#14532d"}
                stroke={n.is_revoked ? "#a31621" : "#14532d"}
                strokeWidth={1.5}
              />
              <text
                x={AUTHORITY_X}
                y={y + 4.5}
                textAnchor="middle"
                fontFamily="IBM Plex Mono, monospace"
                fontSize="10"
                fontWeight="700"
                fill={n.is_revoked ? "#a31621" : "#fff"}
              >
                {shortLabel(n.label, 6)}
              </text>
              <text
                x={AUTHORITY_X - 30}
                y={y + 4}
                textAnchor="end"
                fontFamily="IBM Plex Mono, monospace"
                fontSize="11"
                fill={n.is_revoked ? "#a31621" : "#1c1a15"}
              >
                {shortLabel(n.label, 24)}
              </text>
            </g>
          );
        })}

        {/* file nodes */}
        {files.map((n) => {
          const y = yOf(n.id);
          const compromised = !!n.is_compromised;
          const fill = n.is_revoked || compromised ? "#a31621" : "#1e6b3c";
          return (
            <g key={n.id}>
              <rect x={FILE_X - 92} y={y - 13} width={184} height={26} rx={5} fill="#fffdf8" stroke={fill} strokeWidth={1.2} />
              <text
                x={FILE_X}
                y={y + 4}
                textAnchor="middle"
                fontFamily="IBM Plex Mono, monospace"
                fontSize="10.5"
                fill="#1c1a15"
              >
                {shortLabel(n.label, 26)}
              </text>
              {compromised && (
                <text x={FILE_X} y={y + 21} textAnchor="middle" fontFamily="IBM Plex Mono, monospace" fontSize="8" fontWeight="700" fill="#a31621" letterSpacing="0.08em">
                  (EXPOSED)
                </text>
              )}
            </g>
          );
        })}

        {/* column headers */}
        <text x={AUTHORITY_X} y={22} textAnchor="middle" fontFamily="IBM Plex Mono, monospace" fontSize="10" fontWeight="600" letterSpacing="0.16em" fill="#8d8774">
          AUTHORITIES
        </text>
        <text x={FILE_X} y={22} textAnchor="middle" fontFamily="IBM Plex Mono, monospace" fontSize="10" fontWeight="600" letterSpacing="0.16em" fill="#8d8774">
          SIGNED ARTIFACTS
        </text>
      </svg>
    </div>
  );
}