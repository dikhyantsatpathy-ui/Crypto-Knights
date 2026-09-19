// ============================================================================
// ForensicsHeatmapOverlay — Interactive forensic visualization suite
//
// Renders Error Level Analysis (ELA) heatmaps and YOLOv8-Nano Region-of-Interest
// (ROI) bounding boxes directly on the document image.
// Features:
//   - Heatmap opacity slider (0% original to 100% ELA heatmap)
//   - Interactive ROI bounding box toggles with class labels & confidence
//   - Pixel inspection details: ELA damage ratio, blur variance, exposure facts
// ============================================================================

import { useMemo, useState } from "react";
import type { ForensicsELA, ForensicsQA, ForensicsROI } from "../api";
import { Pill } from "./ui";

interface ForensicsHeatmapOverlayProps {
  file?: File | null;
  imageSrc?: string | null;
  ela?: ForensicsELA | null;
  roi?: ForensicsROI[] | null;
  qa?: ForensicsQA | null;
}

const ROI_COLORS: Record<string, string> = {
  face: "var(--seal, #22c55e)",
  document: "var(--accent, #3b82f6)",
  signature: "var(--amber, #f59e0b)",
  qr_code: "#a855f7",
  mrz_zone: "#ec4899",
};

export function ForensicsHeatmapOverlay({
  file,
  imageSrc,
  ela,
  roi,
  qa,
}: ForensicsHeatmapOverlayProps) {
  const [opacity, setOpacity] = useState<number>(0.55);
  const [showRoi, setShowRoi] = useState<boolean>(true);
  const [showEla, setShowEla] = useState<boolean>(true);
  const [selectedBox, setSelectedBox] = useState<ForensicsROI | null>(null);

  const originalUrl = useMemo(() => {
    if (file) return URL.createObjectURL(file);
    return imageSrc || null;
  }, [file, imageSrc]);

  if (!originalUrl) {
    return null;
  }

  const elaStatusTone =
    ela?.status === "LOW" ? "seal" : ela?.status === "MEDIUM" ? "amber" : "danger";

  return (
    <div className="forensics-visualizer card mt-3" style={{ padding: 14, borderRadius: 12 }}>
      <div className="row-between" style={{ flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <div className="row" style={{ gap: 8, alignItems: "center" }}>
          <span className="kicker" style={{ margin: 0 }}>
            Visual Forensic Canvas (OpenCV ELA + YOLO ROI)
          </span>
          {ela && (
            <Pill tone={elaStatusTone}>
              ELA {ela.status} ({Math.round((ela.damage_ratio || 0) * 100)}% anomaly)
            </Pill>
          )}
        </div>

        <div className="row" style={{ gap: 12, alignItems: "center" }}>
          <label className="row" style={{ gap: 4, cursor: "pointer", fontSize: "0.82rem" }}>
            <input
              type="checkbox"
              checked={showEla}
              onChange={(e) => setShowEla(e.target.checked)}
            />
            <span>ELA Layer</span>
          </label>
          <label className="row" style={{ gap: 4, cursor: "pointer", fontSize: "0.82rem" }}>
            <input
              type="checkbox"
              checked={showRoi}
              onChange={(e) => setShowRoi(e.target.checked)}
            />
            <span>ROI Boxes</span>
          </label>
        </div>
      </div>

      {showEla && ela?.heatmap_b64 && (
        <div className="mt-2 row" style={{ gap: 10, alignItems: "center" }}>
          <span className="stat-note" style={{ minWidth: 110 }}>
            Heatmap Blend: {Math.round(opacity * 100)}%
          </span>
          <input
            type="range"
            min="0"
            max="1"
            step="0.05"
            value={opacity}
            style={{ flex: 1, maxWidth: 260 }}
            onChange={(e) => setOpacity(parseFloat(e.target.value))}
          />
        </div>
      )}

      {/* Stage with layers */}
      <div
        className="forensics-stage mt-3"
        style={{
          position: "relative",
          display: "inline-block",
          maxWidth: "100%",
          borderRadius: 8,
          overflow: "hidden",
          border: "1px solid var(--line-2, #333)",
          background: "#000",
        }}
      >
        {/* Base layer: original document photo */}
        <img
          src={originalUrl}
          alt="Document baseline"
          style={{
            display: "block",
            maxWidth: "100%",
            maxHeight: 520,
            objectFit: "contain",
          }}
        />

        {/* ELA Heatmap overlay layer */}
        {showEla && ela?.heatmap_b64 && (
          <img
            src={`data:image/png;base64,${ela.heatmap_b64}`}
            alt="ELA Heatmap Overlay"
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: "100%",
              height: "100%",
              objectFit: "fill",
              opacity: opacity,
              mixBlendMode: "screen",
              pointerEvents: "none",
              transition: "opacity 0.15s ease",
            }}
          />
        )}

        {/* YOLOv8-Nano ROI Bounding Boxes */}
        {showRoi &&
          Array.isArray(roi) &&
          roi.map((box, idx) => {
            const color = ROI_COLORS[box.label] || "var(--seal, #22c55e)";
            const isHovered = selectedBox === box;
            return (
              <div
                key={`${box.label}-${idx}`}
                onMouseEnter={() => setSelectedBox(box)}
                onMouseLeave={() => setSelectedBox(null)}
                style={{
                  position: "absolute",
                  left: `${box.x * 100}%`,
                  top: `${box.y * 100}%`,
                  width: `${box.w * 100}%`,
                  height: `${box.h * 100}%`,
                  border: `2px solid ${color}`,
                  borderRadius: 4,
                  boxSizing: "border-box",
                  background: isHovered ? "rgba(255, 255, 255, 0.08)" : "transparent",
                  cursor: "pointer",
                  transition: "background 0.15s ease",
                }}
              >
                <span
                  style={{
                    position: "absolute",
                    top: -20,
                    left: 0,
                    fontSize: "0.68rem",
                    fontWeight: 600,
                    textTransform: "uppercase",
                    padding: "2px 6px",
                    borderRadius: 3,
                    background: color,
                    color: "#000",
                    whiteSpace: "nowrap",
                  }}
                >
                  {box.label} ({Math.round(box.confidence * 100)}%)
                </span>
              </div>
            );
          })}
      </div>

      {/* Forensic detail chips */}
      <div className="mt-3 row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {qa && (
          <>
            <span className="screen-chip mono">
              Resolution: {qa.width}x{qa.height} ({qa.megapixels} MP)
            </span>
            <span className="screen-chip mono">
              Focus Variance: {qa.blur_est} {qa.blurry ? "(soft/blur)" : "(crisp)"}
            </span>
            {qa.overexposed && (
              <span className="screen-chip mono" style={{ color: "var(--amber, #f59e0b)" }}>
                Overexposed
              </span>
            )}
            {qa.underexposed && (
              <span className="screen-chip mono" style={{ color: "var(--amber, #f59e0b)" }}>
                Underexposed
              </span>
            )}
          </>
        )}
        {ela && (
          <span className="screen-chip mono">
            ELA Recompression Quality: Q{ela.quality}
          </span>
        )}
      </div>
    </div>
  );
}
