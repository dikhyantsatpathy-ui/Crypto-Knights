// ============================================================================
// QrStamp — scannable provenance stamps.
//
// Every signed artifact can carry one of two QR codes:
//
//   LINK  — https://<host>/?h=<sha256>. A phone scan opens the ledger check
//           page for that exact fingerprint, then asks you to drop the actual
//           file so it can confirm this copy MATCHES before it says anything
//           is authentic. This is what defeats "cut the code off one document
//           and stick it on another" — a stamp only proves the HASH, never the
//           file, so the file still has to prove itself.
//
//   CERT  — a canonical self-contained certificate (`nocap:c1|...`) carrying
//           hash + signature + issuer public key + timestamp + anchors. Any
//           offline tool that knows this app's scheme can re-verify the
//           signature without touching the network. Still hash-bound, so a
//           cert pasted onto a different file re-verifies to a mismatch.
//
// Both render at the highest QR error-correction level (H) — printed stamps
// survive scuffing, creases, and low-light scans. PNG export renders the code
// inside a bordered certificate so the fingerprint travels with the pixels.
// ============================================================================

import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import type { LedgerReceipt } from "../api";
import { useToast } from "../app/state";
import { copyText, displayTime, downloadBlob, shortHash } from "../app/util";
import { Button, IconCopy, IconDownload, Kicker } from "./ui";

const DARK = "#0b1f17";
const BLACK = "#000000";
const PAPER = "#fdfdfb";

export interface StampMeta extends Partial<LedgerReceipt> {
  label?: string;
}

/** Canonical offline-certificate payload. Versioned + scheme-scoped so a
 *  third-party scanner must deliberately implement nocap's format and can
 *  never be confused with any other code format. */
export function certPayload(hash: string, meta: StampMeta): string {
  const join = (k: string, v?: string | null) => {
    const s = v == null ? "" : String(v).trim();
    return s ? `${k}:${encodeURIComponent(s)}|` : "";
  };
  return (
    "nocap:c1|" +
    join("h", hash.toLowerCase()) +
    join("s", meta?.signature) +
    join("k", meta?.issuer_pubkey) +
    join("t", meta?.signed_at) +
    join("m", meta?.merkle_root) +
    join("c", meta?.ipfs_cid) +
    join("x", meta?.tx_hash) +
    join("n", meta?.signer_name) +
    join("o", meta?.label)
  ).replace(/\|$/, "");
}

export function linkPayload(hash: string): string {
  return `${window.location.origin}/?h=${encodeURIComponent(hash.toLowerCase())}`;
}

const QR_OPTS = {
  margin: 1,
  errorCorrectionLevel: "H" as const,
  color: { dark: DARK, light: PAPER },
};

function drawQr(canvas: HTMLCanvasElement, payload: string, width: number): Promise<void> {
  return QRCode.toCanvas(canvas, payload, { ...QR_OPTS, width }).catch(() => {
    /* payload renders or nothing — never crash the page */
  });
}

// ----------------------------------------------------------------------------
// Pure QR canvas renderer (both stamp modes share it).
// ----------------------------------------------------------------------------

function QrCanvas({ payload, width }: { payload: string; width: number }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (ref.current) void drawQr(ref.current, payload, width);
  }, [payload, width]);

  return <canvas ref={ref} style={{ width, height: width, imageRendering: "pixelated" }} aria-hidden="true" />;
}

// ----------------------------------------------------------------------------
// PNG export: borders the QR in a certificate with the fingerprint text, so
// the scan travels with a human-readable digest + signer + timestamp.
// ----------------------------------------------------------------------------

async function renderStampPng(payload: string, hash: string, meta: StampMeta): Promise<Blob> {
  const W = 640;
  const qrSize = 380;
  const canvas = document.createElement("canvas");
  canvas.width = W;
  canvas.height = 820;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas unavailable");

  // paper + frame
  ctx.fillStyle = PAPER;
  ctx.fillRect(0, 0, W, canvas.height);
  ctx.strokeStyle = DARK;
  ctx.lineWidth = 4;
  ctx.strokeRect(10, 10, W - 20, canvas.height - 20);

  // header
  ctx.fillStyle = DARK;
  ctx.textAlign = "center";
  ctx.font = "700 30px system-ui, sans-serif";
  ctx.fillText("PROVENANCE", W / 2, 58);
  ctx.font = "600 18px system-ui, sans-serif";
  ctx.fillText("nocap · public ledger", W / 2, 86);

  // QR
  const qr = document.createElement("canvas");
  await drawQr(qr, payload, qrSize);
  ctx.drawImage(qr, (W - qrSize) / 2, 106);

  // digest
  ctx.fillStyle = BLACK;
  ctx.font = "700 18px Menlo, Consolas, monospace";
  ctx.fillText("SHA-256", W / 2, 540);
  ctx.font = "16px Menlo, Consolas, monospace";
  const full = (hash || "").toLowerCase();
  ctx.fillText(shortHash(full, 34), W / 2, 566);

  // signer block
  ctx.fillStyle = DARK;
  ctx.font = "700 22px system-ui, sans-serif";
  const signer = [meta?.signer_name, meta?.signer_designation, meta?.signer_institution]
    .filter(Boolean)
    .join(" · ");
  ctx.fillText(meta?.label || signer || "SIGNED ARTIFACT", W / 2, 640);

  ctx.font = "15px system-ui, sans-serif";
  ctx.fillStyle = "#44554c";
  ctx.fillText(`Signed: ${displayTime(meta?.signed_at)} UTC`, W / 2, 668);
  const anchor = meta?.merkle_root
    ? `merkle:${shortHash(meta.merkle_root, 22)}`
    : meta?.ipfs_cid
      ? `ipfs:${shortHash(meta.ipfs_cid, 22)}`
      : "";
  if (anchor) ctx.fillText(anchor, W / 2, 692);

  // footer warning
  ctx.fillStyle = "#8a2f2f";
  ctx.font = "600 14px system-ui, sans-serif";
  ctx.fillText("This code is bound to the exact file above.", W / 2, 748);
  ctx.fillText("Pasted onto another file, it reports a mismatch.", W / 2, 772);

  return new Promise((resolve, reject) => {
    canvas.toBlob((b) => (b ? resolve(b) : reject(new Error("PNG export failed"))), "image/png");
  });
}

// ----------------------------------------------------------------------------
// Public block: mode toggle, inline QR, copy + PNG export.
// ----------------------------------------------------------------------------

export function QrStamp({
  hash,
  meta,
  label,
  showLabel = true,
  compact = false,
}: {
  hash: string;
  meta?: StampMeta;
  label?: string;
  showLabel?: boolean;
  compact?: boolean;
}) {
  const { toast } = useToast();
  const [mode, setMode] = useState<"link" | "cert">("link");
  const [busy, setBusy] = useState(false);
  const hasCert = !!(meta?.signature && meta?.issuer_pubkey);
  const payload = mode === "cert" ? certPayload(hash, meta || {}) : linkPayload(hash);

  const download = async () => {
    setBusy(true);
    try {
      const blob = await renderStampPng(payload, hash, meta || {});
      downloadBlob(blob, `nocap-stamp-${(hash || "file").slice(0, 16)}.png`);
      toast("Scan stamp downloaded.", "success");
    } catch {
      toast("Couldn't render the stamp.", "error");
    } finally {
      setBusy(false);
    }
  };

  const copyLink = async () => {
    if (await copyText(linkPayload(hash))) toast("Verify link copied.", "success");
  };

  return (
    <div className={`stamp${compact ? " stamp--compact" : ""}`}>
      {showLabel && (
        <div className="stamp__head">
          <span className="stamp__label">
            <span className="dot" style={{ background: "var(--status-dot)" }} aria-hidden="true" />
            {label || "SCAN TO VERIFY"}
          </span>
          {hasCert && (
            <span className="seg seg--mini">
              <button
                className={`seg__btn${mode === "link" ? " seg__btn--active" : ""}`}
                onClick={() => setMode("link")}
              >
                Scan
              </button>
              <button
                className={`seg__btn${mode === "cert" ? " seg__btn--active" : ""}`}
                onClick={() => setMode("cert")}
              >
                Cert
              </button>
            </span>
          )}
        </div>
      )}

      {showLabel && (
        <Kicker>
          {mode === "link"
            ? "Phone-scan opens the ledger check for this exact fingerprint"
            : "Self-contained signature — verifiable offline by cert-aware tools"}
        </Kicker>
      )}

      <div className="stamp__qrwrap">
        <QrCanvas payload={payload} width={compact ? 128 : 176} />
      </div>

      <div className="stamp__hash" title={hash}>
        <span>sha256</span>
        <code>{shortHash(hash, 24)}</code>
      </div>

      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <Button variant="seal" size="sm" busy={busy} onClick={() => void download()}>
          <IconDownload size={13} /> Download stamp PNG
        </Button>
        {mode === "link" && (
          <Button variant="ghost" size="sm" onClick={() => void copyLink()}>
            <IconCopy size={13} /> Copy link
          </Button>
        )}
      </div>
    </div>
  );
}