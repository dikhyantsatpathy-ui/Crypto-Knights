// ============================================================================
// VerdictCard — renders a single /api/verify result with full forensic detail:
// headline banner + stamp, forensic reasons, AI-detection explainer, signer
// block, web3 anchor, compare-a-copy hasher, inline media preview, guidance
// and clear next-step actions.
// ============================================================================

import { useEffect, useRef, useState } from "react";
import JSZip from "jszip";
import type { VerifyResult, VerdictKind } from "../api";
import { useToast } from "../app/state";
import { copyText, sha256Hex, shortHash } from "../app/util";
import { Button, IconAlert, IconCheck, IconCopy, IconQuestion, IconShield, IconX } from "./ui";
import { QrStamp, type StampMeta } from "./QrStamp";

interface Profile {
  tone: "auth" | "fake" | "rev" | "uns";
  label: string;
  stamp: string;
}

const PROFILES: Record<VerdictKind, Profile> = {
  AUTHENTIC: { tone: "auth", label: "AUTHENTIC", stamp: "GENUINE" },
  PROVEN_FAKE: { tone: "fake", label: "PROVEN_FAKE", stamp: "FORGERY" },
  REVOKED: { tone: "rev", label: "REVOKED", stamp: "VOID" },
  UNSIGNED: { tone: "uns", label: "UNSIGNED", stamp: "UNOFFICIAL" },
};

export function VerdictCard({
  result,
  name,
  rawBlob,
  onVerifyAnother,
}: {
  result: VerifyResult;
  name: string;
  rawBlob: Blob | null;
  onVerifyAnother: () => void;
}) {
  const { toast } = useToast();
  const data = result;
  const profile = PROFILES[data.verdict] || PROFILES.UNSIGNED;
  const warned = !!data.forgery_warned;
  const tone = warned ? ("rev" as const) : profile.tone;

  // ---- media preview (object URL is revoked when the card unmounts) -------
  const [mediaUrl, setMediaUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!rawBlob) return;
    const ext = (name.split(".").pop() || "").toLowerCase();
    const isMedia =
      !name.toLowerCase().endsWith(".json") && !["pdf", "txt"].includes(ext);
    if (!isMedia) return;
    const url = URL.createObjectURL(rawBlob);
    setMediaUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [rawBlob, name]);

  const ext = (name.split(".").pop() || "").toLowerCase();
  const isVideo = !!mediaUrl && (rawBlob?.type.startsWith("video/") || ["mp4", "mov", "webm", "m4v"].includes(ext));
  const isAudio = !!mediaUrl && (rawBlob?.type.startsWith("audio/") || ["mp3", "wav", "m4a", "ogg"].includes(ext));

  // ---- specialized sub-panels ---------------------------------------------
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  const aiDet = data.ai_detection;
  const providerKey = data.ai_provider || aiDet?.provider || "";
  const showDocumentAi = providerKey === "document";
  const showAiAnalysis = !showDocumentAi && ((aiDet?.ran && aiDet?.ai_score != null) || !!data.ai_score || !!aiDet?.explanation);

  const signer = data.signer;
  const hasSigner = !!(signer && signer.name);
  const baseHash = (data.hash || "").toLowerCase();

  const [expandedSigner, setExpandedSigner] = useState(false);
  const [showWhy, setShowWhy] = useState(false);

  // ---- compare-a-copy ------------------------------------------------------
  const [compareInput, setCompareInput] = useState("");
  const [compareResult, setCompareResult] = useState<string | null>(null);
  const [compareMatch, setCompareMatch] = useState<boolean | null>(null);
  const compareFile = useRef<File | null>(null);

  const runCompare = async (raw: string, file?: File) => {
    let other = raw.trim().toLowerCase();
    if (file) {
      compareFile.current = file;
      other = await sha256Hex(file);
    } else if (!/^[0-9a-f]{64}$/.test(other)) {
      setCompareResult("That doesn't look like a SHA-256 hash (64 hex chars).");
      setCompareMatch(null);
      return;
    }
    const same = baseHash === other;
    setCompareResult(
      same
        ? "MATCH — this copy is byte-for-byte identical to the verified file."
        : "DIFFER — this copy has a different SHA-256, so it is NOT the same bytes.",
    );
    setCompareMatch(same);
  };

  // ---- actions -------------------------------------------------------------
  const copyHash = async () => {
    if (await copyText(data.hash)) toast("Digest copied to clipboard.", "success");
  };

  const reportFake = async () => {
    toast("Reporting — thanks for keeping the record honest.", "info");
    try {
      const fd = new FormData();
      fd.append("file_hash", data.hash);
      const res = await fetch("/api/report", { method: "POST", body: fd, credentials: "include" });
      if (!res.ok) throw new Error("report failed");
      toast("Reported. The ledger will review this digest.", "success");
    } catch {
      toast("Couldn't submit the report.", "error");
    }
  };

  const web3 = data.blockchain_explorer
    ? { href: data.blockchain_explorer, hash: data.tx_hash || "" }
    : null;

  const signerOrgs = [signer?.institution, signer?.designation].filter(Boolean).join(" · ");

  return (
    <article className={`verdict verdict--${tone}`}>
      <div className="verdict__headline">
        <div style={{ minWidth: 0 }}>
          <h3>{data.headline || profile.label}</h3>
          <div className="verdict__file">
            {name} {data.retracted ? "· retracted by issuing authority" : ""}
          </div>
        </div>
        <span className="verdict__stamp">{warned ? "SUSPICIOUS" : profile.stamp}</span>
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto"
          aria-expanded={showWhy}
          onClick={() => setShowWhy((v) => !v)}
          title={showWhy ? "Hide details" : "Why did we reach this verdict?"}
        >
          <IconQuestion size={13} /> {showWhy ? "Hide why" : "Why"}
        </Button>
      </div>

      <div className="verdict__signer">
        <IconShield size={13} />
        {hasSigner ? (
          <>
            Signed by <strong>{signer!.name}</strong>
            {signerOrgs && <span className="pill pill--seal" style={{ marginLeft: 8 }}>{signerOrgs}</span>}
          </>
        ) : (
          <span>No signature found for this file.</span>
        )}
      </div>

      {showWhy && (
        <>
      {data.message && <p className="verdict__note">{data.message}</p>}

      {/* forensic reasons */}
      {reasons.length > 0 && (
        <div className="verdict__block">
          <div className="verdict__block-title">
            <IconQuestion size={13} />
            WHY THIS FILE IS {data.likely_forged || data.verdict === "PROVEN_FAKE" || warned ? "SUSPICIOUS" : "INSPECTED"}
            <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--ink-3)" }}>
              ({data.forensic_leaning || "read"})
            </span>
          </div>
          {reasons.map((r, i) => (
            <div className="reason" key={i}>
              <span className="reason__mark">!</span>
              <span>{r}</span>
            </div>
          ))}
        </div>
      )}

      {/* AI detection */}
      {showDocumentAi && (
        <div className="verdict__block">
          <div className="verdict__block-title">
            <IconCheck size={13} /> SCANNED DOCUMENT <span className="pill pill--seal">document-aware</span>
          </div>
          <p style={{ fontSize: 12.5, color: "var(--ink-2)", lineHeight: 1.6, margin: 0 }}>
            {data.ai_explanation ||
              aiDet?.explanation ||
              "This reads as a scanned document/text page. Its authenticity is proven by the signature and provenance chain, not by image-AI analysis."}
          </p>
        </div>
      )}
      {showAiAnalysis && (
        <div className="verdict__block">
          <div className="verdict__block-title" style={{ color: "var(--seal)" }}>
            <IconShield size={13} /> AI CONTENT DETECTION
            {providerKey && <span className="pill pill--seal">{providerKey}</span>}
            <span className="pill pill--night">{data.ai_model || aiDet?.model || "built-in detector"}</span>
          </div>
          <p style={{ fontSize: 12.5, color: "var(--ink-2)", lineHeight: 1.6, margin: 0 }}>
            {data.ai_explanation ||
              aiDet?.explanation ||
              (showAiAnalysis
                ? "The detector saw no strong AI-generation signature."
                : "No image to analyse.")}
          </p>
          {!!(data.ai_score ?? aiDet?.ai_score) && (
            <div className="row mt-2" style={{ gap: 16 }}>
              <span className="pill">confidence {Math.round(data.ai_score ?? aiDet?.ai_score ?? 0)}%</span>
              {!!aiDet?.latency_ms && <span className="pill">{aiDet.latency_ms} ms</span>}
            </div>
          )}
        </div>
      )}

      {/* signer */}
      <dl className="meta-grid">
        <dt>File</dt>
        <dd>{name}</dd>
        <dt>SHA-256</dt>
        <dd>
          <span className="copyable" onClick={copyHash} title="Copy digest">
            {shortHash(data.hash)} · copy
          </span>
        </dd>
        <dt>Signer</dt>
        <dd>
          {hasSigner ? (
            <>
              <strong>{signer!.name}</strong>
              {signerOrgs && <span className="pill pill--seal" style={{ marginLeft: 8 }}>{signerOrgs}</span>}
            </>
          ) : (
            "No signature metadata."
          )}
        </dd>
        <dt>Web3 TX</dt>
        <dd>
          {web3 ? (
            <>
              <a href={web3.href} target="_blank" rel="noopener noreferrer">
                {shortHash(web3.hash, 26)}
              </a>{" "}
              <span className="pill pill--seal">L2 anchored</span>
            </>
          ) : (
            "Not anchored"
          )}
        </dd>
      </dl>

      {hasSigner && (
        <div className="verdict__block">
          <div className="verdict__block-title">WHO SIGNED THIS</div>
          <p style={{ fontSize: 13, fontWeight: 600, color: "var(--ink)", margin: 0 }}>
            {signer!.name}
            {signerOrgs && <span style={{ color: "var(--ink-2)", fontWeight: 400 }}> — {signerOrgs}</span>}
          </p>
          {signer!.signature_guidance && (
            <p style={{ fontSize: 12, color: "var(--ink-2)", marginTop: 6 }}>{signer!.signature_guidance}</p>
          )}
        </div>
      )}

      {/* scannable verify/cert stamp — binds a fixed fingerprint to this file */}
      {data.verdict === "AUTHENTIC" && baseHash && (
        <div className="verdict__block verdict__stamp-row">
          <div className="verdict__block-title">
            <IconShield size={13} /> VERIFICATION STAMP
            <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--ink-3)" }}>
              — a code bound to this exact fingerprint
            </span>
          </div>
          <QrStamp
            hash={baseHash}
            meta={(data.ledger || {}) as StampMeta}
            label="VERIFIED · scan checks the ledger"
          />
          <p className="stamp-note" role="note">
            A stamp only certifies the fingerprint above. If this code is cut off and stuck onto a
            different file, scanning it still points here — then the file you actually hold gets
            hashed and the mismatch is reported. Never trust the code alone; drop the real file.
          </p>
        </div>
      )}

      {/* compare a copy */}
      {baseHash && (
        <div className="verdict__block">
          <div className="verdict__block-title">
            <IconCopy size={13} /> COMPARE A COPY
            <span style={{ textTransform: "none", letterSpacing: 0, color: "var(--ink-3)" }}>
              — paste another hash or drop a second file
            </span>
          </div>
          <div
            style={{ display: "flex", gap: 8 }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              const f = e.dataTransfer.files?.[0];
              if (f) {
                setCompareInput(f.name);
                void runCompare("", f);
              }
            }}
          >
            <input
              className="input"
              style={{ flex: 1 }}
              value={compareInput}
              placeholder="Paste a SHA-256 hash, or drop a file here…"
              onChange={(e) => setCompareInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void runCompare(compareInput);
                }
              }}
            />
            <Button variant="ghost" size="sm" onClick={() => void runCompare(compareInput)}>
              Compare
            </Button>
          </div>
          {compareResult && (
            <p
              className="mt-2"
              style={{ fontSize: 12.5, fontWeight: 600, color: compareMatch ? "var(--seal-2)" : "var(--danger)" }}
            >
              {compareMatch ? "✓ " : "✗ "}
              {compareResult}
            </p>
          )}
        </div>
      )}

      {mediaUrl && (
        <div className={`media-frame media-frame--${tone}`}>
          {isVideo ? (
            <video controls src={mediaUrl} style={{ maxHeight: 260 }} />
          ) : isAudio ? (
            <audio controls src={mediaUrl} />
          ) : (
            <img src={mediaUrl} alt="Verified media" style={{ width: "100%", maxHeight: 260, objectFit: "contain" }} />
          )}
        </div>
      )}

      <div className="guidance">
        <span className="guidance__ic">?</span>
        <span>{data.guidance}</span>
      </div>

      <div className="cta-row">
        {data.verdict === "PROVEN_FAKE" && (
          <Button variant="danger-ghost" onClick={reportFake}>
            <IconX size={14} /> Report this fake
          </Button>
        )}
        {data.verdict === "AUTHENTIC" && !warned && (
          <Button variant="seal">
            <IconCheck size={14} /> Trust this file
          </Button>
        )}
        {data.verdict === "AUTHENTIC" && warned && (
          <Button variant="ghost" onClick={() => setExpandedSigner((v) => !v)}>
            <IconShield size={14} /> Check with the issuer
          </Button>
        )}
        {hasSigner && (data.verdict === "REVOKED" || (data.verdict === "AUTHENTIC" && !warned)) && (
          <Button variant="ghost" onClick={() => setExpandedSigner((v) => !v)}>
            <IconShield size={14} /> Verify who signed this
          </Button>
        )}
        {data.verdict === "UNSIGNED" && (
          <Button variant="danger-ghost" disabled>
            <IconAlert size={14} /> No official source
          </Button>
        )}
        <Button variant="ghost" onClick={onVerifyAnother}>
          Verify another file
        </Button>
      </div>

      {expandedSigner && hasSigner && (
        <div className="verdict__block">
          <p style={{ fontSize: 12.5, color: "var(--ink-2)", margin: 0, lineHeight: 1.6 }}>
            Signed by{" "}
            <strong style={{ color: "var(--ink)" }}>{signer!.name}</strong>
            {signerOrgs && <> ({signerOrgs})</>}. The role inside the signature is assigned only by a super
            administrator — signers cannot claim their own titles.
          </p>
        </div>
      )}
        </>
      )}
    </article>
  );
}

// ----------------------------------------------------------------------------
// Archive expansion — recursive, bomb-guarded
// ----------------------------------------------------------------------------

const MAX_ZIP_DEPTH = 3;
const MAX_ZIP_ENTRIES = 200;

/** Expand an archive in the browser so every inner file is checked individually.
 *  Nested .zip files are unpacked recursively; each member comes back with a
 *  path that traces back through its archives (e.g. "bundle/docs/report.pdf"),
 *  so the verdict cards stay readable and nothing is silently skipped.
 *  A corrupt / encrypted / empty archive falls through and is returned as a
 *  single item — it is still hashed and checked against the ledger as-is. */
export async function expandZip(
  blob: Blob | File,
  name: string = blob instanceof File ? blob.name : "archive.zip",
  depth = 0,
  out: { blob: Blob; name: string }[] = [],
): Promise<{ blob: Blob; name: string }[]> {
  if (depth >= MAX_ZIP_DEPTH || out.length >= MAX_ZIP_ENTRIES) {
    out.push({ blob, name });
    return out;
  }
  try {
    const zip = await JSZip.loadAsync(blob);
    const entries = Object.entries(zip.files);
    if (!entries.length) throw new Error("empty archive");
    const base = name.replace(/\.zip$/i, "").replace(/\/+$/, "");
    let expanded = 0;
    for (const [path, entry] of entries) {
      if (entry.dir || out.length >= MAX_ZIP_ENTRIES) continue;
      const member = await entry.async("blob");
      const memberName = `${base}/${path}`;
      if (path.toLowerCase().endsWith(".zip")) {
        await expandZip(member, memberName, depth + 1, out);
      } else {
        out.push({ blob: member, name: memberName });
      }
      expanded++;
    }
    if (out.length) return out;
  } catch {
    /* fall through and hash the archive itself */
  }
  return [{ blob, name }];
}