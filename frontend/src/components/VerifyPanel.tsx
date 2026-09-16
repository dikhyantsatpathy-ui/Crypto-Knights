// ============================================================================
// VerifyPanel — the public verifier.
//
// Two modes: paste a raw text excerpt, or drop files (including .zip batches —
// each contained file is unpacked and verified individually). Files larger
// than ~3.5MB skip the upload path entirely: the browser keeps the file, sends
// the first 2MB sample plus the FULL-file SHA-256, and the backend checks the
// digest against the ledger. One round-trip, no chunked uploads.
// ============================================================================

import { useEffect, useState, type ReactNode } from "react";
import {
  LARGE_FILE_SAMPLE_BYTES,
  verifyFile,
  verifyHash,
  verifyText as apiVerifyText,
  type VerifyResult,
} from "../api";
import { recordMetric, useToast } from "../app/state";
import { sha256Hex, shortHash } from "../app/util";
import { Button, Card, Dropzone, EmptyNote, Field, IconAlert, IconBolt, IconCheck, IconDoc, IconShield } from "./ui";
import { VerdictCard, expandZip } from "./VerdictCard";

const LARGE_THRESHOLD = 3.5 * 1024 * 1024;

const VERDICT_TOAST: Record<string, string> = {
  AUTHENTIC: "Document verified — AUTHENTIC",
  PROVEN_FAKE: "Document is PROVEN_FAKE — do not trust",
  REVOKED: "Signature revoked by the issuer",
  UNSIGNED: "No matching signature on the ledger",
};

interface PendingVerdict {
  result: VerifyResult;
  name: string;
  blob: Blob | null;
}

/**
 * ScanConfirm — the post-scan trust gate.
 *
 * A scanned QR code only carries a fingerprint. Showing "AUTHENTIC" the moment
 * a code is scanned would let anyone print one off a real document and stick
 * it on a fake. So the code is treated as a REFERENCE, and the file itself has
 * to prove it matches that reference before any verdict is shown.
 */
function ScanConfirm({ hash, onVerified }: { hash: string; onVerified: (r: PendingVerdict) => void }) {
  const { toast } = useToast();
  const [lookup, setLookup] = useState<VerifyResult | null>(null);
  const [checking, setChecking] = useState(true);
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState<"match" | "mismatch" | null>(null);
  const [sentFile, setSentFile] = useState<File[]>([]);

  // the code is a copy of a fingerprint — run the ledger lookup so the user
  // sees WHAT was signed, while making clear it hasn't yet been matched
  // against any actual file in their hands.
  const [lookedUp, setLookedUp] = useState(false);

  useEffect(() => {
    if (lookedUp) return;
    setLookedUp(true);
    void verifyHash(hash)
      .then((res) => {
        if (res.ok) setLookup(res.data);
      })
      .finally(() => setChecking(false));
  }, [hash, lookedUp]);

  const onDrop = async (fs: File[]) => {
    const f = fs[0];
    if (!f || confirming) return;
    setResult(null);
    setConfirming(true);
    try {
      const local = (await sha256Hex(f)).toLowerCase();
      if (local === hash.toLowerCase()) {
        setResult("match");
        const res = await verifyFile(f, f.name);
        if (!res.ok) {
          toast(`Full verification failed — ${res.error}`, "error");
        } else {
          recordMetric(res.data.verdict);
          onVerified({ result: res.data, name: f.name, blob: f });
          toast("This copy matches the scanned fingerprint.", "success");
        }
      } else {
        setResult("mismatch");
        toast("MISMATCH — this file is NOT the one the code belongs to.", "error");
      }
    } finally {
      setConfirming(false);
      setSentFile([]);
    }
  };

  const ledgerLine = lookup
    ? lookup.verdict === "AUTHENTIC"
      ? `Signed by ${lookup.signer?.name || "an authority"}${lookup.signer?.institution ? ` (${lookup.signer.institution})` : ""} — the fingerprint is on the official ledger.`
      : lookup.verdict === "REVOKED"
        ? "This fingerprint was signed but later REVOKED by the issuer."
        : "This fingerprint has NO valid signature on the ledger."
    : null;

  return (
    <div className="scan-confirm" data-status={result ?? checking ? "pending" : "idle"}>
      <div className="scan-confirm__head">
        <span className="scan-confirm__ic"><IconShield size={14} /></span>
        <div>
          <div className="scan-confirm__title">Scanned code — a fingerprint, not a verdict</div>
          <div className="scan-confirm__sub">
            hash <code>{shortHash(hash, 30)}</code>
          </div>
        </div>
      </div>

      {lookup && !checking && ledgerLine && (
        <p className="scan-confirm__line">{ledgerLine}</p>
      )}
      {!lookup && checking && (
        <p className="scan-confirm__line">Checking the ledger for this fingerprint…</p>
      )}
      {!lookup && !checking && (
        <p className="scan-confirm__line">
          Couldn't reach the ledger — the code is still a valid fingerprint, but confirm the file
          matches it before trusting anything.
        </p>
      )}

      {result === "mismatch" && (
        <div className="scan-confirm__gate scan-confirm__gate--bad">
          <strong>This file is NOT the signed original.</strong>
          <br />
          The code belongs to fingerprint <code>{shortHash(hash, 24)}</code>, but this file hashes
          to something else — it has been altered or is a different document entirely.
        </div>
      )}
      {result === "match" && (
        <div className="scan-confirm__gate scan-confirm__gate--good">
          Match confirmed — this is the file the code was issued for. Verdict below.
        </div>
      )}

      <div className="scan-confirm__drop">
        <Dropzone
          label="Drop the actual file to confirm it matches this code"
          sub={sentFile.length ? sentFile[0].name : "The code alone proves nothing — the file must match it"}
          multiple={false}
          files={sentFile}
          onFiles={(fs) => void onDrop(fs)}
          busy={confirming}
        />
      </div>
    </div>
  );
}

export function VerifyPanel({
  scannedHash = null,
  onScannedConsumed,
}: {
  scannedHash?: string | null;
  onScannedConsumed?: () => void;
}) {
  const { toast } = useToast();
  const [mode, setMode] = useState<"file" | "text">("file");
  const [files, setFiles] = useState<File[]>([]);
  const [text, setText] = useState("");

  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState<string | null>(null);
  const [results, setResults] = useState<PendingVerdict[]>([]);

  const [scanDone, setScanDone] = useState(false);
  const [scanAnchored, setScanAnchored] = useState(false);

  // ---- actions -------------------------------------------------------------

  const runVerify = async (blob: Blob, name: string) => {
    const full = await sha256Hex(blob);
    const result =
      blob.size >= LARGE_THRESHOLD
        ? await verifyFile(blob.slice(0, LARGE_FILE_SAMPLE_BYTES), name, full)
        : await verifyFile(blob, name, full);
    if (!result.ok) {
      toast(`Verification failed — ${result.error}`, "error");
      return false;
    }
    recordMetric(result.data.verdict);
    setResults((prev) => [...prev, { result: result.data!, name, blob }]);
    return true;
  };

  const verifySelection = async () => {
    setBusy(true);
    setResults([]);
    let verified = 0;
    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        setBusyLabel(`Verifying ${f.name}…`);
        const lower = f.name.toLowerCase();
        if (lower.endsWith(".zip")) {
          const expanded = await expandZip(f);
          for (const inner of expanded) {
            setBusyLabel(`Unpacking ${f.name} → ${inner.name}…`);
            if (await runVerify(inner.blob, inner.name)) verified++;
          }
        } else if (await runVerify(f, f.name)) {
          verified++;
        }
      }
      if (verified > 0) {
        toast(`Verified ${verified} file${verified > 1 ? "s" : ""} — check the verdict cards`, "success");
      }
    } catch {
      toast("Verification failed — please try again.", "error");
    } finally {
      setBusy(false);
      setBusyLabel(null);
    }
  };

  const verifyAsText = async () => {
    if (!text.trim()) return;
    setBusy(true);
    setResults([]);
    setBusyLabel("Checking text excerpt…");
    try {
      const res = await apiVerifyText(text);
      if (!res.ok) {
        toast(`Verification failed — ${res.error}`, "error");
        return;
      }
      recordMetric(res.data.verdict);
      const verdict = res.data!.verdict;
      setResults((prev) => [...prev, { result: res.data!, name: "text-excerpt.txt", blob: null }]);
      setText("");
      toast(VERDICT_TOAST[verdict] || VERDICT_TOAST.UNSIGNED, verdict === "AUTHENTIC" ? "success" : "error");
    } catch {
      toast("Verification failed — please try again.", "error");
    } finally {
      setBusy(false);
      setBusyLabel(null);
    }
  };

  // ---- render --------------------------------------------------------------

  const filesLabel = files.length
    ? files.map((f) => `${f.name} (${(f.size / 1024 / 1024).toFixed(2)} MB)`).join(", ")
    : null;

  let body: ReactNode;

  if (mode === "text") {
    body = (
      <>
        <Field label="Pasted text">
          <textarea
            className="textarea"
            rows={8}
            placeholder="Paste the raw text of a notice, statement, or screenshot transcript…"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </Field>
        <Button
          variant="seal"
          block
          busy={busy}
          disabled={!text.trim()}
          onClick={() => void verifyAsText()}
        >
          <IconDoc size={15} /> Verify text
        </Button>
      </>
    );
  } else {
    body = (
      <>
        <Dropzone
          label="Drop files or a .zip batch here"
          sub={filesLabel || "Single file, media, or an archive — each member is checked"}
          multiple
          files={files}
          onFiles={setFiles}
          busy={busy}
        />
        {files.length === 0 && !busy && (
          <EmptyNote>
            <span className="big">Nothing staged</span>
            <br />
            Files stay in your browser; we only ever receive a digest.
          </EmptyNote>
        )}
        {files.length > 0 && (
          <Button variant="seal" block busy={busy} onClick={() => void verifySelection()}>
            <IconBolt size={15} /> {busy ? busyLabel : `Verify ${files.length} file${files.length > 1 ? "s" : ""}`}
          </Button>
        )}
      </>
    );
  }

  return (
    <div className="stack">
      <Card title="Verify a file / text" icon={<IconDoc size={14} />}>
        {scannedHash && !scanDone && (
          <>
            <ScanConfirm
              hash={scannedHash}
              onVerified={(r) => {
                setResults([{ ...r, blob: r.blob }]);
                setScanDone(true);
                setScanAnchored(true);
              }}
            />
            <div className="divider" style={{ margin: "16px 0" }} aria-hidden="true" />
          </>
        )}
        {scannedHash && scanAnchored && (
          <div className="row mt-2 mb-1">
            <span className="stat-note" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <IconCheck size={12} /> scanned code matched & verified above
            </span>
            <Button
              variant="ghost"
              size="sm"
              className="ml-auto"
              onClick={() => {
                setScanDone(false);
                setScanAnchored(false);
                onScannedConsumed?.();
              }}
            >
              Scan another code
            </Button>
          </div>
        )}
        <div className="row mt-3 mb-3">
          <div className="seg" role="tablist" aria-label="Verify mode">
            <button
              className={`seg__btn${mode === "file" ? " seg__btn--active" : ""}`}
              onClick={() => setMode("file")}
            >
              File
            </button>
            <button
              className={`seg__btn${mode === "text" ? " seg__btn--active" : ""}`}
              onClick={() => setMode("text")}
            >
              Pasted text
            </button>
          </div>
          <span
            className="stat-note"
            style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 6 }}
          >
            <IconAlert size={12} /> {Math.round(LARGE_FILE_SAMPLE_BYTES / 1024 / 1024)} MB sample + full hash over {Math.round(LARGE_THRESHOLD / 1024 / 1024)} MB
          </span>
        </div>

        {body}
      </Card>

      {results.map((r, i) => (
        <VerdictCard
          key={`${r.result.hash}-${i}`}
          result={r.result}
          name={r.name}
          rawBlob={r.blob}
          onVerifyAnother={() => setResults((prev) => prev.filter((_, idx) => idx !== i))}
        />
      ))}
    </div>
  );
}