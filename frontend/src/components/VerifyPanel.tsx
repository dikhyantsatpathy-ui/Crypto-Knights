// ============================================================================
// VerifyPanel — the public verifier.
//
// Two modes: paste a raw text excerpt, or drop files (including .zip batches —
// each contained file is unpacked and verified individually). Files larger
// than ~3.5MB skip the upload path entirely: the browser keeps the file, sends
// the first 2MB sample plus the FULL-file SHA-256, and the backend checks the
// digest against the ledger. One round-trip, no chunked uploads.
// ============================================================================

import { useState, type ReactNode } from "react";
import {
  LARGE_FILE_SAMPLE_BYTES,
  verifyFile,
  verifyText as apiVerifyText,
  type VerifyResult,
} from "../api";
import { recordMetric } from "../app/state";
import { sha256Hex } from "../app/util";
import { Button, Card, Dropzone, EmptyNote, Field, IconAlert, IconBolt, IconDoc, Kicker } from "./ui";
import { VerdictCard, expandZip } from "./VerdictCard";

const LARGE_THRESHOLD = 3.5 * 1024 * 1024;

interface PendingVerdict {
  result: VerifyResult;
  name: string;
  blob: Blob | null;
}

export function VerifyPanel() {
  const [mode, setMode] = useState<"file" | "text">("file");
  const [files, setFiles] = useState<File[]>([]);
  const [text, setText] = useState("");

  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState<string | null>(null);
  const [results, setResults] = useState<PendingVerdict[]>([]);
  const [error, setError] = useState<string | null>(null);

  // ---- actions -------------------------------------------------------------

  const runVerify = async (blob: Blob, name: string) => {
    const full = await sha256Hex(blob);
    const result =
      blob.size >= LARGE_THRESHOLD
        ? await verifyFile(blob.slice(0, LARGE_FILE_SAMPLE_BYTES), name, full)
        : await verifyFile(blob, name, full);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    recordMetric(result.data.verdict);
    setResults((prev) => [...prev, { result: result.data!, name, blob }]);
  };

  const verifySelection = async () => {
    setBusy(true);
    setError(null);
    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        setBusyLabel(`Verifying ${f.name}…`);
        const lower = f.name.toLowerCase();
        if (lower.endsWith(".zip")) {
          const expanded = await expandZip(f);
          for (const inner of expanded) {
            setBusyLabel(`Unpacking ${f.name} → ${inner.name}…`);
            await runVerify(inner.blob, inner.name);
          }
        } else {
          await runVerify(f, f.name);
        }
      }
    } catch {
      setError("Verification failed — please try again.");
    } finally {
      setBusy(false);
      setBusyLabel(null);
    }
  };

  const verifyAsText = async () => {
    if (!text.trim()) return;
    setBusy(true);
    setError(null);
    setBusyLabel("Checking text excerpt…");
    try {
      const res = await apiVerifyText(text);
      if (!res.ok) {
        setError(res.error);
        return;
      }
      recordMetric(res.data.verdict);
      setResults((prev) => [...prev, { result: res.data!, name: "text-excerpt.txt", blob: null }]);
      setText("");
    } catch {
      setError("Verification failed — please try again.");
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
      <div>
        <Kicker>Check the provenance of any file</Kicker>
        <h2 style={{ fontFamily: "var(--serif)", fontSize: 30 }}>Verify it in the ledger</h2>
        <p style={{ color: "var(--ink-2)", marginTop: 8, maxWidth: 560 }}>
          Every official file carries a signed digest. Drop it here and nocap
          re-derives the hash, checks the authority's signature, and runs a
          forensic + AI scan — usually in under a second.
        </p>
      </div>

      {error && (
        <div className="warning-box" role="alert">
          <strong>{error}</strong>
        </div>
      )}

      <Card title="Verify a file / text" icon={<IconDoc size={14} />}>
        <div className="row mt-2 mb-2">
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