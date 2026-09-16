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
import { recordMetric, useToast } from "../app/state";
import { sha256Hex } from "../app/util";
import { Button, Card, Dropzone, EmptyNote, Field, IconAlert, IconBolt, IconDoc } from "./ui";
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

export function VerifyPanel() {
  const { toast } = useToast();
  const [mode, setMode] = useState<"file" | "text">("file");
  const [files, setFiles] = useState<File[]>([]);
  const [text, setText] = useState("");

  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState<string | null>(null);
  const [results, setResults] = useState<PendingVerdict[]>([]);

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