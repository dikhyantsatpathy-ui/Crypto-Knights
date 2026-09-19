// ============================================================================
// IdentityVerifyPanel — the officer-facing UI for the identity verification
// suite: Aadhaar Secure QR (offline crypto + checksum), PAN (mock NSDL),
// Driving Licence & RC (mock Parivahan/Vahan), Voter-ID/EPIC (mock EC) and
// Passport (ICAO 9303 MRZ). On top of the checks it renders the visual
// forensics the backend computes with PIL+numpy only: the ELA heatmap, ROI
// boxes overlaid on the photo the officer uploaded, and the passive liveness
// cues. Capabilities this deploy actually has (QR decoder, OCR, signature
// key) come from /api/identity/meta so controls that can't be honored are
// visibly disabled instead of silently failing.
// ============================================================================

import { useEffect, useState } from "react";
import {
  getIdentityMeta,
  identityRegistryCheck,
  IDENTITY_DOC_TYPES,
  verifyIdentity,
  type IdentityMeta,
  type IdentityRegistry,
  type IdentityReport,
  type LivenessResult,
} from "../api";
import { useToast } from "../app/state";
import {
  Button,
  Card,
  Dropzone,
  EmptyNote,
  Field,
  IconBolt,
  IconGrid,
  IconLock,
  IconPen,
  Kicker,
  Pill,
} from "../components/ui";
import { ForensicsHeatmapOverlay } from "./ForensicsHeatmapOverlay";
import { WebcamLivenessSuite } from "./WebcamLivenessSuite";

const VERDICT_TONE: Record<string, "seal" | "amber" | "slate"> = {
  VERIFIED: "seal",
  REVIEW: "amber",
  UNVERIFIED: "slate",
};

function checkOk(value: boolean | string | null): boolean | null {
  return value === true || value === false ? value : null;
}

function QrStatusBadge({ status }: { status: string }) {
  const tone =
    status === "VERIFIED" ? "seal" : status === "INVALID" ? "danger" : "amber";
  return <Pill tone={tone}>{status.replace(/_/g, " ")}</Pill>;
}

const SAMPLE_PRESETS: Record<string, { number: string; name: string; mrz?: string; qr?: string }> = {
  pan: { number: "ABCDP2234A", name: "[Aadhaar Redacted]" },
  driving_licence: { number: "KA0120201234567", name: "[Aadhaar Redacted]" },
  rc: { number: "KA01MJ1234", name: "[Aadhaar Redacted]" },
  voter_id: { number: "ABC1234567", name: "[Aadhaar Redacted]" },
  passport: {
    number: "L898902C",
    name: "ANNA MARIA ERIKSSON",
    mrz: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C<3UTO6908061F9406236ZE184226B<<<<<14",
  },
  aadhaar: {
    number: "234512345670",
    name: "[Aadhaar Redacted]",
    qr: '<uidaiData xmlns="http://www.uidai.gov.in/authentication/uidaidata/1.0" uid="234512345670" name="[Aadhaar Redacted]" dob="01/01/1990" gender="M" co="[Aadhaar Redacted]"></uidaiData>',
  },
};

const REGISTRY_BY_DOC: Record<string, string> = {
  pan: "pan_nsdl",
  driving_licence: "dl_parivahan",
  rc: "rc_vahan",
  voter_id: "epic_ec",
  passport: "passport_registry",
};

function RegistryCard({ registry }: { registry: IdentityRegistry }) {
  const regOk: boolean | null = registry.lost_or_stolen
    ? !registry.registered
    : registry.registered && registry.status === "ACTIVE";
  return (
    <div className="screen-report slate mt-3" data-tone="slate">
      <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <Pill tone={regOk === true ? "seal" : regOk === false ? "danger" : "amber"}>
          {regOk === true ? "verified" : regOk === false ? "flagged" : "unchecked"}
        </Pill>
        <span className="strong">{registry.label}</span>
        <span className="mono stat-note">{registry.masked_number}</span>
        {registry.provider && (
          <span className="stat-note" style={{ opacity: 0.7 }}>
            {registry.live ? `via ${registry.provider}` : "mock data"}
          </span>
        )}
      </div>
      <p className="stat-note mt-2" style={{ lineHeight: 1.5 }}>
        {registry.registered
          ? `Status: ${registry.status ?? "n/a"}${registry.lost_or_stolen ? " (lost/stolen list — presence is bad)" : ""}`
          : (registry.reason ?? "No record.")}
      </p>
      {registry.holder_match !== undefined && registry.holder_match !== null && (
        <p className="stat-note" style={{ lineHeight: 1.5 }}>
          holder match: <strong>{registry.holder_match ? "yes" : "NO"}</strong>
          {registry.holder_label ? ` (${registry.holder_label})` : ""}
        </p>
      )}
      {registry.sample_data && <p className="stat-note" style={{ opacity: 0.65 }}>Sample registry data — set IDV_&lt;REGISTRY&gt;_URL to go live.</p>}
      {registry.registered === null && (
        <p className="stat-note" style={{ opacity: 0.65 }}>Live registry did not answer — no verdict issued, verify with the issuing authority directly.</p>
      )}
    </div>
  );
}

export function IdentityVerifyPanel() {
  const { toast } = useToast();
  const [file, setFile] = useState<File[]>([]);
  const [docType, setDocType] = useState<string>("pan");
  const [docNumber, setDocNumber] = useState("");
  const [holderName, setHolderName] = useState("");
  const [mrzText, setMrzText] = useState("");
  const [qrPayload, setQrPayload] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<IdentityReport | null>(null);
  const [meta, setMeta] = useState<IdentityMeta | null>(null);
  const [pastedNumber, setPastedNumber] = useState("");
  const [manualRegistry, setManualRegistry] = useState<IdentityRegistry | null>(null);

  // Liveness modal state
  const [isLivenessOpen, setIsLivenessOpen] = useState(false);
  const [livenessResult, setLivenessResult] = useState<LivenessResult | null>(null);

  useEffect(() => {
    void getIdentityMeta().then((res) => {
      if (res.ok) setMeta(res.data);
    });
  }, []);

  const fillSpecimen = () => {
    const p = SAMPLE_PRESETS[docType];
    if (p) {
      setDocNumber(p.number);
      setHolderName(p.name);
      if (p.mrz) setMrzText(p.mrz);
      if (p.qr) setQrPayload(p.qr);
      toast(`Loaded specimen template for ${docType.toUpperCase()}`, "info");
    }
  };

  const run = async () => {
    if (!file[0] && !qrPayload.trim() && !mrzText.trim() && !docNumber.trim()) {
      toast("Add a document photo, or paste the MRZ/QR payload / declare a number.", "warn");
      return;
    }
    const declared: Record<string, string> = {};
    if (docNumber.trim()) declared.document_number = docNumber.trim();
    if (holderName.trim()) declared.name = holderName.trim();
    setBusy(true);
    const res = await verifyIdentity(file[0], docType, declared, mrzText.trim(), qrPayload.trim());
    setBusy(false);
    if (res.ok) {
      setReport(res.data);
      toast(`Identity check: ${res.data.verdict}.`, res.data.verdict === "VERIFIED" ? "success" : res.data.verdict === "REVIEW" ? "warn" : "error");
    } else {
      toast(res.error, "error");
    }
  };

  const crossRef = async () => {
    if (!pastedNumber.trim()) {
      toast("Paste a document number to cross-reference.", "warn");
      return;
    }
    const registry = REGISTRY_BY_DOC[docType] ?? "pan_nsdl";
    const res = await identityRegistryCheck(registry, pastedNumber.trim(), holderName.trim());
    setManualRegistry(res.ok ? res.data : null);
    if (!res.ok) toast(res.error, "error");
  };

  const tone = report && VERDICT_TONE[report.verdict];

  return (
    <Card title="Enterprise Identity & Deepfake Detection Suite" icon={<IconLock size={15} />}>
      <div className="row-between mb-3" style={{ flexWrap: "wrap", gap: 8, alignItems: "center" }}>
        <span className="stat-note">
          Offline Cryptography (Aadhaar/pyaadhaar) · Modulus-10 MRZ (ICAO 9303) · OpenCV ELA & YOLO ROI · Anti-Virtual-Camera Liveness
        </span>
        <div className="row" style={{ gap: 8 }}>
          <Button size="sm" variant="ghost" onClick={fillSpecimen}>
            ⚡ Auto-Fill Specimen
          </Button>
          <Button size="sm" variant="seal" onClick={() => setIsLivenessOpen(true)}>
            🎥 Launch Webcam Liveness
          </Button>
        </div>
      </div>

      <div className="row-stretch">
        <Field label="Document type">
          <select
            className="select"
            value={docType}
            onChange={(e) => {
              setDocType(e.target.value);
              setDocNumber("");
              setMrzText("");
              setQrPayload("");
            }}
          >
            {IDENTITY_DOC_TYPES.map((d) => (
              <option key={d} value={d}>
                {d.replace("_", " ").toUpperCase()}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Declared number (optional)">
          <input
            className="input"
            value={docNumber}
            placeholder="Number printed on the document"
            onChange={(e) => setDocNumber(e.target.value)}
          />
        </Field>
        <Field label="Holder name (optional)">
          <input
            className="input"
            value={holderName}
            placeholder="[Aadhaar Redacted]"
            onChange={(e) => setHolderName(e.target.value)}
          />
        </Field>
      </div>

      {docType === "passport" && (
        <Field label="MRZ (paste the lines from the passport's bottom zone)">
          <textarea
            className="input"
            rows={2}
            value={mrzText}
            placeholder="P<INDsmith<<... and the check-digit line…"
            onChange={(e) => setMrzText(e.target.value)}
          />
        </Field>
      )}
      {docType === "aadhaar" && (
        <Field label="Aadhaar Secure QR payload (paste the XML or pyaadhaar integer/bytes)">
          <textarea
            className="input"
            rows={3}
            value={qrPayload}
            placeholder={'<uidaiData xmlns="…" uid="…" …></uidaiData> or base-10 integer'}
            onChange={(e) => setQrPayload(e.target.value)}
          />
        </Field>
      )}

      <Dropzone
        label="Drop document photo (PAN, Aadhaar, Passport, DL, RC, Voter ID)"
        sub="Checksum + format + registry cross-reference + OpenCV ELA heatmap, YOLO ROI boxes and liveness cues. Raw document bytes are never stored."
        accept="image/*"
        files={file}
        onFiles={(f) => setFile(f.slice(0, 1))}
        busy={busy}
      />

      <div className="mt-3 row" style={{ gap: 6, flexWrap: "wrap" }}>
        <span className="stat-note">
          QR decoder: <strong>{meta ? meta.qr_decoder : "…"}</strong> · OCR: <strong>{meta ? (meta.ocr.available ? "on" : "off") : "…"}</strong> · signature key: <strong>{meta ? (meta.aadhaar_crypto.startsWith("configured") ? "configured" : "not set") : "…"}</strong>
        </span>
      </div>

      {!file.length && !busy && !qrPayload.trim() && !mrzText.trim() && !docNumber.trim() && (
        <EmptyNote className="mt-3">
          <span className="big">Nothing staged</span>
          <br />
          Upload the document photo, click <strong>Auto-Fill Specimen</strong>, or paste MRZ / QR payload to verify.
        </EmptyNote>
      )}

      {file.length > 0 || qrPayload.trim() || mrzText.trim() || docNumber.trim() ? (
        <Button variant="seal" block className="mt-3" busy={busy} onClick={() => void run()}>
          <IconBolt size={15} /> {busy ? "Verifying Document…" : "Run Identity & Forensics Verification"}
        </Button>
      ) : null}

      {/* Live Webcam Liveness modal */}
      <WebcamLivenessSuite
        isOpen={isLivenessOpen}
        onClose={() => setIsLivenessOpen(false)}
        onVerified={(res) => {
          setLivenessResult(res);
          toast(`Liveness check completed: ${res.verdict}`, res.liveness_passed ? "success" : "error");
        }}
      />

      {/* Display independent webcam liveness badge if completed */}
      {livenessResult && (
        <div
          className="screen-report mt-3"
          data-tone={livenessResult.liveness_passed ? "seal" : "danger"}
        >
          <div className="row" style={{ gap: 8, alignItems: "center" }}>
            <Pill tone={livenessResult.liveness_passed ? "seal" : "danger"}>
              WEBCAM LIVENESS: {livenessResult.verdict}
            </Pill>
            <span className="stat-note">
              Challenge: <strong>{livenessResult.challenge}</strong> · Confidence: {Math.round(livenessResult.confidence * 100)}%
            </span>
          </div>
        </div>
      )}

      {report && tone && (
        <div className={`screen-report ${tone}`} data-tone={tone}>
          <div className="screen-report__top">
            <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
              <Pill tone={tone}>{report.verdict}</Pill>
              <span className="stat-note">confidence {(report.confidence * 100).toFixed(0)}%</span>
              <span className="mono stat-note">{report.latency_ms ?? "--"} ms</span>
              {report.ocr?.ran === false && (
                <Pill tone="amber">ocr: {(report.ocr.reason ?? "unavailable")}</Pill>
              )}
            </div>
            <div className="mono stat-note" style={{ marginTop: 6 }}>
              {report.doc_type.toUpperCase()} · {report.filename} · {report.created_at}
            </div>
          </div>

          {report.qr && (
            <div className="mt-3 row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <span className="mono stat-note">Aadhaar {report.qr.aadhaar}</span>
              <span className="stat-note">
                name match: <strong>{report.qr.name_matched ? "yes" : "no"}</strong> · photo digest {report.qr.photo_sha256.slice(0, 12)}…
              </span>
              <QrStatusBadge status={report.qr.crypto.status} />
            </div>
          )}

          {report.masked_fields &&
            Object.entries(report.masked_fields).filter(([, v]) => v).length > 0 && (
              <div className="screen-fields mt-3">
                {Object.entries(report.masked_fields)
                  .filter(([, v]) => v !== null && v !== undefined)
                  .map(([k, v]) => (
                    <span className="screen-chip mono" key={k}>
                      {k}: {String(v)}
                    </span>
                  ))}
              </div>
            )}

          <ul className="screen-reasons mt-3">
            {report.checks.map((c, i) => {
              const ok = checkOk(c.ok);
              return (
                <li key={`${c.label}-${i}`}>
                  <span className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                    {ok === null ? (
                      <IconGrid size={13} />
                    ) : (
                      <span style={{ color: ok ? "var(--good, #22c55e)" : "var(--bad, #ef4444)" }}>
                        {ok ? "✓" : "✕"}
                      </span>
                    )}
                    <span style={{ minWidth: 150 }} className="mono">{c.label}</span>
                    <span>{c.detail}</span>
                  </span>
                </li>
              );
            })}
          </ul>

          {report.registry && <RegistryCard registry={report.registry} />}
          {Array.isArray(report.signals) && report.signals.length > 0 && (
            <ul className="screen-reasons mt-3">
              {report.signals.map((s, i) => (
                <li key={`sig-${i}`} style={{ color: "var(--amber, #f59e0b)" }}>
                  {s}
                </li>
              ))}
            </ul>
          )}

          {/* Interactive Forensic Visualization Overlay (ELA Heatmap Blend + YOLO ROI) */}
          {(report.forensics?.ela || (report.forensics?.roi && report.forensics.roi.length > 0)) && (
            <ForensicsHeatmapOverlay
              file={file[0]}
              ela={report.forensics?.ela}
              roi={report.forensics?.roi}
              qa={report.forensics?.qa}
            />
          )}

          {report.forensics?.liveness && report.forensics.liveness.length > 0 && (
            <div className="mt-3">
              <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                <span className="kicker">Passive Frame Cues</span>
              </div>
              <ul className="screen-reasons mt-2">
                {report.forensics.liveness.map((s, i) => (
                  <li key={`lv-${i}`} style={{ color: s.level === "danger" ? "var(--bad, #ef4444)" : s.level === "warn" ? "var(--amber, #f59e0b)" : "inherit" }}>
                    {s.note}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="mt-4" style={{ borderTop: "1px solid var(--line-2)", paddingTop: 14 }}>
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <Kicker>Registry cross-reference</Kicker>
          <span className="stat-note">type a number to check it against the (mock) registry directly</span>
        </div>
        <div className="row mt-2" style={{ gap: 6, flexWrap: "wrap" }}>
          <input
            className="input"
            style={{ maxWidth: 300 }}
            value={pastedNumber}
            placeholder="e.g. a PAN / DL / RC / EPIC / passport number"
            onChange={(e) => setPastedNumber(e.target.value)}
          />
          <Button size="sm" variant="ghost" onClick={() => void crossRef()}>
            <IconPen size={14} /> Check registry
          </Button>
        </div>
        {manualRegistry && <RegistryCard registry={manualRegistry} />}
        {manualRegistry && manualRegistry.registered && (
          <p className="stat-note mt-2">
            The full verify flow combines this with checksum, structure and visual forensics — run it above for the authoritative verdict.
          </p>
        )}
      </div>
    </Card>
  );
}