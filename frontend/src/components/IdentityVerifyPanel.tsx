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

import { useEffect, useMemo, useState } from "react";
import {
  getIdentityMeta,
  identityRegistryCheck,
  IDENTITY_DOC_TYPES,
  verifyIdentity,
  type IdentityForensics,
  type IdentityMeta,
  type IdentityRegistry,
  type IdentityReport,
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

interface PreviewWithRoiProps {
  file: File;
  roi?: IdentityForensics["roi"];
}

function PreviewWithRoi({ file, roi }: PreviewWithRoiProps) {
  const url = useMemo(() => URL.createObjectURL(file), [file]);
  return (
    <div className="mt-3">
      <div className="kicker">Forensic overlay — ROI boxes (normalized)</div>
      <div className="roi-stage" style={{ position: "relative", display: "inline-block", maxWidth: "100%" }}>
        <img src={url} alt="document preview" style={{ display: "block", maxWidth: "100%", borderRadius: 8 }} />
        {Array.isArray(roi) &&
          roi.map((b, i) => (
            <span
              key={`${b.label}-${i}`}
              title={`${b.label} — confidence ${Math.round(b.confidence * 100)}%`}
              style={{
                position: "absolute",
                left: `${b.x * 100}%`,
                top: `${b.y * 100}%`,
                width: `${b.w * 100}%`,
                height: `${b.h * 100}%`,
                border: "2px solid var(--accent, #22c55e)",
                borderRadius: 6,
                boxSizing: "border-box",
                pointerEvents: "none",
              }}
            />
          ))}
      </div>
      {Array.isArray(roi) && roi[0] && (
        <p className="stat-note mt-2">
          face {Math.round(roi[0].confidence * 100)}% · document {roi[1] ? Math.round(roi[1].confidence * 100) : "--"}% · heuristic ROI (YOLO plug-in is local-only)
        </p>
      )}
    </div>
  );
}

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
      {registry.sample_data && <p className="stat-note" style={{ opacity: 0.65 }}>Sample registry data — swap in live NSDL/Parivahan/Vahan/ECI clients later.</p>}
    </div>
  );
}

const REGISTRY_BY_DOC: Record<string, string> = {
  pan: "pan_nsdl",
  driving_licence: "dl_parivahan",
  rc: "rc_vahan",
  voter_id: "epic_ec",
  passport: "passport_registry",
};

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

  useEffect(() => {
    void getIdentityMeta().then((res) => {
      if (res.ok) setMeta(res.data);
    });
  }, []);

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
  const qa = report?.forensics?.qa;
  const ela = report?.forensics?.ela;

  return (
    <Card title="Identity verification suite" icon={<IconLock size={14} />}>
      <div className="row-stretch">
        <Field label="Document type">
          <select className="select" value={docType} onChange={(e) => setDocType(e.target.value)}>
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
        <Field label="MRZ (paste the two lines from the passport's bottom zone)">
          <input
            className="input"
            value={mrzText}
            placeholder="P<INDsmith<<... and the check-digit line…"
            onChange={(e) => setMrzText(e.target.value)}
          />
        </Field>
      )}
      {docType === "aadhaar" && (
        <Field label="Aadhaar Secure QR payload (paste the XML, or upload a QR photo)">
          <textarea
            className="input"
            rows={3}
            value={qrPayload}
            placeholder={'<uidaiData xmlns="…" uid="…" …></uidaiData>'}
            onChange={(e) => setQrPayload(e.target.value)}
          />
        </Field>
      )}

      <Dropzone
        label="Drop the document photo (QR / face / print)"
        sub="Checksum + format + registry cross-reference + ELA heatmap, ROI boxes and liveness cues. Raw document bytes are never stored."
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

      {!file.length && !busy && !qrPayload.trim() && (
        <EmptyNote className="mt-3">
          <span className="big">Nothing staged</span>
          <br />
          Upload the document photo — or for Aadhaar, paste the QR payload; for Passport, paste the MRZ.
        </EmptyNote>
      )}

      {file.length > 0 || qrPayload.trim() || mrzText.trim() ? (
        <Button variant="seal" block className="mt-3" busy={busy} onClick={() => void run()}>
          <IconBolt size={15} /> {busy ? "Verifying…" : "Run identity verification"}
        </Button>
      ) : null}

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

          {report.forensics?.ela && ela && (
            <div className="row mt-3" style={{ gap: 14, flexWrap: "wrap" }}>
              <div style={{ maxWidth: 240 }}>
                <div className="kicker">ELA heatmap — tamper map</div>
                <img
                  src={`data:image/png;base64,${ela.heatmap_b64}`}
                  alt="ELA heatmap"
                  style={{ display: "block", maxWidth: "100%", borderRadius: 8 }}
                />
                <p className="stat-note mt-2">
                  {ela.status} · {Math.round(ela.damage_ratio * 100)}% of 8×8 blocks deviate · re-save quality {ela.quality}
                </p>
              </div>
              {file[0] && (
                <div style={{ minWidth: 220, flex: 1 }}>
                  <PreviewWithRoi file={file[0]} roi={report.forensics?.roi} />
                </div>
              )}
            </div>
          )}

          {qa && !qa.error && (
            <div className="screen-fields mt-3">
              <span className="screen-chip mono">res {qa.width}×{qa.height}</span>
              <span className="screen-chip mono">blur {qa.blur_est}</span>
              {qa.blurry && <span className="screen-chip mono" style={{ color: "var(--amber, #f59e0b)" }}>soft focus</span>}
              {qa.overexposed && <span className="screen-chip mono" style={{ color: "var(--amber, #f59e0b)" }}>overexposed</span>}
            </div>
          )}

          {report.forensics?.liveness && report.forensics.liveness.length > 0 && (
            <div className="mt-3">
              <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                <span className="kicker">Liveness cues (still frame)</span>
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