// ============================================================================
// AuthorityView — the signed-in console: Google Single Sign-In gate, media
// signing (batched + chunked for big files), the broadcast composer, the
// identity directory with revoke/reinstate, the ledger table + dependency map,
// and the super-admin command bar (sync / rollback / D-Day).
// ============================================================================

import { useEffect, useMemo, useRef, useState } from "react";
import JSZip from "jszip";
import {
  assignRole,
  getLedger,
  getNetwork,
  googleLogin,
  reinstateIdentity,
  revokeIdentity,
  rollbackLedger,
  runDDay,
  setPin,
  signChunk,
  signComplete,
  signFiles,
  signTextNotice,
  syncBlockchain,
  type LedgerPayload,
  type NetworkPayload,
  type Signer,
} from "../api";
import { useAuth, useToast } from "../app/state";
import {
  copyText,
  downloadBlob,
  initials,
  shortHash,
  timeLabel,
} from "../app/util";
import { NetworkMap } from "../components/NetworkMap";
import {
  Button,
  Card,
  Dropzone,
  EmptyNote,
  Field,
  IconBolt,
  IconCheck,
  IconClock,
  IconCopy,
  IconGrid,
  IconKey,
  IconLayers,
  IconLink,
  IconLock,
  IconPen,
  IconUsers,
  Kicker,
  Modal,
  Pill,
  useGsiReady,
} from "../components/ui";
import { downloadReceiptJson, FALLBACK_CLIENT_ID } from "./gsi";

// ----------------------------------------------------------------------------
// Auth gate + Google sign-in button
// ----------------------------------------------------------------------------

function GoogleSignInButton() {
  const containerRef = useRef<HTMLDivElement>(null);
  const ready = useGsiReady();
  const rendered = useRef(false);
  const { refresh } = useAuth();
  const { toast } = useToast();
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  useEffect(() => {
    if (!ready || !containerRef.current || rendered.current) return;
    rendered.current = true;
    const clientId = (import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined) || FALLBACK_CLIENT_ID;
    window.google!.accounts!.id!.initialize({
      client_id: clientId,
      ux_mode: "popup",
      auto_prompt: false,
      callback: async (response) => {
        const res = await googleLogin(response.credential);
        if (res.ok) {
          toast("Authority session established.", "success");
          await refreshRef.current();
        } else {
          toast(res.error || "ACCESS DENIED: Invalid clearance.", "error");
        }
      },
    });
    window.google!.accounts!.id!.renderButton(containerRef.current, {
      type: "standard",
      shape: "rectangular",
      theme: "outline",
      text: "signin_with",
      size: "large",
      logo_alignment: "center",
    });
  }, [ready, toast]);

  return <div ref={containerRef} style={{ minHeight: 44 }} />;
}

function RoleBadge() {
  const { me } = useAuth();
  if (!me) return null;
  const pending = !!me.pending_approval;
  return (
    <div className={`role-badge ${pending ? "role-badge--pending" : "role-badge--ok"}`}>
      <span style={{ fontSize: 20 }}>
        {pending ? <IconClock /> : <IconCheck />}
      </span>
      <div>
        <div className="role-badge__label">
          {pending ? "Pending super-admin approval" : `${me.designation || "Signer"} · ${me.institution || "—"}`}
        </div>
        <div className="role-badge__meta">
          {pending
            ? "Signing is blocked until an administrator approves your post & institution."
            : `Verified signer · ${me.name}`}
        </div>
      </div>
      {me.is_super_admin && <Pill tone="night">super admin</Pill>}
    </div>
  );
}

// ----------------------------------------------------------------------------
// Media signing — batches for small files, chunked for big ones
// ----------------------------------------------------------------------------

const MAX_SINGLE_FILE = 4.2 * 1024 * 1024;
const MAX_BATCH_BYTES = 4 * 1024 * 1024;
const CHUNK_BYTES = 4 * 1024 * 1024;
const MAX_CHUNKS_IN_FLIGHT = 3;

async function signFileChunked(f: File): Promise<{ name: string; blob: Blob }> {
  const session =
    (typeof crypto !== "undefined" && "randomUUID" in crypto && crypto.randomUUID()) ||
    `s${Date.now()}${Math.random().toString(36).slice(2)}`;
  const total = Math.max(1, Math.ceil(f.size / CHUNK_BYTES));

  const jobs: (() => Promise<boolean>)[] = [];
  for (let i = 0; i < total; i++) {
    jobs.push(async () => {
      const slice = f.slice(i * CHUNK_BYTES, Math.min(f.size, (i + 1) * CHUNK_BYTES));
      for (let attempt = 0; attempt < 2; attempt++) {
        const res = await signChunk(session, i, total, f.name, slice);
        if (res.ok) return true;
      }
      return false;
    });
  }
  for (let start = 0; start < jobs.length; start += MAX_CHUNKS_IN_FLIGHT) {
    const batch = jobs.slice(start, start + MAX_CHUNKS_IN_FLIGHT).map((j) => j());
    const results = await Promise.all(batch);
    if (results.includes(false)) throw new Error("Chunk upload failed.");
  }

  const done = await signComplete(session);
  if (!done.ok) throw new Error(done.error || "Signing large file failed.");
  return { name: `signed_${f.name}`, blob: await done.response.blob() };
}

function SignPanel() {
  const { toast } = useToast();
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);

  const total = files.reduce((a, f) => a + (f.size || 0), 0);
  const oversized = files.filter((f) => (f.size || 0) > MAX_SINGLE_FILE).length;

  const handleSign = async () => {
    if (!files.length) return;
    setBusy(true);
    try {
      const big = files.filter((f) => (f.size || 0) > MAX_SINGLE_FILE);
      const normal = files.filter((f) => (f.size || 0) <= MAX_SINGLE_FILE);

      const batches: File[][] = [];
      let cur: File[] = [];
      let curSz = 0;
      for (const f of normal) {
        const sz = f.size || 0;
        if (cur.length && curSz + sz > MAX_BATCH_BYTES) {
          batches.push(cur);
          cur = [];
          curSz = 0;
        }
        cur.push(f);
        curSz += sz;
      }
      if (cur.length) batches.push(cur);

      const signed: { name: string; blob: Blob }[] = [];

      for (const f of big) {
        const r = await signFileChunked(f);
        signed.push(r);
      }
      for (const b of batches) {
        const res = await signFiles(b);
        if (!res.ok) throw new Error(res.error || "Signing failed.");
        const blob = await res.response.blob();
        if (b.length === 1) {
          signed.push({ name: `signed_${b[0].name}`, blob });
        } else {
          const zip = await JSZip.loadAsync(blob);
          for (const [inner, entry] of Object.entries(zip.files)) {
            if (!entry.dir) signed.push({ name: inner, blob: await entry.async("blob") });
          }
        }
      }

      if (signed.length === 1) {
        downloadBlob(signed[0].blob, signed[0].name);
      } else {
        const zip = new JSZip();
        for (const s of signed) zip.file(s.name, s.blob);
        const out = await zip.generateAsync({ type: "blob" });
        downloadBlob(out, "signed_batch.zip");
      }
      toast(`Signed ${signed.length} file${signed.length === 1 ? "" : "s"}. LEDGER 'SIGN_COMPLETE'`, "success");
      setFiles([]);
    } catch (err) {
      toast(err instanceof Error ? err.message : "Signing failed.", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Sign media" icon={<IconPen size={14} />}>
      <Dropzone
        label="Drop files to sign"
        sub={
          files.length
            ? `${files.length} file${files.length > 1 ? "s" : ""} · ${(total / 1024 / 1024).toFixed(2)} MB total${
                oversized ? ` · ${oversized} over ${Math.round(MAX_SINGLE_FILE / 1024 / 1024)} MB → chunked` : ""
              }`
            : "Batch under 4 MB automatically; larger files are chunked and reassembled"
        }
        multiple
        files={files}
        onFiles={setFiles}
      />
      {files.length > 0 && !busy && (
        <div
          className="row mt-3"
          style={{ gap: 6 }}
        >
          {files.map((f, i) => (
            <span className="pill" key={`${f.name}-${i}`}>
              {f.name} · {(f.size / 1024 / 1024).toFixed(2)} MB
            </span>
          ))}
        </div>
      )}
      <Button
        variant="seal"
        className="mt-3"
        block
        busy={busy}
        disabled={!files.length}
        onClick={() => void handleSign()}
      >
        <IconBolt size={15} /> {busy ? "Signing & anchoring…" : "Sign & anchor"}
      </Button>
      <p className="stat-note mt-3">
        Signing injects an invisible forensic trap, records a ledger block, and anchors it to the chain.
      </p>
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Broadcast composer
// ----------------------------------------------------------------------------

function BroadcastComposer() {
  const { toast } = useToast();
  const [title, setTitle] = useState("");
  const [urgency, setUrgency] = useState("HIGH");
  const [message, setMessage] = useState("");
  const [media, setMedia] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [receipt, setReceipt] = useState<{ json: Record<string, unknown>; hash: string; persisted: boolean } | null>(null);

  const mediaFile = media[0] || null;
  const mediaUrl = useMemo(
    () => (mediaFile ? URL.createObjectURL(mediaFile) : null),
    [mediaFile],
  );

  const submit = async () => {
    if (!message.trim()) return;
    setBusy(true);
    try {
      const res = await signTextNotice(title || "Emergency Notice", urgency, message, mediaFile || undefined);
      if (!res.ok) {
        toast(res.error, "error");
        return;
      }
      setReceipt({
        json: res.data.receipt as unknown as Record<string, unknown>,
        hash: res.data.ledger_hash,
        persisted: res.data.ledger_persisted,
      });
      toast(res.data.ledger_persisted ? "Broadcast issued & anchored." : "Broadcast already on record (duplicate).", "success");
      setMessage("");
      setMedia([]);
    } catch {
      toast("Broadcast failed.", "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Issue a broadcast" icon={<IconLayers size={14} />}>
      <div className="row-stretch">
        <Field label="Title">
          <input
            className="input"
            value={title}
            placeholder="Emergency Notice"
            maxLength={120}
            onChange={(e) => setTitle(e.target.value)}
          />
        </Field>
        <Field label="Urgency">
          <select className="select" value={urgency} onChange={(e) => setUrgency(e.target.value)}>
            {(["ADVISORY", "HIGH", "CRITICAL"] as const).map((u) => (
              <option key={u} value={u}>
                {u}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <Field label="Message">
        <textarea
          className="textarea"
          rows={5}
          placeholder="The official statement the public needs to see…"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      </Field>
      <Dropzone
        label="Attach media (optional)"
        sub={mediaFile ? mediaFile.name : "One image or video binds into the signed hash"}
        files={media}
        onFiles={(fs) => setMedia(fs.slice(0, 1))}
        accept="image/*,video/*"
      />
      {mediaUrl && (
        <div className="notice-media" style={{ marginTop: 10 }}>
          {mediaFile!.type.startsWith("video/") ? (
            <video src={mediaUrl} controls style={{ maxHeight: 260 }} />
          ) : (
            <img src={mediaUrl} alt="Media preview" style={{ maxWidth: "100%", maxHeight: 260, objectFit: "contain" }} />
          )}
        </div>
      )}
      <Button
        variant="seal"
        className="mt-3"
        block
        busy={busy}
        disabled={!message.trim()}
        onClick={() => void submit()}
      >
        <IconPen size={15} /> Issue signed broadcast
      </Button>

      {receipt && (
        <div className="verdict__block" style={{ borderTop: "1px dashed var(--line-2)" }}>
          <div className="verdict__block-title">
            <IconCheck size={13} /> RECEIPT {receipt.persisted ? "· PERSISTED" : "· DUPLICATE"}
          </div>
          <p style={{ fontSize: 12.5, color: "var(--ink-2)", lineHeight: 1.6, margin: 0 }}>
            Hash <span className="mono">{shortHash(receipt.hash, 26)}</span> · anchored to IPFS, carved into the ledger.
          </p>
          <div className="row mt-3">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => downloadReceiptJson(receipt.json)}
            >
              <IconCopy size={13} /> Download receipt (.json)
            </Button>
            <Button variant="ghost" size="sm" onClick={() => void copyText(receipt.hash)}>
              Copy hash
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Identity directory + revoke / reinstate
// ----------------------------------------------------------------------------

function IdentityDirectory({
  payload,
  onChanged,
}: {
  payload: LedgerPayload;
  onChanged: () => void;
}) {
  const { me } = useAuth();
  const { toast } = useToast();
  const [manage, setManage] = useState<{ signer: Signer; mode: "revoke" | "reinstate" } | null>(null);
  const [pin, setPinValue] = useState("");
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);
  const [roleAssign, setRoleAssign] = useState<{ email: string; designation: string; institution: string } | null>(null);

  const isSuper = !!me?.is_super_admin;
  const signers = Object.values(payload.signers);

  const submitManage = async () => {
    if (!manage) return;
    setBusy(true);
    const { signer, mode } = manage;
    const target = signer.email;

    if (mode === "revoke") {
      if (!isSuper && !/^\d{5}$/.test(pin)) {
        toast("Enter a 5-digit PIN.", "warn");
        setBusy(false);
        return;
      }
      if (!isSuper && !signer.has_pin) {
        // First-time PIN: set it, then revoke with it (backend accepts new PIN)
        const res = await setPin(pin);
        if (!res.ok) {
          toast(res.error, "error");
          setBusy(false);
          return;
        }
      }
      const res = await revokeIdentity(target, isSuper ? undefined : pin);
      if (res.ok) {
        toast(`${signer.name} revoked — prior signatures marked void.`, "success");
        setManage(null);
        onChanged();
      } else {
        toast(res.error, "error");
      }
    } else {
      const res = await reinstateIdentity(target, pin || "00000");
      if (res.ok) {
        toast(`${signer.name} reinstated.`, "success");
        setManage(null);
        onChanged();
      } else {
        toast(res.error, "error");
      }
    }
    setBusy(false);
    setPinValue("");
    setConfirmText("");
  };

  const submitAssign = async () => {
    if (!roleAssign) return;
    const res = await assignRole(roleAssign.email, roleAssign.designation, roleAssign.institution);
    if (res.ok) {
      toast(`Role assigned to ${roleAssign.email}.`, "success");
      setRoleAssign(null);
      onChanged();
    } else {
      toast(res.error, "error");
    }
  };

  const confirmRequired = manage && manage.mode === "revoke" && isSuper;

  return (
    <Card title="Identity directory" icon={<IconUsers size={14} />}>
      {signers.length === 0 ? (
        <EmptyNote>
          <span className="big">No identities exposed</span>
          <br />
          A regular signer only sees their own record.
        </EmptyNote>
      ) : (
        <div className="stack-sm">
          {signers.map((s) => (
            <div key={s.email} className={`authority-row${s.is_revoked ? " is-revoked" : ""}`}>
              <span className="authority-row__avatar">{initials(s.name)}</span>
              <div className="authority-row__info">
                <div className="authority-row__name">
                  {s.name}
                  {s.is_revoked && <Pill tone="danger" style={{ marginLeft: 8 }}>revoked</Pill>}
                  {s.has_pin && <Pill tone="seal" style={{ marginLeft: 8 }}>pin set</Pill>}
                </div>
                <div className="authority-row__id">{s.email}</div>
                <div className="authority-row__key">
                  {s.designation || "—"} · {s.institution || "—"}
                </div>
              </div>
              <div className="authority-row__actions">
                {isSuper && (
                  <Button size="sm" variant="ghost" onClick={() => setRoleAssign({ email: s.email, designation: s.designation, institution: s.institution })}>
                    Role
                  </Button>
                )}
                <Button
                  size="sm"
                  variant={s.is_revoked ? "seal" : "danger-ghost"}
                  onClick={() => setManage({ signer: s, mode: s.is_revoked ? "reinstate" : "revoke" })}
                >
                  {s.is_revoked ? "Reinstate" : "Revoke"}
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {manage && (
        <Modal
          narrow
          title={manage.mode === "revoke" ? "Revoke identity" : "Reinstate identity"}
          onClose={() => setManage(null)}
          footer={
            <Button
              variant={manage.mode === "revoke" ? "danger-ghost" : "seal"}
              busy={busy}
              disabled={confirmRequired ? confirmText !== "REVOKE" : false}
              onClick={() => void submitManage()}
            >
              Confirm {manage.mode}
            </Button>
          }
        >
          <p style={{ fontSize: 13, color: "var(--ink-2)", lineHeight: 1.6 }}>
            {manage.mode === "revoke" ? (
              <>
                Revoking <strong style={{ color: "var(--ink)" }}>{manage.signer.name}</strong>{" "}
                ({manage.signer.email}) voids this authority's prior signatures across the ledger.
                The blocks remain public — they simply read REVOKED.
              </>
            ) : (
              <>
                Reinstate <strong style={{ color: "var(--ink)" }}>{manage.signer.name}</strong> so they
                can sign again. Their past signatures recover their standing.
              </>
            )}
          </p>

          {confirmRequired && (
            <div className="warning-box mt-3">
              <strong>Super-admin override — no PIN</strong>
              <p>Type REVOKE to confirm this irreversible action.</p>
              <input
                className="input mt-3"
                value={confirmText}
                placeholder="Type REVOKE…"
                onChange={(e) => setConfirmText(e.target.value)}
              />
            </div>
          )}

          {manage.mode === "reinstate" && (
            <Field label="Target's revocation PIN (or 00000 to bypass)">
              <input
                className="input pin-input"
                inputMode="numeric"
                maxLength={5}
                placeholder="•••••"
                value={pin}
                onChange={(e) => setPinValue(e.target.value.replace(/\D/g, ""))}
              />
            </Field>
          )}

          {manage.mode === "revoke" && !isSuper && (
            <Field label="Your 5-digit PIN (first time sets it)">
              <input
                className="input pin-input"
                inputMode="numeric"
                maxLength={5}
                placeholder="•••••"
                value={pin}
                onChange={(e) => setPinValue(e.target.value.replace(/\D/g, ""))}
              />
            </Field>
          )}
        </Modal>
      )}

      {roleAssign && (
        <Modal
          narrow
          title={`Assign role · ${roleAssign.email}`}
          onClose={() => setRoleAssign(null)}
          footer={
            <Button variant="seal" onClick={() => void submitAssign()}>
              Assign
            </Button>
          }
        >
          <Field label="Designation">
            <input
              className="input"
              value={roleAssign.designation}
              placeholder="e.g. Emergency Response Officer"
              onChange={(e) => setRoleAssign({ ...roleAssign, designation: e.target.value })}
            />
          </Field>
          <Field label="Institution">
            <input
              className="input"
              value={roleAssign.institution}
              placeholder="e.g. National Disaster Authority"
              onChange={(e) => setRoleAssign({ ...roleAssign, institution: e.target.value })}
            />
          </Field>
        </Modal>
      )}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Ledger table + dependency map
// ----------------------------------------------------------------------------

const CRYPTO_META: Record<string, { label: string; tone: "seal" | "danger" | "slate" }> = {
  hybrid: { label: "HYBRID", tone: "seal" },
  standard: { label: "STANDARD", tone: "danger" },
};

function LedgerSection({ payload }: { payload: LedgerPayload }) {
  const [filter, setFilter] = useState("");
  const [mode, setMode] = useState<"table" | "map">("table");
  const [net, setNet] = useState<NetworkPayload | null>(null);

  const blocks = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return q
      ? payload.blocks.filter(
          (b) =>
            (b.signer_institution || "").toLowerCase().includes(q) ||
            (b.signer_name || "").toLowerCase().includes(q) ||
            (b.filename || "").toLowerCase().includes(q),
        )
      : payload.blocks;
  }, [payload.blocks, filter]);

  const loadNet = async () => {
    const res = await getNetwork();
    if (res.ok) setNet(res.data);
  };

  return (
    <Card
      title="Provenance ledger"
      icon={<IconGrid size={14} />}
      aside={
        <div className="seg">
          <button
            className={`seg__btn${mode === "table" ? " seg__btn--active" : ""}`}
            onClick={() => setMode("table")}
          >
            Table
          </button>
          <button
            className={`seg__btn${mode === "map" ? " seg__btn--active" : ""}`}
            onClick={() => {
              setMode("map");
              if (!net) void loadNet();
            }}
          >
            Map
          </button>
        </div>
      }
    >
      {mode === "table" ? (
        <>
          <div className="row" style={{ padding: "12px 12px 6px" }}>
            <input
              className="input"
              style={{ maxWidth: 320 }}
              placeholder="Filter by institution, signer, or file…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <span className="stat-note right">{blocks.length} of {payload.total} blocks</span>
          </div>
          <div className="tbl-scroll">
            <table className="tbl">
              <thead>
                <tr>
                  <th>File</th>
                  <th>Signer</th>
                  <th>Role / Org</th>
                  <th>Crypto</th>
                  <th>Anchored</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {blocks.length === 0 && (
                  <tr>
                    <td colSpan={6} className="empty-note">
                      <span className="big">No blocks match</span>
                    </td>
                  </tr>
                )}
                {blocks.map((b) => {
                  const crypto = CRYPTO_META[b.crypto_mode] || { label: b.crypto_mode.toUpperCase(), tone: "slate" as const };
                  return (
                    <tr key={b.id}>
                      <td>
                        <span className="strong trunc" title={b.filename}>{b.filename}</span>
                        <br />
                        <span className="mono" style={{ fontSize: 10 }}> {shortHash(b.file_hash, 20)}</span>
                      </td>
                      <td>{b.signer_name}</td>
                      <td>
                        {b.signer_designation}
                        <br />
                        <span style={{ color: "var(--ink-3)" }}>{b.signer_institution}</span>
                      </td>
                      <td>
                        <Pill tone={crypto.tone}>{crypto.label}</Pill>
                        <br />
                        {b.is_revoked ? <Pill tone="danger">revoked</Pill> : <Pill tone="seal">active</Pill>}
                      </td>
                      <td>
                        {b.tx_hash ? (
                          <span className="mono" style={{ fontSize: 10.5 }}>
                            <IconLink size={11} /> {shortHash(b.tx_hash, 18)}
                          </span>
                        ) : (
                          <span className="mono" style={{ fontSize: 10.5, color: "var(--ink-3)" }}>unanchored</span>
                        )}
                      </td>
                      <td className="mono" style={{ fontSize: 10.5, whiteSpace: "nowrap" }}>
                        {timeLabel(b.timestamp)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      ) : net ? (
        <div style={{ padding: 14 }}>
          <NetworkMap nodes={net.nodes} edges={net.edges} />
        </div>
      ) : (
        <EmptyNote>Loading the authority↔file dependency graph…</EmptyNote>
      )}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Super-admin command bar
// ----------------------------------------------------------------------------

function SuperAdminBar({ onChanged }: { onChanged: () => void }) {
  const { toast } = useToast();
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [rollbackTs, setRollbackTs] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const sync = async () => {
    setBusy("sync");
    const res = await syncBlockchain();
    if (res.ok) toast(res.data.status === "UP_TO_DATE" ? "All blocks already anchored." : `Anchored ${res.data.anchored_blocks_count} blocks — ${res.data.tx_hash}`, "success");
    else toast(res.error, "error");
    setBusy(null);
    onChanged();
  };

  const doRollback = async () => {
    if (!rollbackTs) return;
    setBusy("rollback");
    const ts = rollbackTs.replace("T", " ") + ":00";
    const res = await rollbackLedger(ts);
    if (res.ok) toast(`Ledger rolled back to ${ts} UTC.`, "success");
    else toast(res.error, "error");
    setBusy(null);
    setRollbackOpen(false);
    onChanged();
  };

  const dday = async () => {
    if (!window.confirm("D-DAY SIMULATION: injects 5 malicious signer blocks + 15 forged verifications for the incident-response exercise. Proceed?")) return;
    setBusy("dday");
    const res = await runDDay();
    if (res.ok) toast("D-Day scenario active — the network now shows the attack surface.", "success");
    else toast(res.error, "error");
    setBusy(null);
    onChanged();
  };

  return (
    <Card title="Super admin commands" icon={<IconKey size={14} />} danger>
      <div className="row">
        <Button variant="ink" size="sm" busy={busy === "sync"} onClick={() => void sync()}>
          <IconLink size={13} /> Sync to blockchain
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setRollbackOpen(true)}>
          Rollback ledger
        </Button>
        <Button variant="danger-ghost" size="sm" busy={busy === "dday"} onClick={() => void dday()}>
          Run D-Day simulation
        </Button>
        <span className="stat-note right">These actions are permanent and recorded.</span>
      </div>

      {rollbackOpen && (
        <Modal
          narrow
          title="Rollback ledger"
          onClose={() => setRollbackOpen(false)}
          footer={
            <Button variant="danger-ghost" busy={busy === "rollback"} onClick={() => void doRollback()}>
              Rollback beyond this time
            </Button>
          }
        >
          <p style={{ fontSize: 12.5, color: "var(--ink-2)", lineHeight: 1.6 }}>
            Every ledger block and verification <em>after this timestamp</em> is permanently deleted.
          </p>
          <Field label="Delete everything after (UTC)">
            <input
              className="input"
              type="datetime-local"
              value={rollbackTs}
              onChange={(e) => setRollbackTs(e.target.value)}
            />
          </Field>
        </Modal>
      )}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// The view
// ----------------------------------------------------------------------------

export function AuthorityView() {
  const { signedIn, booting, me } = useAuth();
  const [payload, setPayload] = useState<LedgerPayload | null>(null);

  const loadLedger = async () => {
    const res = await getLedger();
    if (res.ok) setPayload(res.data);
  };

  useEffect(() => {
    if (signedIn) void loadLedger();
  }, [signedIn]);

  if (booting) {
    return (
      <div className="section">
        <EmptyNote>Checking your authority session…</EmptyNote>
      </div>
    );
  }

  if (!signedIn || !me) {
    return (
      <section className="section" style={{ maxWidth: 560, margin: "0 auto" }}>
        <Card title="Restricted access" icon={<IconLock size={14} />}>
          <div style={{ textAlign: "center", padding: "22px 10px" }}>
            <p style={{ color: "var(--ink-2)", marginBottom: 22 }}>
              Authenticate with an authorized Google account to reach the signing
              console, identity directory, and ledger.
            </p>
            <div className="hero__kicker" style={{ display: "inline-flex" }}>
              <span className="dot" aria-hidden="true" /> Google single sign-in
            </div>
            <div style={{ marginTop: 16, display: "flex", justifyContent: "center" }}>
              <GoogleSignInButton />
            </div>
            <p className="stat-note mt-4">
              Roles are assigned only by a super administrator — signing privileges are never self-claimed.
            </p>
          </div>
        </Card>
      </section>
    );
  }

  return (
    <section className="section">
      <div className="section__head">
        <div>
          <Kicker>Authority console</Kicker>
          <h2>Sign, broadcast, and steward the record</h2>
        </div>
        <p>
          {me.name} — session active.{" "}
          {me.is_super_admin ? "Full network visibility." : "Your view is scoped to your own signatures."}
        </p>
      </div>

      <RoleBadge />

      {me.pending_approval ? (
        <Card title="Awaiting approval" icon={<IconKey size={14} />}>
          <EmptyNote>
            <span className="big">Signing is temporarily blocked</span>
            <br />
            A super administrator must assign your post & institution before you can sign files or issue broadcasts.
          </EmptyNote>
        </Card>
      ) : (
        <div className="grid-2 mt-5">
          <SignPanel />
          <BroadcastComposer />
        </div>
      )}

      {me.is_super_admin && (
        <div className="mt-5">
          <SuperAdminBar onChanged={() => void loadLedger()} />
        </div>
      )}

      <div className="mt-5">
        {payload ? (
          <>
            <IdentityDirectory payload={payload} onChanged={() => void loadLedger()} />
            <div className="mt-4">
              <LedgerSection payload={payload} />
            </div>
            <p className="stat-note mt-3">
              Ledger total: {payload.total} blocks. Regular signers see only their own; super admins see the whole chain.
            </p>
          </>
        ) : (
          <Card title="Provenance ledger" icon={<IconGrid size={14} />}>
            <EmptyNote>Loading the ledger…</EmptyNote>
          </Card>
        )}
      </div>

      <div style={{ height: 12 }} />
    </section>
  );
}