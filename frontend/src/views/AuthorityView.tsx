// ============================================================================
// AuthorityView — the signed-in console: Google Single Sign-In gate, media
// signing (batched + chunked for big files), the broadcast composer, the
// identity directory with revoke/reinstate, the provenance ledger table,
// and the administrator command bar (sync / rollback).
// ============================================================================

import { useEffect, useMemo, useRef, useState } from "react";
import JSZip from "jszip";
import {
  adjudicateScreen,
  addWatchlistEntry,
  assignRole,
  getLedger,
  getScreenQueue,
  getScreenReport,
  getWatchlist,
  googleLogin,
  reinstateIdentity,
  removeWatchlistEntry,
  revokeIdentity,
  rollbackLedger,
  SCREEN_DOC_TYPES,
  screenDocument,
  setPin,
  signChunk,
  signComplete,
  signFiles,
  signTextNotice,
  syncBlockchain,
  type LedgerPayload,
  type ScreenQueue,
  type ScreenReport,
  type Signer,
  type WatchlistEntry,
} from "../api";
import { useAuth, useToast } from "../app/state";
import {
  copyText,
  downloadBlob,
  initials,
  shortHash,
  timeLabel,
} from "../app/util";
import { expandZip } from "../components/VerdictCard";
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

function AuthorityProfileHeader({ payload }: { payload: LedgerPayload | null }) {
  const { me } = useAuth();
  if (!me) return null;
  const pending = !!me.pending_approval;

  return (
    <div className="auth-profile rv rv--d1">
      <div className="auth-profile__user">
        <div className="auth-profile__avatar-wrap">
          <div className="auth-profile__avatar">
            {initials(me.name)}
          </div>
          <span
            className="auth-profile__status-dot"
            style={{ background: pending ? "var(--warn)" : "var(--seal-2)" }}
            title={pending ? "Pending approval" : "Verified session"}
            aria-hidden="true"
          />
        </div>
        <div className="auth-profile__meta">
          <h3>
            {me.name}
            {me.is_super_admin ? (
              <Pill tone="night">Administrator</Pill>
            ) : pending ? (
              <Pill tone="amber">Pending Approval</Pill>
            ) : (
              <Pill tone="seal">Verified Signer</Pill>
            )}
          </h3>
          <div className="auth-profile__sub">
            {pending
              ? "Signing blocked until an administrator assigns your institution"
              : `${me.designation || "Signer"} · ${me.institution || "Root Authority"} · ${me.admin}`}
          </div>
        </div>
      </div>

      <div className="auth-profile__stats">
        <div className="auth-stat-pill">
          <IconLayers size={13} />
          <span>Ledger:</span>
          <strong>{payload ? `${payload.total} blocks` : "—"}</strong>
        </div>
        <div className="auth-stat-pill">
          <IconUsers size={13} />
          <span>Identities:</span>
          <strong>{payload ? `${Object.keys(payload.signers).length}` : "—"}</strong>
        </div>
        <div className="auth-stat-pill">
          <span className="dot" style={{ background: "var(--seal-2)" }} aria-hidden="true" />
          <span>Network:</span>
          <strong>L2 Anchored</strong>
        </div>
      </div>
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

async function signFileChunked(name: string, blob: Blob): Promise<{ name: string; blob: Blob }> {
  const session =
    (typeof crypto !== "undefined" && "randomUUID" in crypto && crypto.randomUUID()) ||
    `s${Date.now()}${Math.random().toString(36).slice(2)}`;
  const total = Math.max(1, Math.ceil(blob.size / CHUNK_BYTES));

  const jobs: (() => Promise<boolean>)[] = [];
  for (let i = 0; i < total; i++) {
    jobs.push(async () => {
      const slice = blob.slice(i * CHUNK_BYTES, Math.min(blob.size, (i + 1) * CHUNK_BYTES));
      for (let attempt = 0; attempt < 2; attempt++) {
        const res = await signChunk(session, i, total, name, slice);
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
  return { name: `signed_${name}`, blob: await done.response.blob() };
}

/** Flat, collision-free member keys: keep the original basename, but when two
 *  members imported from different archives/folders share a basename, prefix
 *  with the sanitized parent path so nothing is silently overwritten. */
function uniqueSignKeys(items: { name: string; blob: Blob }[]): { name: string; blob: Blob }[] {
  const counts = new Map<string, number>();
  for (const it of items) {
    const base = (it.name.split("/").pop() || it.name).replace(/[^a-zA-Z0-9._-]+/g, "_");
    counts.set(base, (counts.get(base) || 0) + 1);
  }
  const used = new Set<string>();
  return items.map((it) => {
    const base = (it.name.split("/").pop() || it.name).replace(/[^a-zA-Z0-9._-]+/g, "_");
    let key = base;
    if (counts.get(base)! > 1 && it.name.includes("/")) {
      const folder = it.name.slice(0, it.name.lastIndexOf("/")).replace(/[^a-zA-Z0-9._-]+/g, "_");
      key = `${folder}_${base}`;
    }
    let i = 1;
    while (used.has(key)) key = `${i++}_${key}`;
    used.add(key);
    return { name: key, blob: it.blob };
  });
}

function SignPanel({ onSigned, bare }: { onSigned?: () => void; bare?: boolean }) {
  const { toast } = useToast();
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState<string | null>(null);

  const total = files.reduce((a, f) => a + (f.size || 0), 0);
  const oversized = files.filter((f) => (f.size || 0) > MAX_SINGLE_FILE).length;

  const handleSign = async () => {
    if (!files.length) return;
    setBusy(true);
    setBusyLabel("Preparing files…");
    try {
      // Archives are unpacked FIRST so every internal file is signed on its own
      // and lands in the ledger — a notice re-zipped with its signed file later
      // verifies individually instead of appearing unsigned.
      const members: { name: string; blob: Blob }[] = [];
      for (const f of files) {
        if (f.name.toLowerCase().endsWith(".zip")) {
          setBusyLabel(`Unpacking ${f.name}…`);
          const inner = await expandZip(f);
          members.push(...inner);
        } else {
          members.push({ name: f.name, blob: f });
        }
      }

      const items = uniqueSignKeys(members);
      const big = items.filter((it) => it.blob.size > MAX_SINGLE_FILE);
      const normal = items.filter((it) => it.blob.size <= MAX_SINGLE_FILE);

      const batches: typeof items[] = [];
      let cur: typeof items = [];
      let curSz = 0;
      for (const it of normal) {
        const sz = it.blob.size;
        if (cur.length && curSz + sz > MAX_BATCH_BYTES) {
          batches.push(cur);
          cur = [];
          curSz = 0;
        }
        cur.push(it);
        curSz += sz;
      }
      if (cur.length) batches.push(cur);

      const signed: { name: string; blob: Blob }[] = [];

      setBusyLabel("Anchoring to ledger…");
      for (const it of big) {
        const r = await signFileChunked(it.name, it.blob);
        signed.push(r);
      }
      for (const b of batches) {
        const res = await signFiles(b.map((it) => it.blob));
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
      toast(`Signed ${signed.length} file${signed.length === 1 ? "" : "s"} — each member is ledger-verified.`, "success");
      setFiles([]);
      onSigned?.();
    } catch (err) {
      toast(err instanceof Error ? err.message : "Signing failed.", "error");
    } finally {
      setBusy(false);
      setBusyLabel(null);
    }
  };

  const signContent = (
    <>
      <Dropzone
        label="Drop files to sign"
        sub={
          files.length
            ? `${files.length} file${files.length > 1 ? "s" : ""} · ${(total / 1024 / 1024).toFixed(2)} MB total${
                oversized ? ` · ${oversized} over ${Math.round(MAX_SINGLE_FILE / 1024 / 1024)} MB → chunked` : ""
              }`
            : "Drop files or a .zip — archives are unpacked and every member is signed individually"
        }
        multiple
        files={files}
        onFiles={setFiles}
        busy={busy}
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
        size="lg"
        className="mt-3"
        block
        busy={busy}
        disabled={!files.length}
        onClick={() => void handleSign()}
      >
        <IconBolt size={15} /> {busy ? busyLabel || "Signing…" : "Sign & anchor"}
      </Button>
      <p className="stat-note mt-3">
        Signing injects an invisible forensic trap, records a ledger block, and anchors it to the chain.
      </p>
    </>
  );

  if (bare) return signContent;

  return (
    <Card title="Sign media" icon={<IconPen size={14} />}>
      {signContent}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Broadcast composer
// ----------------------------------------------------------------------------

function BroadcastComposer({ onIssued, bare }: { onIssued?: () => void; bare?: boolean }) {
  const { toast } = useToast();
  const [title, setTitle] = useState("");
  const [urgency, setUrgency] = useState("HIGH");
  const [message, setMessage] = useState("");
  const [media, setMedia] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<{ json: Record<string, unknown>; hash: string; persisted: boolean } | null>(null);

  const mediaFile = media[0] || null;
  const [mediaUrl, setMediaUrl] = useState<string | null>(null);
  const lastMediaUrl = useRef<string | null>(null);
  useEffect(() => {
    if (lastMediaUrl.current) {
      URL.revokeObjectURL(lastMediaUrl.current);
      lastMediaUrl.current = null;
    }
    if (mediaFile) {
      const url = URL.createObjectURL(mediaFile);
      lastMediaUrl.current = url;
      setMediaUrl(url);
    } else {
      setMediaUrl(null);
    }
  }, [mediaFile]);

  const submit = async () => {
    if (!message.trim()) return;
    setBusy(true);
    setBusyLabel("Computing hash…");
    try {
      const hashTimer = window.setTimeout(() => setBusyLabel("Anchoring broadcast…"), 600);
      const res = await signTextNotice(title || "Emergency Notice", urgency, message, mediaFile || undefined);
      window.clearTimeout(hashTimer);
      if (!res.ok) {
        toast(res.error, "error");
        return;
      }
      setReceipt({
        json: res.data.receipt as unknown as Record<string, unknown>,
        hash: res.data.ledger_hash,
        persisted: res.data.ledger_persisted,
      });
      toast(res.data.ledger_persisted ? "Document successfully anchored." : "Broadcast already on record (duplicate).", "success");
      setMessage("");
      setMedia([]);
      onIssued?.();
    } catch {
      toast("Broadcast failed.", "error");
    } finally {
      setBusy(false);
      setBusyLabel(null);
    }
  };

  const broadcastContent = (
    <>
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
        busy={busy}
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
        size="lg"
        className="mt-3"
        block
        busy={busy}
        disabled={!message.trim()}
        onClick={() => void submit()}
      >
        <IconPen size={15} /> {busy ? busyLabel || "Processing…" : "Issue signed broadcast"}
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
    </>
  );

  if (bare) return broadcastContent;

  return (
    <>
      <Card title="Issue a broadcast" icon={<IconLayers size={14} />}>
        {broadcastContent}
      </Card>
    </>
  );
}

// ----------------------------------------------------------------------------
// Identity directory + revoke / reinstate
// ----------------------------------------------------------------------------

function IdentityDirectory({
  payload,
  onChanged,
  bare,
}: {
  payload: LedgerPayload;
  onChanged: () => void;
  bare?: boolean;
}) {
  const { me } = useAuth();
  const { toast } = useToast();
  const [manage, setManage] = useState<{ signer: Signer; mode: "revoke" | "reinstate" } | null>(null);
  const [pin, setPinValue] = useState("");
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);
  const [roleAssign, setRoleAssign] = useState<{ email: string; designation: string; institution: string } | null>(null);

  // compact, searchable directory: filter by status + free text
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"all" | "active" | "revoked">("all");

  const isSuper = !!me?.is_super_admin;
  const signers = Object.values(payload.signers);
  const q = query.trim().toLowerCase();
  const filtered = signers.filter((s) => {
    if (status === "active" && s.is_revoked) return false;
    if (status === "revoked" && !s.is_revoked) return false;
    if (!q) return true;
    return [s.name, s.email, s.designation, s.institution].some((v) =>
      (v || "").toLowerCase().includes(q)
    );
  });

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

  const dirContent = (
    <>
      {signers.length === 0 ? (
        <EmptyNote>
          <span className="big">No identities exposed</span>
          <br />
          A regular signer only sees their own record.
        </EmptyNote>
      ) : (
        <>
          <div className="dir-toolbar">
            <input
              className="input dir-search"
              placeholder="Search name, email, designation, institution…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Filter identity directory"
            />
            <div className="dir-tabs" role="tablist" aria-label="Filter by status">
              <button
                className={`dir-tab${status === "all" ? " dir-tab--active" : ""}`}
                onClick={() => setStatus("all")}
              >
                All
              </button>
              <button
                className={`dir-tab${status === "active" ? " dir-tab--active" : ""}`}
                onClick={() => setStatus("active")}
              >
                Active
              </button>
              <button
                className={`dir-tab${status === "revoked" ? " dir-tab--active" : ""}`}
                onClick={() => setStatus("revoked")}
              >
                Revoked
              </button>
            </div>
            <span className="dir-count">
              {filtered.length} / {signers.length}
            </span>
          </div>

          {filtered.length === 0 ? (
            <EmptyNote>No identities match that filter.</EmptyNote>
          ) : (
            <div className="dir-scroll">
              {filtered.map((s) => (
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
        </>
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
              <strong>Administrator override — no PIN</strong>
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
    </>
  );

  if (bare) return dirContent;

  return (
    <Card title="Identity directory" icon={<IconUsers size={14} />}>
      {dirContent}
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

function LedgerSection({ payload, bare }: { payload: LedgerPayload; bare?: boolean }) {
  const [filter, setFilter] = useState("");

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

  const ledgerContent = (
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
  );

  if (bare) return ledgerContent;

  return (
    <Card title="Provenance ledger" icon={<IconGrid size={14} />}>
      {ledgerContent}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Administrator command bar
// ----------------------------------------------------------------------------

function SuperAdminBar({ onChanged }: { onChanged: () => void }) {
  const { toast } = useToast();
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [rollbackTs, setRollbackTs] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const sync = async () => {
    setBusy("sync");
    const res = await syncBlockchain();
    if (res.ok) toast(res.data.status === "UP_TO_DATE" ? "All blocks already anchored." : `Anchored ${res.data.anchored_blocks_count ?? 0} blocks — ${res.data.tx_hash || "n/a"}`, "success");
    else toast(res.error, "error");
    setBusy(null);
    onChanged();
  };

  const doRollback = async () => {
    if (!rollbackTs) return;
    setBusy("rollback");
    const local = new Date(rollbackTs);
    if (Number.isNaN(local.getTime())) {
      toast("Pick a valid date/time.", "error");
      setBusy(null);
      return;
    }
    // datetime-local is local time; the ledger lives in UTC.
    const ts = local.toISOString().slice(0, 19).replace("T", " ") + " UTC";
    const res = await rollbackLedger(ts);
    if (res.ok) toast(`Ledger rolled back to ${ts}.`, "success");
    else toast(res.error, "error");
    setBusy(null);
    setRollbackOpen(false);
    onChanged();
  };

  return (
    <Card
      title="Administrator operations"
      icon={<IconKey size={14} />}
      danger
      aside={<span className="stat-note">Root authority clearance</span>}
    >
      <div className="admin-grid">
      <div className="admin-card">
        <div className="admin-card__title">
          <IconLink size={16} /> Blockchain Anchoring
        </div>
        <p className="admin-card__desc">
          Sync newly signed ledger digests and anchor the cryptographic Merkle root to Ethereum L2 for public non-repudiation.
        </p>
        <div className="admin-card__actions">
          <Button variant="ink" size="sm" block busy={busy === "sync"} onClick={() => void sync()}>
            <IconLink size={13} /> Sync to blockchain
          </Button>
        </div>
      </div>

      <div className="admin-card">
        <div className="admin-card__title">
          <IconClock size={16} /> Ledger Rollback
        </div>
        <p className="admin-card__desc">
          Time-travel recovery: roll the cryptographic provenance chain back to any UTC timestamp to excise compromised blocks.
        </p>
        <div className="admin-card__actions">
          <Button variant="ghost" size="sm" block onClick={() => setRollbackOpen(true)}>
            Configure rollback
          </Button>
        </div>
      </div>
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
          <p className="stat-note mt-3" style={{ margin: "12px 0 0" }}>
            Your local date/time is converted to UTC before it leaves the browser.
          </p>
        </Modal>
      )}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Screening desk — MHA SIH26188: AI-Based Fake Identity & Document Screening
// Upload -> Extract -> Analyze -> Verify -> Assess Risk, human-in-the-loop.
// ----------------------------------------------------------------------------

const VERDICT_META: Record<string, { pill: "seal" | "amber" | "danger" }> = {
  CLEAR: { pill: "seal" },
  REVIEW: { pill: "amber" },
  FLAGGED: { pill: "danger" },
};

const MODULE_VERDICT_TONE: Record<string, "seal" | "amber" | "danger" | "slate"> = {
  PASS: "seal",
  CLEAR: "seal",
  REVIEW: "amber",
  FAIL: "danger",
  UNVERIFIED: "slate",
};

/** Captures a single JPEG still from the operator's camera (Module 4 input). */
function LiveCapture({ onFrame }: { onFrame: (blob: Blob | null) => void }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [active, setActive] = useState(false);
  const [imgUrl, setImgUrl] = useState<string | null>(null);
  const [denied, setDenied] = useState(false);

  const stop = () => {
    const v = videoRef.current;
    if (v && v.srcObject) {
      (v.srcObject as MediaStream).getTracks().forEach((t) => t.stop());
      v.srcObject = null;
    }
    setActive(false);
  };

  const start = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" }, audio: false });
      const v = videoRef.current;
      if (!v) {
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      v.srcObject = stream;
      await v.play();
      setActive(true);
      setDenied(false);
    } catch {
      setDenied(true);
    }
  };

  const capture = () => {
    const v = videoRef.current;
    if (!v || !v.videoWidth) return;
    const c = document.createElement("canvas");
    c.width = v.videoWidth;
    c.height = v.videoHeight;
    c.getContext("2d")?.drawImage(v, 0, 0);
    c.toBlob(
      (blob) => {
        if (!blob) return;
        onFrame(blob);
        setImgUrl(URL.createObjectURL(blob));
        stop();
      },
      "image/jpeg",
      0.85,
    );
  };

  // release object URL on unmount / replace
  useEffect(() => {
    return () => {
      stop();
      if (imgUrl) URL.revokeObjectURL(imgUrl);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [imgUrl]);

  return (
    <div className="row" style={{ gap: 10, flexWrap: "wrap", alignItems: "center" }}>
      <video
        ref={videoRef}
        playsInline
        muted
        style={{
          display: active ? "block" : "none",
          width: 150,
          height: 105,
          borderRadius: "var(--r-sm)",
          background: "#000",
          objectFit: "cover",
        }}
      />
      {imgUrl && (
        <img
          src={imgUrl}
          alt="holder capture"
          style={{
            width: 150,
            height: 105,
            borderRadius: "var(--r-sm)",
            objectFit: "cover",
            border: "2px solid var(--border-seal-mid)",
          }}
        />
      )}
      <div className="stack-sm">
        <span className="stat-note">Module 4 — holder capture</span>
        {!active && !imgUrl && (
          <Button size="sm" variant={denied ? "danger-ghost" : "ghost"} onClick={() => void start()}>
            {denied ? "Camera blocked — retry" : "Open camera"}
          </Button>
        )}
        {active && (
          <Button size="sm" variant="seal" onClick={capture}>
            Capture frame
          </Button>
        )}
        {imgUrl && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              onFrame(null);
              setImgUrl(null);
              void start();
            }}
          >
            Retake
          </Button>
        )}
      </div>
    </div>
  );
}

interface ModuleCheckRow {
  label: string;
  ok: boolean | null;
  detail: string;
}

function ScreenCheckRow({ check }: { check: ModuleCheckRow }) {
  const tone = check.ok === true ? "pass" : check.ok === false ? "fail" : "na";
  return (
    <div className={`screen-check screen-check--${tone}`}>
      <span className="screen-check__dot" aria-hidden="true" />
      <span className="screen-check__label mono">{check.label}</span>
      <span className="screen-check__detail">{check.detail || "—"}</span>
    </div>
  );
}

function ModulePanel({
  label,
  verdict,
  tone,
  extra,
  rows,
  checks,
  heatmapB64,
}: {
  label: string;
  verdict: string;
  tone: "seal" | "amber" | "danger" | "slate";
  extra?: string;
  rows?: [string, string][];
  checks?: ModuleCheckRow[];
  heatmapB64?: string | null;
}) {
  const [heatOn, setHeatOn] = useState(false);
  return (
    <div className="module-panel">
      <div className="module-panel__head">
        <span className="kicker kicker--plain" style={{ margin: 0 }}>{label}</span>
        <Pill tone={tone}>{verdict}</Pill>
      </div>
      {extra && <div className="stat-note mb-2">{extra}</div>}
      {rows && (
        <div className="screen-fields" style={{ marginBottom: checks?.length ? 10 : 0 }}>
          {rows.map(([k, v]) => (
            <span className="screen-chip mono" key={k}>
              {k}: {v}
            </span>
          ))}
        </div>
      )}
      {checks && checks.length > 0 && (
        <div className="stack-sm">
          {checks.map((c, i) =>
            typeof c === "string" ? null : <ScreenCheckRow key={i} check={c} />,
          )}
        </div>
      )}
      {heatmapB64 && (
        <>
          <button type="button" className="mini-btn mt-3" onClick={() => setHeatOn((v) => !v)}>
            {heatOn ? "Hide ELA heatmap" : "Show ELA heatmap"}
          </button>
          {heatOn && (
            <img
              className="heatmap-img mt-3"
              src={`data:image/png;base64,${heatmapB64}`}
              alt="ELA heatmap"
            />
          )}
        </>
      )}
    </div>
  );
}

function ScreeningDesk() {
  const { me } = useAuth();
  const { toast } = useToast();
  const isSuper = !!me?.is_super_admin;

  const [file, setFile] = useState<File[]>([]);
  const [docType, setDocType] = useState<string>("passport");
  const [checkpoint, setCheckpoint] = useState("");
  const [docNumber, setDocNumber] = useState("");
  const [liveFrame, setLiveFrame] = useState<Blob | null>(null);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<ScreenReport | null>(null);
  const [queue, setQueue] = useState<ScreenQueue | null>(null);
  const [watchlist, setWatchlist] = useState<WatchlistEntry[]>([]);
  const [adjudicateNote, setAdjudicateNote] = useState("");
  const [wlCategory, setWlCategory] = useState("pan");
  const [wlValue, setWlValue] = useState("");
  const [wlReason, setWlReason] = useState("");

  const loadQueue = async () => {
    const res = await getScreenQueue();
    if (res.ok) setQueue(res.data);
  };
  const loadWatchlist = async () => {
    if (!isSuper) return;
    const res = await getWatchlist();
    if (res.ok) setWatchlist(res.data.entries);
  };

  useEffect(() => {
    void loadQueue();
    void loadWatchlist();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSuper]);

  const run = async () => {
    const f = file[0];
    if (!f) {
      toast("Choose a document file to screen.", "warn");
      return;
    }
    setBusy(true);
    const declared: Record<string, string> = {};
    if (docNumber.trim()) declared.document_number = docNumber.trim();
    const res = await screenDocument(f, docType, checkpoint.trim(), declared, liveFrame);
    setBusy(false);
    if (res.ok) {
      setReport(res.data);
      toast(
        `Screen complete — ${res.data.verdict} (risk ${res.data.risk_score}/100).`,
        res.data.verdict === "FLAGGED" ? "error" : res.data.verdict === "REVIEW" ? "warn" : "success",
      );
      void loadQueue();
    } else {
      toast(res.error, "error");
    }
  };

  const adjudicate = async (id: string, decision: string) => {
    const res = await adjudicateScreen(id, decision, adjudicateNote);
    if (res.ok) {
      toast(`Adjudicated ${decision}.`, "success");
      setAdjudicateNote("");
      void loadQueue();
      // mirror the decision onto the visible report card immediately
      void getScreenReport(id).then((r) => {
        if (r.ok) setReport(r.data);
      });
    } else {
      toast(res.error, "error");
    }
  };

  const addWl = async () => {
    if (!wlValue.trim()) {
      toast("Enter an identifier value.", "warn");
      return;
    }
    const res = await addWatchlistEntry(wlCategory, wlValue, wlReason);
    if (res.ok) {
      toast(res.data.already ? "Already on the watchlist." : `Watchlisted ${res.data.mask}.`, "success");
      setWlValue("");
      setWlReason("");
      void loadWatchlist();
    } else {
      toast(res.error, "error");
    }
  };

  const removeWl = async (id: number) => {
    const res = await removeWatchlistEntry(id);
    if (res.ok) {
      toast("Entry removed.", "success");
      void loadWatchlist();
    } else {
      toast(res.error, "error");
    }
  };

  const vm = report && VERDICT_META[report.verdict];

  return (
    <Card title="Identity-document screening desk" icon={<IconLock size={14} />}>
      <div className="row-stretch">
        <Field label="Document type">
          <select className="select" value={docType} onChange={(e) => setDocType(e.target.value)}>
            {SCREEN_DOC_TYPES.map((d) => (
              <option key={d} value={d}>
                {d.replace("_", " ").toUpperCase()}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Checkpoint / office">
          <input
            className="input"
            value={checkpoint}
            placeholder="e.g. IGI Delhi — T2 Arrival"
            onChange={(e) => setCheckpoint(e.target.value)}
          />
        </Field>
        <Field label="Declared number (optional)">
          <input
            className="input"
            value={docNumber}
            placeholder="Number printed on the document"
            onChange={(e) => setDocNumber(e.target.value)}
          />
        </Field>
      </div>

      <Dropzone
        label="Drop the identity document (PDF or photo)"
        sub="Modules — M1 extract (OCR/MRZ) · M2 validate (checksum/format/watchlist) · M3 tamper (ELA/focus) · M4 face (portrait vs holder). Raw bytes and text are never stored."
        accept=".pdf,image/*"
        files={file}
        onFiles={(f) => setFile(f.slice(0, 1))}
        busy={busy}
      />

      <div className="mt-3" style={{ borderTop: "1px dashed var(--line-2)", paddingTop: 12 }}>
        <LiveCapture
          onFrame={(b) => {
            setLiveFrame(b);
            if (b) toast("Holder capture attached — face will be compared.", "success");
            else toast("Holder capture cleared.", "warn");
          }}
        />
      </div>

      {!file.length && !busy && (
        <EmptyNote className="mt-3">
          <span className="big">Nothing staged</span>
          <br />
          Drop a document above to run the screening checks.
        </EmptyNote>
      )}

      {file.length > 0 && (
        <Button
          variant="seal"
          block
          className="mt-3"
          busy={busy}
          onClick={() => void run()}
        >
          <IconBolt size={15} /> {busy ? "Screening…" : "Run screening"}
        </Button>
      )}

      {report && vm && (
        <div className={`screen-report ${vm.pill}`} data-tone={vm.pill}>
          <div className="screen-report__top">
            <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
              <Pill tone={vm.pill}>{report.verdict}</Pill>
              <span className="strong">
                {report.risk_score}
                <span className="stat-note"> /100 risk</span>
              </span>
              <span className="stat-note">confidence {(report.confidence * 100).toFixed(0)}%</span>
              <Pill tone="slate">
                ledger: {report.ledger_status}
              </Pill>
              {report.watchlist_hits && report.watchlist_hits.length > 0 && (
                <Pill tone="danger">watchlist hit</Pill>
              )}
            </div>
            <div className="mono stat-note" style={{ marginTop: 6 }}>
              {report.doc_type.toUpperCase()} · {report.checkpoint || "no checkpoint"} · {report.created_at}
            </div>
          </div>

          <div className="risk-meter mt-3">
            <span className={`risk-meter__fill risk-meter__fill--${vm.pill}`} style={{ width: `${report.risk_score}%` }} />
          </div>

          {report.masked_fields && (
            <div className="screen-fields mt-3">
              {Object.entries(report.masked_fields)
                .filter(([, v]) => v !== null && v !== undefined && v !== false)
                .map(([k, v]) => (
                  <span className="screen-chip mono" key={k}>
                    {k}: {String(v)}
                  </span>
                ))}
            </div>
          )}

          {Array.isArray(report.reasons) && report.reasons.length > 0 && (
            <ul className="screen-reasons mt-3">
              {report.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}

          {report.modules && (
            <div className="screen-modules mt-4">
              <div className="screen-modules__grid">
                <ModulePanel
                  label="M1 Extract"
                  tone={report.modules.extraction.medium === "unknown" ? "slate" : "seal"}
                  verdict={report.modules.extraction.medium === "unknown" ? "UNVERIFIED" : "OK"}
                  rows={[
                    ["medium", report.modules.extraction.medium],
                    ["mrz", report.modules.extraction.mrz ? (report.modules.extraction.mrz.valid ? "valid" : "INVALID") : "not extracted"],
                    ["ocr", report.modules.extraction.ocr?.ran ? "read" : report.modules.extraction.ocr?.reason || "skipped"],
                    ["document-aware", report.modules.extraction.document_aware === null ? "n/a" : report.modules.extraction.document_aware ? "yes" : "no"],
                  ]}
                />
                <ModulePanel
                  label="M2 Validate"
                  tone={MODULE_VERDICT_TONE[report.modules.validation.verdict] || "slate"}
                  verdict={report.modules.validation.verdict}
                  checks={report.modules.validation.checks}
                />
                <ModulePanel
                  label="M3 Tamper"
                  tone={MODULE_VERDICT_TONE[report.modules.tampering.verdict] || "slate"}
                  verdict={report.modules.tampering.verdict}
                  extra={
                    report.modules.tampering.ela
                      ? `ELA Δ ${report.modules.tampering.ela.mean_diff?.toFixed(3) ?? "—"}`
                      : undefined
                  }
                  checks={report.modules.tampering.checks}
                  heatmapB64={report.modules.tampering.heatmap_b64}
                />
                <ModulePanel
                  label="M4 Face"
                  tone={MODULE_VERDICT_TONE[report.modules.face.verdict] || "slate"}
                  verdict={report.modules.face.verdict}
                  extra={`${report.modules.face.method} · ${report.modules.face.match === null ? "no capture" : report.modules.face.match ? "match" : "mismatch"}`}
                  checks={report.modules.face.checks}
                />
              </div>
            </div>
          )}

          {isSuper && (
            <div className="mt-3" style={{ borderTop: "1px dashed var(--line-2)", paddingTop: 12 }}>
              <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                <Button size="sm" variant="seal" onClick={() => void adjudicate(report.id, "CLEARED")}>
                  Clear
                </Button>
                <Button size="sm" variant="danger-ghost" onClick={() => void adjudicate(report.id, "CONFIRMED_FRAUD")}>
                  Confirm fraud
                </Button>
                <Button size="sm" variant="ghost" onClick={() => void adjudicate(report.id, "INCONCLUSIVE")}>
                  Inconclusive
                </Button>
                <input
                  className="input"
                  style={{ maxWidth: 280, flex: 1 }}
                  placeholder="Adjudication note…"
                  value={adjudicateNote}
                  onChange={(e) => setAdjudicateNote(e.target.value)}
                />
              </div>
              {report.adjudication && (
                <p className="stat-note mt-3">
                  Adjudicated <strong>{report.adjudication}</strong> by {report.adjudicator}
                  {report.adjudication_note ? ` — “${report.adjudication_note}”` : ""} at {report.adjudicated_at}.
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {queue && (queue.pending.length > 0 || queue.recent.length > 0) && (
        <div className="mt-4" style={{ borderTop: "1px solid var(--line-2)", paddingTop: 14 }}>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <span className="kicker">Screening queue</span>
            <span className="stat-note">
              {queue.pending.length} pending adjudication{queue.pending.length === 1 ? "" : "s"} · {queue.recent.length} recent
            </span>
          </div>
          <div className="queue-scroll mt-3">
            {(isSuper ? queue.pending : []).map((r) => (
              <div className="queue-row" key={r.id}>
                <div>
                  <span className="mono" style={{ fontSize: 11.5 }}>{r.filename}</span>
                  <br />
                  <span className="stat-note">
                    {r.doc_type.toUpperCase()} · risk {r.risk_score}/100 · {r.created_at}
                  </span>
                </div>
                <div className="row" style={{ gap: 5 }}>
                  <Pill tone={VERDICT_META[r.verdict]?.pill || "slate"}>{r.verdict}</Pill>
                  {isSuper && (
                    <>
                      <Button size="sm" variant="seal" onClick={() => void adjudicate(r.id, "CLEARED")}>Clear</Button>
                      <Button size="sm" variant="danger-ghost" onClick={() => void adjudicate(r.id, "CONFIRMED_FRAUD")}>Fraud</Button>
                    </>
                  )}
                </div>
              </div>
            ))}
            {!isSuper &&
              queue.recent.map((r) => (
                <div className="queue-row" key={r.id}>
                  <div>
                    <span className="mono" style={{ fontSize: 11.5 }}>{r.filename}</span>
                    <br />
                    <span className="stat-note">
                      {r.doc_type.toUpperCase()} · risk {r.risk_score}/100 · {r.created_at}
                    </span>
                  </div>
                  <Pill tone={VERDICT_META[r.verdict]?.pill || "slate"}>{r.verdict}</Pill>
                </div>
              ))}
          </div>
        </div>
      )}

      {isSuper && (
        <div className="mt-4" style={{ borderTop: "1px solid var(--line-2)", paddingTop: 14 }}>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <span className="kicker">Watchlist</span>
            <span className="stat-note">hash-only — raw identifiers never stored</span>
          </div>
          <div className="row-stretch mt-3">
            <Field label="Category">
              <select className="select" value={wlCategory} onChange={(e) => setWlCategory(e.target.value)}>
                {SCREEN_DOC_TYPES.map((d) => (
                  <option key={d} value={d === "driving_licence" ? "driving_licence" : d === "other" ? "other" : d}>
                    {d.replace("_", " ").toUpperCase()}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Identifier value">
              <input className="input" value={wlValue} placeholder="e.g. 2345 1234 5678" onChange={(e) => setWlValue(e.target.value)} />
            </Field>
            <Field label="Reason">
              <input className="input" value={wlReason} placeholder="e.g. Debit blocked in fraud case 23/xx" onChange={(e) => setWlReason(e.target.value)} />
            </Field>
          </div>
          <Button variant="seal" size="sm" className="mt-3" disabled={!wlValue.trim()} onClick={() => void addWl()}>
            <IconPen size={13} /> Add to watchlist
          </Button>

          <div className="queue-scroll mt-3">
            {watchlist.map((e) => (
              <div className="queue-row" key={e.id}>
                <div>
                  <span className="mono" style={{ fontSize: 11.5 }}>{e.mask || e.category}</span>
                  <br />
                  <span className="stat-note">
                    {e.category || "—"} · {e.reason || "no reason"} · by {e.added_by}
                  </span>
                </div>
                <Button size="sm" variant="danger-ghost" onClick={() => void removeWl(e.id)}>
                  Remove
                </Button>
              </div>
            ))}
            {watchlist.length === 0 && <EmptyNote>Watchlist is empty.</EmptyNote>}
          </div>
        </div>
      )}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// Unified directory + ledger card (Identity Directory | Signed Ledger)
// ----------------------------------------------------------------------------

function DirectoryLedgerCard({ payload, onChanged }: { payload: LedgerPayload; onChanged: () => void }) {
  const [tab, setTab] = useState<"dir" | "ledger">("dir");
  return (
    <Card
      title="Directory & ledger"
      icon={<IconUsers size={14} />}
      aside={
        <div className="seg">
          <button
            className={`seg__btn${tab === "dir" ? " seg__btn--active" : ""}`}
            onClick={() => setTab("dir")}
          >
            Identity Directory
          </button>
          <button
            className={`seg__btn${tab === "ledger" ? " seg__btn--active" : ""}`}
            onClick={() => setTab("ledger")}
          >
            Signed Ledger
          </button>
        </div>
      }
    >
      {tab === "dir" ? <IdentityDirectory bare payload={payload} onChanged={onChanged} /> : <LedgerSection bare payload={payload} />}
    </Card>
  );
}

// ----------------------------------------------------------------------------
// The view
// ----------------------------------------------------------------------------

export function AuthorityView() {
  const { signedIn, booting, me } = useAuth();
  const [payload, setPayload] = useState<LedgerPayload | null>(null);
  const [tab, setTab] = useState<"sign" | "broadcast" | "screening" | "records" | "admin">("sign");

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
              Roles are assigned only by an administrator — signing privileges are never self-claimed.
            </p>
          </div>
        </Card>
      </section>
    );
  }

  return (
    <section className="section">
      <div className="section__head rv">
        <div>
          <Kicker>Authority console</Kicker>
          <h2>Sign, broadcast, and steward the record</h2>
        </div>
        <p>
          {me.name} — session active.{" "}
          {me.is_super_admin ? "Full network visibility." : "Your view is scoped to your own signatures."}
        </p>
      </div>

      <AuthorityProfileHeader payload={payload} />

      <div className="auth-tabs rv rv--d2">
        <button
          type="button"
          className={`auth-tab${tab === "sign" ? " auth-tab--active" : ""}`}
          onClick={() => setTab("sign")}
        >
          <IconPen size={14} />
          Sign Media
        </button>
        <button
          type="button"
          className={`auth-tab${tab === "broadcast" ? " auth-tab--active" : ""}`}
          onClick={() => setTab("broadcast")}
        >
          <IconLayers size={14} />
          Issue Broadcast
        </button>
        <button
          type="button"
          className={`auth-tab${tab === "screening" ? " auth-tab--active" : ""}`}
          onClick={() => setTab("screening")}
        >
          <IconCheck size={14} />
          Screening Desk
        </button>
        <button
          type="button"
          className={`auth-tab${tab === "records" ? " auth-tab--active" : ""}`}
          onClick={() => setTab("records")}
        >
          <IconUsers size={14} />
          Ledger & Directory
          {payload ? <span className="auth-tab__badge">{payload.total}</span> : null}
        </button>
        {me.is_super_admin && (
          <button
            type="button"
            className={`auth-tab${tab === "admin" ? " auth-tab--active" : ""}`}
            onClick={() => setTab("admin")}
          >
            <IconKey size={14} />
            Admin Operations
          </button>
        )}
      </div>

      <div className="rv rv--d3">
        {tab === "sign" && (
          me.pending_approval ? (
            <Card title="Awaiting approval" icon={<IconKey size={14} />}>
              <EmptyNote>
                <span className="big">Signing is temporarily blocked</span>
                <br />
                An administrator must assign your post & institution before you can sign files or issue broadcasts.
              </EmptyNote>
            </Card>
          ) : (
            <Card
              title="Cryptographic media signing"
              icon={<IconPen size={14} />}
              aside={<span className="stat-note">ECDSA P-256 · SHA-256</span>}
            >
              <SignPanel bare onSigned={() => void loadLedger()} />
            </Card>
          )
        )}

        {tab === "broadcast" && (
          me.pending_approval ? (
            <Card title="Awaiting approval" icon={<IconKey size={14} />}>
              <EmptyNote>
                <span className="big">Broadcast issuance blocked</span>
                <br />
                An administrator must assign your post & institution before you can sign files or issue broadcasts.
              </EmptyNote>
            </Card>
          ) : (
            <Card
              title="Issue official broadcast bulletin"
              icon={<IconLayers size={14} />}
              aside={<span className="stat-note">Anchored to IPFS & Ledger</span>}
            >
              <BroadcastComposer bare onIssued={() => void loadLedger()} />
            </Card>
          )
        )}

        {tab === "screening" && (
          <ScreeningDesk />
        )}

        {tab === "records" && (
          payload ? (
            <>
              <DirectoryLedgerCard payload={payload} onChanged={() => void loadLedger()} />
              <p className="stat-note mt-3">
                Ledger total: {payload.total} blocks. Regular signers see only their own; administrators see the whole chain.
              </p>
            </>
          ) : (
            <Card title="Provenance ledger" icon={<IconGrid size={14} />}>
              <EmptyNote>Loading the ledger…</EmptyNote>
            </Card>
          )
        )}

        {tab === "admin" && me.is_super_admin && (
          <SuperAdminBar onChanged={() => void loadLedger()} />
        )}
      </div>

      <div style={{ height: 16 }} />
    </section>
  );
}