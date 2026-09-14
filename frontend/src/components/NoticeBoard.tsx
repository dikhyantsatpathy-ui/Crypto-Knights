// ============================================================================
// NoticeBoard — the public bulletin of signed authority broadcasts.
//
// Shows the most recent 24h of notices as a live feed; "view all" opens the
// full archive in a modal. Signed-in authorities can retract their own
// notices; everyone can re-verify a notice's digest (ledger-only check) or
// copy its hash.
// ============================================================================

import { useCallback, useEffect, useState } from "react";
import {
  deleteBroadcast,
  getBroadcasts,
  verifyHash,
  type Broadcast,
  type VerifyResult,
} from "../api";
import { recordMetric, useToast } from "../app/state";
import { copyText, parseUtc, shortHash, timeLabel, urgencyMeta } from "../app/util";
import { Button, Card, EmptyNote, IconClock, IconEye, IconLayers, Modal, Pill } from "./ui";
import { VerdictCard } from "./VerdictCard";

const DAY_MS = 24 * 60 * 60 * 1000;

/** urgency tone -> design Pill tone ("warn" lives as "amber" in the palette). */
const pillTone = (tone: "danger" | "warn" | "seal"): "danger" | "amber" | "seal" =>
  tone === "warn" ? "amber" : tone;

function mediaKind(media_type: string): "image" | "video" | "doc" {
  const t = (media_type || "").toLowerCase();
  if (t.startsWith("video/") || t === "mp4") return "video";
  if (t.startsWith("image/") || ["jpg", "jpeg", "png", "gif", "webp"].includes(t)) return "image";
  return "doc";
}

function NoticeContent({ b }: { b: Broadcast }) {
  if (!b.has_media) return null;
  const kind = mediaKind(b.media_type);
  const url = `/api/broadcasts/${b.file_hash}/media`;
  if (kind === "image") return <img src={url} alt="Notice media attachment" loading="lazy" />;
  if (kind === "video") return <video src={url} controls loop muted />;
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" style={{ display: "block", padding: 10, fontSize: 12 }}>
      ⬇ {b.media_name || "attachment"}
    </a>
  );
}

export function NoticeBoard() {
  const { toast } = useToast();
  const [rows, setRows] = useState<Broadcast[]>([]);
  const [authed, setAuthed] = useState(false);
  const [loading, setLoading] = useState(true);
  const [viewAll, setViewAll] = useState(false);
  const [busyHash, setBusyHash] = useState<string | null>(null);

  // verification of a notice digest (opens its VerdictCard inline)
  const [verifying, setVerifying] = useState<string | null>(null);
  const [verdict, setVerdict] = useState<{ name: string; result: VerifyResult } | null>(null);

  const load = useCallback(async () => {
    const res = await getBroadcasts(50);
    if (res.ok) {
      setRows(res.data.broadcasts);
      setAuthed(res.data.authed);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
    const t = window.setInterval(() => void load(), 60_000);
    return () => window.clearInterval(t);
  }, [load]);

  // ---- actions -------------------------------------------------------------

  const copyHash = async (h: string) => {
    if (await copyText(h)) toast("Digest copied.", "success");
  };

  const verifyDigest = async (b: Broadcast) => {
    setVerifying(b.file_hash);
    setVerdict(null);
    const res = await verifyHash(b.file_hash);
    if (res.ok) {
      recordMetric(res.data.verdict);
      setVerdict({ name: b.file_hash, result: res.data });
    } else {
      toast(res.error, "error");
    }
    setVerifying(null);
  };

  const retract = async (b: Broadcast) => {
    if (!window.confirm(`Retract "${b.title}"? The digest stays in the ledger, marked revoked.`)) return;
    setBusyHash(b.file_hash);
    const res = await deleteBroadcast(b.file_hash);
    if (res.ok) {
      toast("Notice retracted. The record now reads REVOKED.", "success");
      await load();
    } else {
      toast(res.error, "error");
    }
    setBusyHash(null);
  };

  const now = Date.now();
  const recent = rows.filter((b) => now - parseUtc(b.timestamp) < DAY_MS);
  const list = viewAll ? rows : recent.slice(0, 6);

  return (
    <>
      <Card
        title="Live notices"
        icon={<IconLayers size={14} />}
        aside={
          <span className="live-chip">
            <span className="dot" aria-hidden="true" />
            {loading ? "streaming" : `${recent.length} in 24h`}
          </span>
        }
      >
        {loading ? (
          <EmptyNote>Loading the board…</EmptyNote>
        ) : list.length === 0 ? (
          <EmptyNote>
            <span className="big">No issuances in this window</span>
            <br />
            Open the archive below for the full record.
          </EmptyNote>
        ) : (
          <div className="bulletin__feed bulletin__feed--rail" aria-live="polite">
            {list.map((b) => {
              const u = urgencyMeta(b.urgency);
              return (
                <article className="notice-row" key={b.file_hash}>
                  <span className={`notice-row__rail notice-row__rail--${u.tone}`} aria-hidden="true" />
                  <div className="notice-row__body">
                    <div className="notice-row__head">
                      <span className="notice-row__title">{b.title}</span>
                      <Pill tone={pillTone(u.tone)}>{u.label}</Pill>
                      {b.is_mine && <Pill tone="seal">mine</Pill>}
                      <span className="notice-row__time">
                        <IconClock size={11} /> {timeLabel(b.timestamp)}
                      </span>
                    </div>
                    <div className="notice-row__meta">
                      <span>
                        <b>{b.institution || "—"}</b> · {b.signer}
                        {b.designation ? ` · ${b.designation}` : ""}
                      </span>
                      <span>sha256:{shortHash(b.file_hash, 18)}</span>
                    </div>
                    <div className="notice-row__content">{b.content}</div>
                    {b.has_media && (
                      <div className="notice-media">
                        <NoticeContent b={b} />
                      </div>
                    )}
                    <div className="notice-row__actions">
                      <button
                        className="mini-btn"
                        onClick={() => void verifyDigest(b)}
                        disabled={verifying === b.file_hash}
                      >
                        {verifying === b.file_hash ? "Checking…" : "Verify digest"}
                      </button>
                      <button className="mini-btn" onClick={() => void copyHash(b.file_hash)}>
                        Copy hash
                      </button>
                      {b.can_delete && (
                        <button
                          className="mini-btn mini-btn--danger"
                          onClick={() => void retract(b)}
                          disabled={busyHash === b.file_hash}
                        >
                          Retract
                        </button>
                      )}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        )}
        <div className="notice-row__actions" style={{ margin: "10px 12px 0", borderTop: "1px solid var(--line)", paddingTop: 10 }}>
          <Button variant="ghost" size="sm" onClick={() => setViewAll((v) => !v)}>
            <IconEye size={13} /> {viewAll ? "Show recent only" : `View archive (${rows.length})`}
          </Button>
          {!authed && (
            <span className="stat-note" style={{ marginLeft: "auto" }}>
              retraction requires an authority session
            </span>
          )}
        </div>
      </Card>

      {verdict && (
        <div style={{ marginTop: 18 }}>
          <VerdictCard
            result={verdict.result}
            name={verdict.name}
            rawBlob={null}
            onVerifyAnother={() => setVerdict(null)}
          />
        </div>
      )}

      {viewAll && (
        <Modal title={`Full archive · ${rows.length} issuances`} onClose={() => setViewAll(false)}>
          <div className="bulletin__feed" style={{ maxHeight: "55vh" }}>
            {rows.length === 0 && (
              <EmptyNote>
                <span className="big">The archive is empty</span>
                <br />
                Broadcasting is enabled for assigned authorities.
              </EmptyNote>
            )}
            {rows.map((b) => {
              const u = urgencyMeta(b.urgency);
              return (
                <article className="notice-row" key={b.file_hash}>
                  <span className={`notice-row__rail notice-row__rail--${u.tone}`} aria-hidden="true" />
                  <div className="notice-row__body">
                    <div className="notice-row__head">
                      <span className="notice-row__title">{b.title}</span>
                      <Pill tone={pillTone(u.tone)}>{u.label}</Pill>
                      <span className="notice-row__time">
                        <IconClock size={11} /> {timeLabel(b.timestamp)}
                      </span>
                    </div>
                    <div className="notice-row__meta">
                      <span>
                        <b>{b.institution || "—"}</b> · {b.signer}
                        {b.designation ? ` · ${b.designation}` : ""}
                      </span>
                      <span>sha256:{shortHash(b.file_hash, 18)}</span>
                    </div>
                    <div className="notice-row__content">{b.content}</div>
                    {b.has_media && (
                      <div className="notice-media">
                        <NoticeContent b={b} />
                      </div>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        </Modal>
      )}
    </>
  );
}