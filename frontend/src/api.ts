// ============================================================================
// API layer — typed wrapper around the FastAPI backend.
//
// Every request carries the HttpOnly session cookie (credentials: "include").
// Non-2xx responses become { ok: false, error } so callers never repeat
// try/catch. Endpoints that stream a downloadable file (Content-Disposition:
// attachment) are detected so the raw body is never pre-consumed.
// ============================================================================

export type VerdictKind = "AUTHENTIC" | "PROVEN_FAKE" | "REVOKED" | "UNSIGNED";

export interface SignerSummary {
  name?: string;
  institution?: string;
  designation?: string;
  signature_guidance?: string;
}

export interface AiDetection {
  ran: boolean;
  ai_suspected: boolean;
  ai_score: number;
  model: string | null;
  provider: string | null;
  explanation: string;
  latency_ms: number;
}

export interface LedgerReceipt {
  found: boolean;
  hash?: string;
  filename?: string;
  signature?: string;
  signed_at?: string;
  merkle_root?: string | null;
  ipfs_cid?: string | null;
  tx_hash?: string | null;
  retracted?: boolean;
  revoked?: boolean;
  signer_name?: string;
  signer_institution?: string | null;
  signer_designation?: string | null;
  issuer_pubkey?: string | null;
  blockchain_explorer?: string | null;
}

export interface VerifyResult {
  verdict: VerdictKind;
  message: string;
  hash: string;
  filename: string;
  signer?: SignerSummary;
  tx_hash: string | null;
  retracted?: boolean;
  headline: string;
  guidance: string;
  forensic_leaning?: string;
  forensic_tool?: string | null;
  forensic_confidence?: number;
  ai_detection?: AiDetection;
  ai_score?: number;
  ai_model?: string | null;
  ai_provider?: string | null;
  ai_explanation?: string;
  ai_suspected?: boolean;
  edited_suspected?: boolean;
  likely_forged?: boolean;
  forgery_warned?: boolean;
  reasons?: string[];
  ledger?: LedgerReceipt;
  blockchain_explorer?: string | null;
}

export interface Broadcast {
  title: string;
  urgency: string;
  content: string;
  signer: string;
  institution: string;
  designation: string;
  timestamp: string;
  file_hash: string;
  signature: string;
  ipfs_cid: string;
  media_type: string;
  media_name: string;
  has_media: boolean;
  is_mine: boolean;
  can_delete: boolean;
}

export interface Me {
  status: string;
  admin: string;
  name: string;
  designation: string | null;
  institution: string | null;
  pending_approval: boolean;
  is_super_admin: boolean;
}

export interface Signer {
  email: string;
  name: string;
  designation: string;
  institution: string;
  is_revoked: boolean;
  has_pin: boolean;
  registered_at?: string;
  revoked_at?: string;
}

export interface LedgerBlock {
  id: number;
  signer_email: string;
  signer_name: string;
  signer_institution: string;
  signer_designation: string;
  filename: string;
  file_hash: string;
  sig_hex: string;
  timestamp: string;
  ipfs_cid: string;
  tx_hash: string | null;
  merkle_root: string | null;
  is_revoked: boolean;
  crypto_mode: string;
  is_compromised: boolean;
}

export interface LedgerPayload {
  signers: Record<string, Signer>;
  blocks: LedgerBlock[];
  total: number;
  is_super_admin: boolean;
}

export interface Stats {
  signed_docs: number;
  trusted_issuers: number;
}

export interface AnalyticsPayload {
  stats: Record<VerdictKind, number>;
  latency: { avg_ms: number; min_ms: number; max_ms: number; samples: number } | null;
  providers: Record<string, number>;
}

export interface DetectionUsage {
  provider: string;
  model: string;
  period_day: string;
  period_month: string;
  ops_used_today: number;
  ops_used_month: number;
  limit_today: number;
  limit_month: number;
  remaining_today: number;
  remaining_month: number;
}

export interface SignTextResult {
  receipt: Record<string, unknown>;
  ipfs_cid: string;
  ledger_persisted: boolean;
  ledger_hash: string;
}

// ----------------------------------------------------------------------------
// Fetch wrapper
// ----------------------------------------------------------------------------

export type ApiResult<T> = { ok: true; data: T; response: Response } | { ok: false; error: string };

async function request<T>(url: string, init?: RequestInit): Promise<ApiResult<T>> {
  try {
    const response = await fetch(url, { ...init, credentials: "include" });
    if (response.status === 429) throw new Error("Rate limit exceeded. Please wait.");

    // Attachment responses (signed files) must be read as a blob by the caller
    // — parsing the JSON first would consume the body.
    const isAttachment = (response.headers.get("content-disposition") || "").includes("attachment");
    let data: unknown = null;
    if (!isAttachment && (response.headers.get("content-type") || "").includes("application/json")) {
      data = await response.json();
    }
    if (!response.ok) {
      throw new Error((data as { detail?: string } | null)?.detail || `Error ${response.status}`);
    }
    return { ok: true, data: data as T, response };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "Network error" };
  }
}

function form(fields: Record<string, string | Blob | File | undefined | null>): FormData {
  const fd = new FormData();
  for (const [key, value] of Object.entries(fields)) {
    if (value != null) fd.append(key, value);
  }
  return fd;
}

// ----------------------------------------------------------------------------
// Public endpoints
// ----------------------------------------------------------------------------

export function getStats() {
  return request<Stats>("/api/stats");
}

export function verifyFile(file: Blob, filename: string, clientHash?: string) {
  const fd = new FormData();
  // Passing the name with the blob preserves it through .slice() and lets the
  // backend name the artifact correctly (media previews + forensics).
  fd.append("file", file, filename);
  if (clientHash) fd.append("client_hash", clientHash);
  return request<VerifyResult>("/api/verify", { method: "POST", body: fd });
}

export function verifyText(rawText: string) {
  const fd = form({ raw_text: rawText });
  return request<VerifyResult>("/api/verify", { method: "POST", body: fd });
}

/** Ledger-only check: re-verify a digest with no uploaded content. */
export function verifyHash(hash: string) {
  const fd = form({ client_hash: hash });
  return request<VerifyResult>("/api/verify", { method: "POST", body: fd });
}

export function getBroadcasts(limit = 200) {
  return request<{ broadcasts: Broadcast[]; authed: boolean }>(`/api/broadcasts?limit=${limit}`);
}

export function deleteBroadcast(fileHash: string) {
  return request<{ status: string }>("/api/broadcasts/delete", {
    method: "POST",
    body: form({ file_hash: fileHash }),
  });
}

// ----------------------------------------------------------------------------
// Auth endpoints
// ----------------------------------------------------------------------------

export function getMe() {
  return request<Me>("/api/admin/me");
}

export function googleLogin(credential: string) {
  return request<{ status: string }>("/api/admin/login", {
    method: "POST",
    body: form({ credential }),
  });
}

export function logout() {
  return request<{ status: string }>("/api/admin/logout", { method: "POST" });
}

export function assignRole(targetEmail: string, designation: string, institution: string) {
  return request<{ status: string }>("/api/admin/assign_role", {
    method: "POST",
    body: form({ target_email: targetEmail, designation, institution }),
  });
}

// ----------------------------------------------------------------------------
// Signing endpoints
// ----------------------------------------------------------------------------

export function signFiles(files: Blob[]) {
  const fd = new FormData();
  for (const f of files) fd.append("files", f);
  return request<unknown>("/api/sign", { method: "POST", body: fd });
}

export function signChunk(sessionId: string, index: number, total: number, filename: string, chunk: Blob) {
  const fd = form({ session_id: sessionId, chunk_index: String(index), total_chunks: String(total), filename, chunk });
  return request<{ ok: boolean }>("/api/sign_chunk", { method: "POST", body: fd });
}

export function signComplete(sessionId: string) {
  return request<unknown>("/api/sign_complete", {
    method: "POST",
    body: form({ session_id: sessionId }),
  });
}

export function signTextNotice(
  title: string,
  urgency: string,
  message: string,
  media?: File,
) {
  const fd = form({ broadcast_title: title, urgency_level: urgency, message });
  if (media) fd.append("media", media, media.name);
  return request<SignTextResult>("/api/sign_text", { method: "POST", body: fd });
}

export function setPin(pin: string) {
  return request<{ status: string }>("/api/set_pin", { method: "POST", body: form({ pin }) });
}

export function revokeIdentity(targetEmail: string, pin?: string) {
  return request<{ status: string }>("/api/revoke", {
    method: "POST",
    body: form({ target_email: targetEmail, pin }),
  });
}

export function reinstateIdentity(targetEmail: string, pin: string) {
  return request<{ status: string }>("/api/reinstate", {
    method: "POST",
    body: form({ target_email: targetEmail, pin }),
  });
}

// ----------------------------------------------------------------------------
// Ledger / network / analytics / system
// ----------------------------------------------------------------------------

export function getLedger() {
  return request<LedgerPayload>("/api/ledger");
}

export function getAnalytics() {
  return request<AnalyticsPayload>("/api/analytics");
}

export function getDetectionUsage() {
  return request<DetectionUsage>("/api/detection/usage");
}

export function syncBlockchain() {
  return request<{ status: string; tx_hash?: string; anchored_blocks_count?: number; merkle_root?: string }>(
    "/api/blockchain/sync",
    { method: "POST" },
  );
}

export function rollbackLedger(targetTimestamp: string) {
  return request<{ status: string }>("/api/rollback", {
    method: "POST",
    body: form({ target_timestamp: targetTimestamp }),
  });
}

// ----------------------------------------------------------------------------
// MHA screening desk (SIH26188 — AI-Based Fake Identity & Document Screening)
// ----------------------------------------------------------------------------

export type ScreenVerdict = "CLEAR" | "REVIEW" | "FLAGGED";

export interface ScreenReport {
  id: string;
  filename: string;
  doc_type: string;
  checkpoint: string;
  verdict: ScreenVerdict;
  risk_score: number;
  confidence: number;
  ledger_status: string;
  screener?: string | null;
  created_at: string;
  adjudication?: string | null;
  adjudicator?: string | null;
  adjudication_note?: string | null;
  adjudicated_at?: string | null;
  masked_fields: Record<string, string | boolean | null>;
  signals?: string[];
  ai_detection?: AiDetection | null;
  file_hash?: string;
  watchlist_hits?: { field: string; mask: string }[];
  reasons?: string[];
  latency_ms?: number;
  declared_count?: number;
}

export interface ScreenQueue {
  pending: ScreenReport[];
  recent: ScreenReport[];
}

export interface WatchlistEntry {
  id: number;
  category: string | null;
  mask: string | null;
  reason: string | null;
  added_by: string;
  created_at: string;
}

export const SCREEN_DOC_TYPES = [
  "aadhaar",
  "pan",
  "passport",
  "driving_licence",
  "voter_id",
  "other",
] as const;

/** Run a screening pass on an uploaded identity document (officer only). */
export function screenDocument(
  file: File,
  docType: string,
  checkpoint: string,
  declared?: Record<string, string>,
) {
  const fd = form({ doc_type: docType, checkpoint });
  fd.append("file", file, file.name);
  if (declared && Object.keys(declared).length > 0) {
    fd.append("declared", JSON.stringify(declared));
  }
  return request<ScreenReport>("/api/screen", { method: "POST", body: fd });
}

export function getScreenQueue() {
  return request<ScreenQueue>("/api/screen/queue");
}

export function getScreenReport(reportId: string) {
  return request<ScreenReport>(
    `/api/screen/reports/${encodeURIComponent(reportId)}`,
  );
}

export function adjudicateScreen(reportId: string, decision: string, note?: string) {
  return request<{ ok: boolean }>(
    `/api/screen/reports/${encodeURIComponent(reportId)}/adjudicate`,
    { method: "POST", body: form({ decision, note: note || "" }) },
  );
}

export function getWatchlist() {
  return request<{ entries: WatchlistEntry[] }>("/api/screen/watchlist");
}

export function addWatchlistEntry(category: string, value: string, reason?: string) {
  return request<{ ok: boolean; id?: number; mask?: string; already?: boolean }>(
    "/api/screen/watchlist/add",
    { method: "POST", body: form({ category, value, reason: reason || "" }) },
  );
}

export function removeWatchlistEntry(entryId: number) {
  return request<{ ok: boolean }>("/api/screen/watchlist/remove", {
    method: "POST",
    body: form({ entry_id: String(entryId) }),
  });
}

// ----------------------------------------------------------------------------
// Identity verification suite — Aadhaar Secure QR / PAN / DL & RC / EPIC /
// Passport MRZ + mock NSDL-Parivahan-Vahan-ECI registries + visual forensics.
// ----------------------------------------------------------------------------

export interface IdentityCheck {
  label: string;
  ok: boolean | string | null;
  detail: string;
}

export interface IdentityRegistry {
  registry: string;
  label: string;
  masked_number: string;
  registered: boolean;
  status?: string | null;
  holder_match?: boolean | null;
  holder_label?: string;
  reason?: string;
  sample_data: boolean;
  lost_or_stolen?: boolean | null;
}

export interface ForensicsELA {
  engine: string;
  quality: number;
  damage_ratio: number;
  mean_diff: number;
  status: string;
  heatmap_b64: string;
  overlay_grid: number[][];
  latency_ms: number;
}

export interface ForensicsQA {
  width?: number;
  height?: number;
  megapixels?: number;
  blur_est?: number;
  blurry?: boolean;
  overexposed?: boolean;
  underexposed?: boolean;
  dark_frac?: number;
  bright_frac?: number;
  error?: string;
}

export interface ForensicsROI {
  label: string;
  x: number;
  y: number;
  w: number;
  h: number;
  confidence: number;
}

export interface LivenessSignal {
  signal: string;
  level: "info" | "warn" | "danger";
  note: string;
}

export interface IdentityForensics {
  ela?: ForensicsELA | null;
  qa?: ForensicsQA | null;
  roi?: ForensicsROI[];
  liveness?: LivenessSignal[];
  error?: string;
}

export interface QrCrypto {
  status: string;
  note: string;
}

export interface IdentityReport {
  doc_type: string;
  filename: string;
  masked_fields: Record<string, string | null>;
  checks: IdentityCheck[];
  registry?: IdentityRegistry | null;
  forensics?: IdentityForensics | null;
  verdict: "VERIFIED" | "REVIEW" | "UNVERIFIED";
  confidence: number;
  signals?: string[];
  ocr?: { ran: boolean; reason?: string };
  qr?: { aadhaar: string; name_matched: boolean; photo_sha256: string; crypto: QrCrypto };
  created_at: string;
  latency_ms?: number;
  screener?: string;
}

export interface IdentityMeta {
  version: string;
  ocr: { available: boolean; engine: string };
  qr_decoder: string;
  aadhaar_crypto: string;
  registries: { key: string; label: string; mock: boolean; sample_rows: number }[];
}

export const IDENTITY_DOC_TYPES = [
  "aadhaar",
  "pan",
  "driving_licence",
  "rc",
  "voter_id",
  "passport",
] as const;

/** Run one identity-verification pass on a document photo (officer only). */
export function verifyIdentity(
  file: File | undefined,
  docType: string,
  declared: Record<string, string>,
  mrzText: string,
  qrPayload: string,
) {
  const fd = form({
    doc_type: docType,
    declared: JSON.stringify(declared),
    mrz_text: mrzText,
    qr_payload: qrPayload,
  });
  if (file) fd.append("file", file, file.name);
  return request<IdentityReport>("/api/identity/verify", { method: "POST", body: fd });
}

/** Standalone cross-reference against a (mock) government registry. */
export function identityRegistryCheck(registry: string, number: string, name = "") {
  return request<IdentityRegistry>("/api/identity/registry-check", {
    method: "POST",
    body: form({ registry, number, name }),
  });
}

/** Capabilities this deploy actually has (QR decoder, OCR, signature key). */
export function getIdentityMeta() {
  return request<IdentityMeta>("/api/identity/meta");
}

export interface LivenessResult {
  verdict: "LIVE" | "SUSPECT" | "SPOOF" | "FAILED";
  liveness_passed: boolean;
  confidence: number;
  challenge: string;
  checks: { label: string; ok: boolean | null; detail: string }[];
  signals: string[];
  motion_score?: number;
  latency_ms?: number;
}

/** Interactive webcam liveness check with anti-virtual-camera detection. */
export function verifyWebcamLiveness(
  frames: Blob[],
  challenge = "blink",
  clientMeta: Record<string, any> = {},
) {
  const fd = new FormData();
  frames.forEach((f, i) => {
    fd.append("frames", f, `frame_${i}.jpg`);
  });
  fd.append("challenge", challenge);
  fd.append("client_meta", JSON.stringify(clientMeta));
  return request<LivenessResult>("/api/identity/liveness/verify", {
    method: "POST",
    body: fd,
  });
}

/** Standalone Error Level Analysis and YOLO ROI bounding box extraction. */
export function getForensicsEla(file: File, quality = 92) {
  const fd = new FormData();
  fd.append("file", file, file.name);
  fd.append("quality", String(quality));
  return request<{ ela: ForensicsELA; roi: ForensicsROI[]; qa: ForensicsQA }>(
    "/api/identity/forensics/ela",
    { method: "POST", body: fd }
  );
}

// ----------------------------------------------------------------------------
// Large-file verification
//
// Vercel rejects request bodies over ~4.2MB, so a file larger than ~3.5MB is
// sampled: the browser sends the first 2MB plus the FULL-file SHA-256. The
// backend checks the digest against the ledger and runs forensics on the
// sample. Same trust model as a full upload — one round-trip, no chunking.
// ----------------------------------------------------------------------------

export const LARGE_FILE_SAMPLE_BYTES = 2 * 1024 * 1024;