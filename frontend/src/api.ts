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

export function getLedger(limit?: number, offset?: number) {
  const params = new URLSearchParams();
  if (limit != null) params.set("limit", String(limit));
  if (offset) params.set("offset", String(offset));
  const q = params.toString();
  return request<LedgerPayload>(`/api/ledger${q ? `?${q}` : ""}`);
}

export function getAnalytics() {
  return request<AnalyticsPayload>("/api/analytics");
}

export interface AnalyticsSummary {
  analytics: AnalyticsPayload;
  usage: DetectionUsage;
  cached: boolean;
}

/** One round trip for the whole dashboard (tallies + latency + quota). */
export function getAnalyticsSummary() {
  return request<AnalyticsSummary>("/api/analytics/summary");
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
//
// Module contract (1:1 with the problem statement):
//   M1 extraction  OCR/MRZ/declared field extraction
//   M2 validation  format/MRZ/expiry + watchlist
//   M3 tampering   ELA/spectral/noise/metadata + AI-generation cues
//   M4 face        document portrait vs live holder capture
// ----------------------------------------------------------------------------

export type ScreenVerdict = "CLEAR" | "REVIEW" | "FLAGGED";

export interface ScreenCheck {
  label: string;
  ok: boolean | null;
  detail: string;
}

export interface ScreenMrz {
  format?: string;
  valid?: boolean;
  document_ck?: boolean | null;
  dob_ck?: boolean | null;
  expiry_ck?: boolean | null;
  composite_ck?: boolean | null;
  passport?: string;
}

export interface ScreenModuleExtraction {
  medium: "pdf" | "image" | "unknown";
  mrz?: ScreenMrz | null;
  ocr?: { ran: boolean; reason?: string };
  document_aware?: boolean | null;
}

export interface ScreenModuleValidation {
  verdict: string;
  checks: ScreenCheck[];
}

export interface ScreenSpectralAnalysis {
  papr?: number;
  high_freq_ratio?: number;
  spectral_anomaly?: boolean;
  status?: string;
  detail?: string;
}

export interface ScreenNoiseConsistency {
  portrait_noise_var?: number;
  substrate_noise_var?: number;
  noise_ratio?: number;
  consistent?: boolean;
  status?: string;
  detail?: string;
}

export interface ScreenImageQA {
  width?: number;
  height?: number;
  megapixels?: number;
  blur_est?: number;
  blurry?: boolean;
  dark_frac?: number;
  bright_frac?: number;
  overexposed?: boolean;
  underexposed?: boolean;
}

export interface ScreenModuleTampering {
  verdict: string;
  checks: ScreenCheck[];
  ela?: {
    status?: string;
    damage_ratio?: number;
    mean_diff?: number;
    latency_ms?: number;
  } | null;
  spectral?: ScreenSpectralAnalysis | null;
  noise_consistency?: ScreenNoiseConsistency | null;
  qa?: ScreenImageQA | null;
  heatmap_b64?: string | null;
  overlay_grid?: number[][] | null;
  roi?: ForensicsROI[];
  liveness?: Array<{ signal?: string; level?: string; note?: string }>;
}

export interface ScreenModuleFace {
  verdict: string;
  match: boolean | null;
  score: number;
  method: string;
  detail: string;
  checks: ScreenCheck[];
}

export interface ForensicsROI {
  label: string;
  x: number;
  y: number;
  w: number;
  h: number;
  confidence: number;
}

export interface ScreenModules {
  extraction: ScreenModuleExtraction;
  validation: ScreenModuleValidation;
  tampering: ScreenModuleTampering;
  face: ScreenModuleFace;
}

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
  modules?: ScreenModules;
  travel_validity?: ScreenTravelValidity | null;
  syndicate_alerts?: Array<{
    level: string;
    type: string;
    title: string;
    detail: string;
    checkpoint: string;
  }>;
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
  "pan",
  "passport",
  "visa",
  "driving_licence",
  "voter_id",
  "other",
] as const;

export type ScreenDocType = (typeof SCREEN_DOC_TYPES)[number];

/**
 * Backend-aligned document labels. These are the document families the
 * screening pipeline can extract and validate end to end. Aadhaar is
 * intentionally absent: the backend no longer accepts it.
 */
export const SCREEN_DOC_LABELS: Record<ScreenDocType, string> = {
  pan: "PAN",
  passport: "PASSPORT",
  visa: "VISA",
  driving_licence: "DRIVING LICENCE",
  voter_id: "VOTER ID",
  other: "OTHER",
};

export const SCREEN_DOC_NUMBER_PLACEHOLDERS: Record<ScreenDocType, string> = {
  pan: "e.g. ABCDP2234A",
  passport: "e.g. K1234567",
  visa: "e.g. V1234567",
  driving_licence: "e.g. KA0120201234567",
  voter_id: "e.g. ABC1234567",
  other: "Number printed on the document",
};

/**
 * Watchlist categories are the identifier families the backend actually
 * hashes and compares during screening. The category is metadata; matching
 * is always by SHA-256 digest.
 */
export const SCREEN_WATCHLIST_CATEGORIES = [
  "pan",
  "passport",
  "visa",
  "driving_licence",
  "voter_id",
  "phone",
] as const;

export type ScreenWatchlistCategory =
  (typeof SCREEN_WATCHLIST_CATEGORIES)[number];

export const SCREEN_WATCHLIST_LABELS: Record<ScreenWatchlistCategory, string> = {
  pan: "PAN",
  passport: "PASSPORT",
  visa: "VISA",
  driving_licence: "DRIVING LICENCE",
  voter_id: "VOTER ID",
  phone: "PHONE",
};

export const SCREEN_WATCHLIST_PLACEHOLDERS: Record<
  ScreenWatchlistCategory,
  string
> = {
  pan: "e.g. ABCDP2234A",
  passport: "e.g. K1234567",
  visa: "e.g. V1234567",
  driving_licence: "e.g. KA0120201234567",
  voter_id: "e.g. ABC1234567",
  phone: "e.g. 9876543210",
};

export interface ScreenTravelValidity {
  days_to_expiry: number | null;
  six_month_rule: boolean | null;
  age_at_crossing: number | null;
  status: "VALID" | "EXPIRING_SOON" | "EXPIRED" | "UNKNOWN";
  detail: string;
}

/** Run a screening pass on an uploaded identity document (officer only). */
export function screenDocument(
  file: File,
  docType: string,
  checkpoint: string,
  declared?: Record<string, string>,
  liveFrame?: Blob | null,
) {
  const fd = form({ doc_type: docType, checkpoint });
  fd.append("file", file, file.name);
  if (declared && Object.keys(declared).length > 0) {
    fd.append("declared", JSON.stringify(declared));
  }
  if (liveFrame) fd.append("live_frame", liveFrame, "holder_live.jpg");
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

export function getSyndicateAlerts(checkpoint?: string) {
  const url = checkpoint ? `/api/screen/syndicate-alerts?checkpoint=${encodeURIComponent(checkpoint)}` : "/api/screen/syndicate-alerts";
  return request<{
    checkpoint_filter: string;
    total_screened_sample: number;
    alerts: Array<{
      level: string;
      type: string;
      title: string;
      detail: string;
      checkpoint: string;
    }>;
    active_alerts_count: number;
  }>(url);
}

export function getDossierUrl(reportId: string, autoPrint: boolean = false): string {
  return `/api/screen/dossier/${encodeURIComponent(reportId)}${autoPrint ? "?print=true" : ""}`;
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