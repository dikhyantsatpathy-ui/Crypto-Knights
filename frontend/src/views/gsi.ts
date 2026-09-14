// ---------------------------------------------------------------------------
// Google Single Sign-In helper + signed receipt download.
//
// The client ID is injected at build time via VITE_GOOGLE_CLIENT_ID. When no
// env file is provided the deployed public ID (as used by the original page)
// falls back — it is intentionally a client-side, non-secret identifier.
// ---------------------------------------------------------------------------

import { downloadBlob, slugify } from "../app/util";

export const FALLBACK_CLIENT_ID =
  "698365851650-qd2nsi8ahrbv4d67aov3lff4anbco2g1.apps.googleusercontent.com";

/** Serialise a signed broadcast receipt into a downloadable .json file. */
export function downloadReceiptJson(receipt: Record<string, unknown>): void {
  const title = String((receipt as { title?: unknown }).title || "notice");
  const hash = String((receipt as { file_hash?: unknown }).file_hash || "receipt");
  const name = `${slugify(title)}-${hash.slice(0, 8)}.json`;
  const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" });
  downloadBlob(blob, name);
}