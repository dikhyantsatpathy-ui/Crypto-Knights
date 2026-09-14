// ---------------------------------------------------------------------------
// Small shared helpers — formatting, hashing, downloads, clipboard.
// ---------------------------------------------------------------------------

export const shortHash = (h?: string | null, max = 22): string => {
  if (!h) return "—";
  return h.length > max ? `${h.slice(0, 10)}…${h.slice(-8)}` : h;
};

/** Client-side SHA-256 of a Blob/File via WebCrypto (hex string). */
export async function sha256Hex(blob: Blob): Promise<string> {
  const buf = await blob.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Fire a Blob download through a transient <a> element. */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * Parse the backend's "YYYY-MM-DD HH:MM:SS UTC" string as a UTC epoch.
 * (Robust across browsers, unlike new Date() on that loosely-specified format.)
 */
export function parseUtc(t?: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(String(t || ""));
  if (!m) return 0;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

/** "2026-09-14 08:30:00 UTC" -> "2026-09-14 08:30" (UTC, suffix kept by caller). */
export function displayTime(t?: string): string {
  return String(t || "").replace(" UTC", "");
}

/** Shorthand clock like "14:02" or "Sep 14, 14:02" based on age. */
export function timeLabel(t?: string): string {
  const ts = parseUtc(t);
  if (!ts) return "—";
  const d = new Date(ts);
  const hh = String(d.getUTCHours()).padStart(2, "0");
  const mm = String(d.getUTCMinutes()).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  const mon = d.toLocaleString("en", { month: "short", timeZone: "UTC" });
  return `${mon} ${day} · ${hh}:${mm} UTC`;
}

export function initials(name?: string): string {
  return (name || "")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0])
    .join("")
    .toUpperCase();
}

export function formatCount(n: number): string {
  return Math.floor(n).toLocaleString("en-US");
}

/** Emergency urgency -> design token name + label. */
export const URGENCY: Record<string, { tone: "danger" | "warn" | "seal"; label: string }> = {
  CRITICAL: { tone: "danger", label: "CRITICAL" },
  HIGH: { tone: "warn", label: "HIGH" },
  ADVISORY: { tone: "seal", label: "ADVISORY" },
};

export function urgencyMeta(urgency?: string): { tone: "danger" | "warn" | "seal"; label: string } {
  const key = (urgency || "HIGH").toUpperCase();
  return URGENCY[key] || URGENCY.HIGH;
}

/** Consistent slug used for downloaded receipt filenames. */
export function slugify(text: string): string {
  return (
    text
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "") || "notice"
  );
}

/** Human "N days ago" style label from a UTC timestamp string. */
export function ageLabel(t?: string): string {
  const ts = parseUtc(t);
  if (!ts) return "—";
  const mins = Math.floor((Date.now() - ts) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}