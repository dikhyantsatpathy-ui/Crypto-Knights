// ============================================================================
// Project guide knowledge base (offline, curated).
// The chatbot answers purely from this file — no network, no LLM — so it works
// in a judge's offline demo and every answer is a line the team can vouch for.
// ============================================================================

export type BotMessage = { role: "user" | "bot"; text: string };

type Entry = { id: string; tags: string[]; q: string; a: string; s?: string };

const ENTRIES: Entry[] = [
  {
    id: "what",
    tags: ["what", "is", "nocap", "project", "veri_source", "about", "sih", "genesis"],
    q: "What is this project?",
    a: "*nocap (Veri_source)* is a provenance ledger for official documents. **Institutions sign files, messages and identity documents with a real key; anyone can drop a file back in and get a one-second verdict**: AUTHENTIC, proven fake, revoked, or unsigned. It layers a SHA-256 sieve, an ECDSA signature vault, an append-only ledger and an L2 blockchain anchor on top.",
    s: "README.md + app main",
  },
  {
    id: "how",
    tags: ["how", "works", "flow", "sign", "verify", "chain"],
    q: "How does the trust chain actually work?",
    a: "Three layers: **01 the digest** — every file becomes a SHA-256 fingerprint (the file itself is never stored); **02 the signature** — an approved institution binds its key to that digest, signed server-side in a vault; **03 the chain** — each signature is appended to the ledger, retractions only mark it revoked, and a Merkle root is anchored to the L2 chain as `NOCAP_ROOT:<root>`.",
    s: "Public page 'Three layers, one trust chain'",
  },
  {
    id: "verify",
    tags: ["verify", "check", "verdict", "auth", "authentic", "genuine", "real"],
    q: "How do I verify a file?",
    a: "On the *Verify* tab: drop a file, a zip, or pasted text. The app re-derives the SHA-256, looks it up in the ledger, checks the authority's ECDSA signature, runs a forensic + AI scan, then shows the verdict card: `AUTHENTIC`, `PROVEN_FAKE`, `REVOKED`, or `UNSIGNED`, with who signed it and when.",
    s: "VerifyPanel + api.ts",
  },
  {
    id: "sign",
    tags: ["sign", "anchor", "authority", "official", "publish", "broadcast"],
    q: "How do officials sign and publish?",
    a: "In *Authority*: upload a file and press **Sign & anchor**. The server SHA-256s it, signs with your vault key (ECDSA), injects a forensic trap, writes a ledger block and pins a receipt. **Issue signed broadcast** does the same for emergency text and posts it to the public notice board.",
    s: "AuthorityView.tsx",
  },
  {
    id: "revoke",
    tags: ["revoke", "kill", "switch", "pin", "cascade", "stolen", "compromised", "cancel"],
    q: "What is the kill switch?",
    a: "`Set PIN` registers a 5-digit emergency code. `Revoke access` then **permanently retires a signing key — and every ledger block that key ever signed turns into REVOKED across the network** in one step. `Reinstate` (administrator, PIN required) is the only way back, so a mis-click can't undo a whole batch.",
    s: "AuthorityView + main.py kill-switch route",
  },
  {
    id: "screen",
    tags: ["screen", "screening", "mha", "document", "id", "aadhaar", "voter", "verify-document"],
    q: "What does the document screening desk do?",
    a: "Officers upload an identity photo/PDF (Aadhaar, passport, voter ID) plus declared fields. The pipeline **extracts fields, validates checksums (Verhoeff for Aadhaar, ICAO 9303 MRZ for passports), cross-checks the ledger and watchlist, and runs the AI detector** — returning CLEAR / REVIEW / FLAGGED with one explainable reason per risk point. Only masked identifiers are stored.",
    s: "MHA_SCREENING.md + screening.py",
  },
  {
    id: "watchlist",
    tags: ["watchlist", "blacklist", "flagged", "administrator", "privacy", "bloom"],
    q: "How does the watchlist work without storing raw numbers?",
    a: "Administrators add a *hashed* identifier + a reason phrase. Screening compares identifiers **before hashing**, so the raw Aadhaar/number never touches the database — zero plaintext storage. If a watchlisted number shows up again, it glows red as a risk.",
    s: "MHA_SCREENING.md watchlist section",
  },
  {
    id: "ai",
    tags: ["ai", "detector", "sightengine", "heuristic", "onnx", "deepfake", "genai"],
    q: "What is the AI detector?",
    a: "The app checks images for AI generation with **interchangeable backends**: the free offline *heuristic* (metadata self-tags + pixel noise scan), the cloud *Sightengine* model, or a *self-hosted ONNX* vision classifier. Every path returns the same verdict shape and a plain-language explanation; a scanned document is detected first and routed past the photo-focused AI models.",
    s: "inlined AI-detection section of app/main.py",
  },
  {
    id: "ledger",
    tags: ["ledger", "blockchain", "anchor", "l2", "merkle", "root", "sync", "tamper"],
    q: "Where does the blockchain come in?",
    a: "Every signed file creates a ledger block (hash-chained, signed, timestamped). **Batch anchor (L2 sync)** folds all un-anchored blocks into one Merkle tree and broadcasts `NOCAP_ROOT:<root>` on-chain. The on-chain root is the audit-trail backstop: an offline rollback is possible but visibly breaks the chain — no silent abuse.",
    s: "main.py blockchain/sync route",
  },
  {
    id: "analytics",
    tags: ["analytics", "stats", "metrics", "counts", "dashboard", "fraud", "public"],
    q: "What is on the Analytics page?",
    a: "Aggregate-only public metrics: verdict totals (authentic / fake / revoked / unsigned), screening area stats, fraud reports, and today's AI-detector usage (e.g. 470/500) — **counters only, no personal rows exposed**.",
    s: "AnalyticsView.tsx",
  },
  {
    id: "privacy",
    tags: ["privacy", "zero", "storage", "pii", "hash", "mask", "sensitive", "data"],
    q: "Is this privacy-safe / zero-storage?",
    a: "Yes by design: **files never leave your browser** on verify (only the digest is sent); the ledger stores hashes and *masked* identifiers, never raw content or naked numbers; receipt JSONs are how you keep your own copy. The footer literally reads `ZERO-STORAGE VERIFICATION`.",
    s: "VerifyPanel + screening mute/mask",
  },
  {
    id: "rollback",
    tags: ["rollback", "drill", "disaster", "recovery", "reset", "clean"],
    q: "What is the rollback ledger used for?",
    a: "An administrator disaster-recovery drill: pick a UTC boundary and every newer record is deleted. It is deliberate, needs the admin role, and because it happens under a watchful on-chain root it can't be used to secretly clean evidence.",
    s: "AuthorityView rollback modal",
  },
  {
    id: "roles",
    tags: ["roles", "access", "officer", "administrator", "approve", "authorisation", "authz"],
    q: "Who can do what?",
    a: "Anyone can verify and read analytics. **Approved officers** (Google SSO + admin-assigned post/institution) can sign, broadcast, and screen documents. **Administrators** adjudicate screening verdicts, manage the watchlist, assign roles, and run ledger sync/rollback. Titles are granted, never self-claimed.",
    s: "main.py access model + MHA_SCREENING.md",
  },
  {
    id: "fake",
    tags: ["fake", "fake", "forgery", "fraud", "report", "scam", "proven_fake"],
    q: "What happens when a file comes back fake?",
    a: "The card shows `PROVEN_FAKE` and offers **Report this fake** — logging that exact copy + hash as a community fraud report so the network learns it circulated. A tampered file keeps its signed history but is marked non-authentic.",
    s: "VerdictCard.tsx",
  },
  {
    id: "compare",
    tags: ["compare", "copy", "versions", "match", "zip", "batch"],
    q: "Can I compare two copies of a file?",
    a: "Yes — the **Compare a copy** control takes a second SHA-256 (or a second file) and instantly says match or mismatch. Great for spotting a subtly altered 'copy' of a real document. Zip batches verify each member individually.",
    s: "VerdictCard compare control",
  },
  {
    id: "tech",
    tags: ["tech", "stack", "fastapi", "react", "vite", "sqlite", "vercel", "provider"],
    q: "What is the tech stack?",
    a: "**Backend**: FastAPI + SQLAlchemy/SQLite + cryptography (ECDSA/KMS-style signer), Sightengine/web3 for anchoring, bundled in two files (`app/main.py`, `app/screening.py`). **Frontend**: React + TypeScript + Vite, built into a single self-contained `app/static/index.html`. Deployable on Vercel via `api/index.py`.",
    s: "requirements.txt + package.json",
  },
  {
    id: "run",
    tags: ["run", "start", "install", "setup", "local", "port", "8000"],
    q: "How do I run it locally?",
    a: "Double-click **START.bat** (Windows): it installs Python + npm deps on first run, rebuilds the frontend, starts `uvicorn` on port 8000 and opens the browser. Manual: `python -m pip install -r requirements.txt`, `npm install && npm run build` in `frontend/`, then `uvicorn main:app --port 8000` from `app/`.",
    s: "START.bat + HOW_TO_HOST.md",
  },
  {
    id: "explain",
    tags: ["explain", "breakdown", "verdict", "layman", "details", "why", "reason"],
    q: "Does the app explain its results?",
    a: "*nocap doesn't have a standalone 'explain mode'.* Instead, whenever you run a verification or document screening, the app provides a detailed breakdown of its verdict — `AUTHENTIC`, `PROVEN_FAKE`, `REVOKED`, or `UNSIGNED`. That breakdown covers checking the file's SHA-256 hash, inspecting metadata self-tags and pixel noise for AI generation, testing the cryptographic signature, and — for documents — verifying identity rules like Verhoeff check digits or MRZ lines. Screening results explain whether a document scored CLEAR, REVIEW, or FLAGGED and why.",
    s: "VerifyPanel + screening.py",
  },
];

export const SUGGESTED_QUESTIONS: string[] = [
  "What does nocap do?",
  "How does verify work?",
  "What is the kill switch?",
  "What is on the Analytics page?",
  "What is the tech stack?",
  "How do I run it locally?",
];

const normify = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

export function searchKnowledge(query: string, limit = 2): Entry[] {
  const q = normify(query);
  if (!q) return [];
  const tokens = q.split(" ").filter(Boolean);
  const scored = ENTRIES.map((e) => {
    const tagText = normify(e.tags.join(" "));
    const qText = normify(e.q);
    let score = 0;
    for (const t of tokens) {
      if (tagText.includes(t)) score += 3;
      else if (qText.includes(t)) score += 1;
      if (tagText.startsWith(t) || qText.includes(t)) score += 1;
    }
    if (tokens.every((t) => tagText.includes(t) || qText.includes(t))) score += 4;
    return { e, score };
  })
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score);
  return scored.slice(0, limit).map((s) => s.e);
}

export function answerFor(query: string): string {
  const hits = searchKnowledge(query, 2);
  if (!hits.length) return fallbackAnswer(query);
  return hits.map((h) => formatAnswer(h.a + (h.s ? `\n— ${h.s}` : ""))).join("\n\n---\n\n");
}

export function fallbackAnswer(query: string): string {
  const q = query.trim();
  return (
    `I couldn't match that to a curated note. Try one of the suggested questions, ` +
    `or ask about *verify*, *sign*, *revoke*, *screening*, *watchlist*, *analytics*, ` +
    `or the *tech stack*.\n` +
    (q ? `Snippet of your question: "${q.slice(0, 80)}"` : "")
  );
}

/** Minimal markdown-lite renderer: **bold**, *italic*, `code`, and newlines. */
export function formatAnswer(text: string): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const inline = (s: string): string => {
    let out = "";
    const parts = s.split(/(`[^`]*`|\*[^*]+\*)/g);
    for (const p of parts) {
      if (p.startsWith("`") && p.endsWith("`") && p.length > 2) {
        out += `<code>${esc(p.slice(1, -1))}</code>`;
      } else if (p.startsWith("*") && p.endsWith("*") && p.length > 2) {
        out += `<em>${esc(p.slice(1, -1))}</em>`;
      } else if (p.startsWith("**") && p.endsWith("**") && p.length > 4) {
        out += `<strong>${esc(p.slice(2, -2))}</strong>`;
      } else {
        out += esc(p);
      }
    }
    return out;
  };
  return text
    .split("\n")
    .map((ln) => inline(ln))
    .join("<br/>");
}