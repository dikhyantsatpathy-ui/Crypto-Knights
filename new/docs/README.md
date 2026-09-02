# No Cap 2.0 — Enterprise Provenance Engine (reorganized)

Clean, deploy-ready copy of the "No Cap" crypto provenance app, reorganized into
a maintainable folder structure with a real, explainable AI-content-detection
layer. Work in this folder is **isolated** from the deployed root until you
approve a push.

## Folder layout

```
new/
├── app/
│   ├── main.py                  # FastAPI application (single-file backend)
│   ├── api/
│   │   └── index.py             # Vercel serverless entrypoint (imports app)
│   ├── static/
│   │   ├── index.html           # UI markup + styles
│   │   └── main.js              # UI logic (verdict cards, analytics charts)
│   └── detectors/               # AI-content-detection layer (see below)
│       ├── __init__.py          # orchestrator: picks backend, normalizes result
│       ├── heuristic.py         # free metadata + pixel detector (default)
│       ├── provider_sightengine.py  # cloud API backend (needs key)
│       ├── self_hosted.py       # on-device ONNX Vision Transformer (real model)
│       └── _signatures.py       # ~70 AI-gen + ~34 editing tool signatures
├── data/models/                 # downloaded ONNX weights (self-hosted path)
├── docs/                        # this documentation
├── scripts/                     # dev/maintenance helpers
├── tests/                       # unit/smoke tests
├── requirements.txt
├── vercel.json                  # edge function config + duration limits
└── .gitignore
```

## How AI content detection works

Every image you verify is passed through an **AI-detection orchestrator**
(`app/detectors/__init__.py`). It returns a single, normalized verdict:

```json
{
  "ran": true,
  "ai_suspected": true,
  "ai_score": 80,           // 0..100 confidence
  "model": "heuristic v2 (metadata+pixels)",
  "provider": "heuristic",  // heuristic | sightengine | self-hosted
  "explanation": "...judge-friendly sentence...",
  "latency_ms": 4           // how long the model took
}
```

The active backend is chosen by the `AI_DETECTOR_PROVIDER` env var:

| Provider           | Needs key? | Real model? | Notes |
|--------------------|-----------|-------------|-------|
| `heuristic` (def.) | No        | No          | Reads embedded labels + a conservative pixel scan. ~1-4ms, never sends the image anywhere. |
| `sightengine`      | Yes       | Yes         | Cloud AI-Content API, ~200ms, high accuracy. Set `AI_DETECTOR_KEY`. |
| `self-hosted`      | No        | Yes         | On-device ONNX `ViT-Base` (CIFAKE fine-tune, 86M params). Downloads weights on first run to `data/models/`. ~850ms locally. Too heavy (~343MB) for the Vercel edge runner — **local/worker use only**. |

> **Free-tier reality (Sightengine):** 2,000 ops/month capped at 500/day. Each
> `genai` check consumes **5 operations** (measured live), and adding deepfake
> costs more — so the free tier buys ~100 image checks/day. A live crowd trashes
> that in minutes, so budget it like a demo cap, not a production backend. The
> app counts every check's operations server-side and shows an honest "uses
> left" in Analytics (`/api/detection/usage`).

### Why three backends?
1. **Sightengine — the JUDGE-FACING demo model.** This is the one you turn on
   for the judges: a genuine cloud-trained classifier that names what it sees
   (AI-generated vs photograph) in ~200ms. It is the "we use a real trained
   model via API" proof point.
2. **Self-hosted ONNX** — the "we run a real neural net ourselves, no third
   party" proof: downloads a real ViT and runs inference locally with zero API
   keys. Complement to, not replacement for, Sightengine.
3. **Heuristic (default fallback)** — free, key-free, always-on safety net so
   the app never breaks when the cloud budget is spent or unavailable. If a
   judge connects to the live URL without a key, this keeps the demo alive.

`detect_image()` **never raises** — any backend failure degrades to a clean
"unable to inspect" result, so a verify request can never 500.

### Scanned-document awareness (notices)
Cloud AI-art detectors are trained on **photos**, so a scanned notice (a photo
of paper, text-heavy) would misfire and burn paid operations. We added a
**document-aware pre-check** (`app/detectors/document_aware.py`): a
conservative scan of aspect ratio + paper-white background + ink coverage
detects "this is a scanned page" and routes it to a **document verdict** —
trust points to the cryptographic signature/provenance, not image-AI analysis.
Real photos and AI-art images are not misread as documents, so the model still
runs where it actually helps.

## Where the verdict surfaces

- **API**: `/api/verify` returns `ai_detection`, `ai_score`, `ai_model`,
  `ai_provider`, `ai_explanation`, `ai_suspected` alongside the regular verdict.
- **UI**: every verdict card shows an **AI Content Detection** panel naming the
  model, its confidence, how fast it ran, and a plain-language explanation
  written for a non-technical judge.
- **Analytics**: each verify records its detector latency
  (`verification_logs.detection_ms` + `detection_provider`). `/api/analytics`
  (admin) returns a `latency` series (avg/min/max) plus a provider breakdown;
  the dashboard renders this as an **AI Detection Performance** chart.

## VerificationLog schema additions
```sql
ALTER TABLE verification_logs ADD COLUMN IF NOT EXISTS detection_ms INTEGER DEFAULT 0;
ALTER TABLE verification_logs ADD COLUMN IF NOT EXISTS detection_provider VARCHAR;
```
Handled idempotently by the startup migration pass — safe on both Postgres and SQLite.

## Deploy notes (Vercel)
- `vercel.json` sets the `python3.9` runtime and keeps functions single-file.
- The self-hosted ONNX path is **not** wired into the Vercel builder; use
  Sightengine (key) or the heuristic there. Keep everything else as-is.
- Root `vercel.json` and `api/index.py` serve the *deployed* copy; this `new/`
  copy is not deployed until you approve.

## Run locally
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
# to try the real local model:
AI_DETECTOR_PROVIDER=self-hosted uvicorn app.main:app
```