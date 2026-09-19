# Training Runbook — No Cap identity & deepfake models

Everything you run, in order, for training a replacement fake-image classifier
(or the optional ROI detector), with the exact commands, the dataset/"database"
locations, and what to do after training so the running app picks it up.

**The repo ships no weights** (Vercel 128 MB cap + clean git). All training
artifacts land in gitignored folders — `data/models/` for weights/manifest,
`data/datasets/` for training data. Nothing you train here gets committed by
mistake. Note: `scripts/` is also gitignored by repo convention (local helper
tools), so `scripts/train_vit_onnx.py` is a local tool on your box, not a
pushed file.

---

## 1. Where everything lives ("the database" question)

| What | Where | Tracked in git? |
|---|---|---|
| ViT weights (runtime) | `data/models/model.onnx` | ❌ gitignored |
| Best torch checkpoint | `data/models/best_state.pt` | ❌ gitignored |
| Weights manifest (version, sha256, threshold) | `data/models/weights.json` | ❌ gitignored |
| ROI detector (optional) | `app/models/yolov8n.onnx` | ❌ gitignored |
| Training images | `data/datasets/fake-detector/{train,val}/{real,fake}/` | ❌ gitignored |
| Label manifest (optional, for reproducibility) | `data/datasets/fake-detector/labels.csv` | ❌ gitignored |

There is **no SQL database involved in training**. "The database" is two things:

1. **The dataset** — an image-folder tree + an optional `labels.csv`
   (`path,label`, label `0`=real `1`=fake) that records the exact split. Keep a
   copy of `labels.csv` + a `params.json` of the training hyperparameters next
   to the images so any training run is reproducible and auditable.
2. **The weight store** — `data/models/`, versioned by `weights.json`. The app
   reads that manifest to report which model/threshold is live.

If you want a real persisted store, use a HuggingFace **Dataset** for the
training split and a **model repo / GitHub Release** for weights (see §4).

---

## 2. Environment (local dev box)

Python 3.10–3.11 recommended. Create the venv **away from the deploy path**:

```bash
python -m venv .venv-training
# Windows:  .venv-training\Scripts\activate
# macOS/Linux: source .venv-training/bin/activate

pip install torch torchvision transformers datasets onnx onnxruntime pillow numpy
```

`torch`/`onnxruntime` stay **out of `requirements.txt`** on purpose —
installing them on Vercel would blow the 128 MB bundle. They are dev-only here.

---

## 3. Build the dataset

Rule of thumb: ≥5k real + ≥5k fake images for a solid binary classifier
(3 epochs here ≈ 20–40 min on a consumer GPU). Sources:

- **real**: CIFAKE's CIFAR-10 real split, or your own camera/Dataset images.
- **fake**: CIFAKE's Stable-Diffusion split, CIFAKE-adjacent sets, or images
  you manipulate with Deepfake/StyleGAN/Diffusion models.

Layout (this is what `scripts/train_vit_onnx.py` expects):

```
data/datasets/fake-detector/
  train/real/ img001.jpg ...
  train/fake/ f001.png ...
  val/real/
  val/fake/
```

```bash
python scripts/train_vit_onnx.py --data-dir data/datasets/fake-detector \
    --epochs 3 --batch-size 32 --lr 3e-5 --seed 7 --device cuda
```

Watching the console: each epoch prints `loss` + `val_acc`; the best checkpoint
is saved automatically to `data/models/best_state.pt`.

---

## 4. After training (trust-but-verify)

### 4.1 Check the export + manifest

The script already does this, but if you want to re-check:

```bash
python scripts/train_vit_onnx.py --data-dir ... --predict data/datasets/fake-detector/val/fake
# prints per-image verdict + probability
```

Read `data/models/weights.json` — it records class order `[real, fake]`,
input contract (`resize + /255, no mean/std`), `threshold: 0.5`, the ONNX
`sha256`, and the val accuracy. Trim the threshold if your false-accept rate
matters more than false-reject (e.g. 100–X% → `0.45` rejects more aggressively).

> Validate live before trusting: hit `/api/screen` (or `/api/identity/verify`
> for an ID photo) with one **known-fake** and one **known-real** sample and
> confirm the verdict flips. Re-run with a second model variant and compare —
> you want the *judge* to disagree on hard samples.

### 4.2 Store the weights (never in git)

- **Local demo**: leave in `data/models/` → app already looks there.
- **Vercel deploy**: the `.onnx` (~340 MB fp32; ignore the 128 MB bundle cap)
  goes **outside the bundle**, e.g. a GitHub Release or a HF repo. Set
  `AI_DETECTOR_MODEL_URL` to it and `AI_DETECTOR_MODEL_DIR` to a writable cache
  dir; the loader downloads on first run and caches. Model stays a build-time
  resource, not serverless middleware.
- **Reproducibility**: archive `data/datasets/fake-detector/` + `labels.csv` +
  the `weights.json` manifest together (`tar`/`zip`), and tag the release with
  the manifest version.

### 4.3 Activate the new model

```bash
# runtime env in the deployed app (or .env locally):
AI_DETECTOR_PROVIDER=self-hosted
AI_DETECTOR_MODEL_DIR=/path/to/data/models
AI_DETECTOR_MODEL_URL=https://releases.example/vit-fake-detector.onnx   # optional, non-Vercel
```

The self-hosted loader (`app/main.py` → `onnx_detect()`) expects `model.onnx`
(this is the trainer's default export name — no renaming needed) or whatever
`AI_DETECTOR_MODEL_URL`'s basename is; `input` `[1,3,224,224]` fp32 0–1,
`logits` `[1,2]`, `probs[1] >= 0.5` ⇒ fake. **Do not** normalise with mean/std
at inference — the exported graph maps `/255` only, and training mirrored that
(see the `CRITICAL` comment in the trainer).

---

## 5. Option B — YOLOv8 ROI detector (face/document)

Database/layout identical but detection labels, not classes:

```
data/datasets/roi/
  images/*.jpg
  labels/*.txt        # YOLO .txt per image
```

```bash
pip install ultralytics
yolo detect train model=yolov8n.pt data=data/datasets/roi/data.yaml \
    epochs=50 imgsz=640 batch=16
yolo export model=runs/detect/train/weights/best.pt format=onnx imgsz=640
cp runs/detect/train/weights/best.onnx app/models/yolov8n.onnx
```

`class 0 -> face` maps onto the ROI boxes the Identity panel overlays; the
model is **optional** — `app/yolo_roi.py` degrades to heuristics when the file
is absent (which is the default commit state).

---

## 6. Versioning rules

1. Bump the version in `weights.json` every time you retrain.
2. Record `sha256` + val accuracy in the manifest; tag the HF repo / Release
   with the same version.
3. Keep `labels.csv` + hyperparams next to the dataset so an auditor can
   rebuild your exact split.
4. When swapping `data/models/*.onnx` in a running app, swap the manifest first
   and restart — the loader reads model + threshold together.

---

## 7. Gotchas

- **Preprocessing drift**: resize must be 224×224 and pixel values 0–1. A
  mean/std pipeline in training but not inference quietly destroys accuracy.
- **Class order**: `[real, fake]`. Swapping the head's order silently flips the
  verdict.
- **ONNX opset**: export with `--opset 17` (trainer default). Older runtimes on
  some platforms choke on newer Reddit-style ops.
- **Vercel**: `onnxruntime` + `torch` are dev-only; the deployed runtime uses
  the ONNX file via `AI_DETECTOR_MODEL_URL`, never a venv-packaged giant.
- **EPIC/Voter ID**: ECI publishes the structure (3-letter FUSN + 7 digits,
  7th digit = checksum) but **not** the checksum formula — the suite
  intentionally validates structure + a live electoral-roll name match via the
  `epic_ec` registry adapter rather than a fabricated checksum (see
  `VERIFICATION_PROVIDERS.md`). Same honesty rule as the PAN check character.