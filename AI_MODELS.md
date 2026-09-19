# AI Models - No Cap identity suite & deepfake detection

This file is the authoritative inventory of every trained model that touches the
verification pipeline, how each is wired in, and **how to train/replace your own**.
It intentionally ships **no weight files** - the repo stays under Vercel's 128 MB
serverless bundle and git stays clean. Weights appear at runtime (auto-download, or
a path you set) and are gitignored (`data/models/`, `app/models/`).

---

## 1. The inventory

| # | Model | Task | Real weights? | Where it lives | Loaded when |
|---|-------|------|---------------|----------------|-------------|
| 1 | **ViT-Base "Real vs AI" classifier** | Is this image AI-generated? | Yes (auto-downloaded, ~340 MB fp32) | `app/main.py` -> `onnx_detect()` | `AI_DETECTOR_PROVIDER=self-hosted` |
| 2 | **YOLOv8-Nano ROI detector** | Find face/document/QR/MRZ/signature zones on IDs | Optional (drop-in, ~6 MB) | `app/yolo_roi.py`, `app/models/yolov8n.onnx` | ONNX file present + `onnxruntime` |
| 3 | Sightengine (cloud API) | AI-image detection | No (hosted, proprietary) | `app/main.py` -> `sightengine_detect()` | `AI_DETECTOR_PROVIDER=sightengine` + key |
| 4 | Heuristic v2 (rule engine) | Cheap AI/edit flags + AI-tool attribution | No | `app/main.py` (document-aware pre-check, metadata tables) | always |
| 5 | Identity suite heuristics | ELA, checksums, Verhoeff/MRZ, crop analysis | No | `app/forensics.py`, `app/identity.py` | always |

The identity-suite forensics calls `app/yolo_roi.py` for the **ROI boxes** you see
overlaid on the document photo (`app/forensics.py:234`), so model #2 feeds directly
into the Identity Verify panel even though the whole suite is designed to degrade
gracefully without it.

---

## 2. Model 1 - ViT-Base AI-image classifier (the workhorse)

### 2.1 Architecture & lineage

- **Base:** `google/vit-base-patch16-224-in21k` (ViT-Base, **86 M params**, 12
  layers, 12 heads, patch 16 px, Apache-2.0).
- **Fine-tune:** `dima806/ai_vs_real_image_detection` - binary `Real` vs
  `Fake/AI`, trained on **CIFAKE** (60 k real images from CIFAR-10 + 60 k
  synthetic images generated with Stable Diffusion), Apache-2.0.
- **ONNX export:** `onnx-community/ai-image-detection-ONNX` (what this repo
  downloads), Apache-2.0.
- **Lineage:** google ViT-Base -> dima806 CIFAKE fine-tune -> capcheck repack ->
  onnx-community ONNX export.

### 2.2 Input / output contract (this repo)

`app/main.py -> _preprocess()`:

```
image  ->  RGB  ->  resize (224, 224)  ->  /255.0  ->  channel-first (1, 3, 224, 224) float32
```

`app/main.py -> onnx_score()`:

```
logits (2,)  ->  softmax  ->  probs[1] = P(Fake/AI)
ai_score      = int(round(probs[1] * 100))          # 0..100
ai_suspected  = ai_score >= 50
```

Only **2 logits** are read. If you swap in any other checkpoint you MUST keep the
`(1,3,224,224), /255, channel-first` tensor layout, or fork `_preprocess`.

> **Gotcha:** the runtime uses plain `/255` (no ImageNet mean/std). If you
> fine-tune with the HF `ViTImageProcessor` (which normalizes by
> `mean=[0.5,0.5,0.5], std=[0.5,0.5,0.5]` or ImageNet stats), your checkpoint will
> NOT behave correctly with the shipped `_preprocess`. Match your training
> preprocessing to this repo's, or extend `_preprocess` and re-export.

### 2.3 Activation (env vars)

| Var | Purpose |
|---|---|
| `AI_DETECTOR_PROVIDER=self-hosted` | Use the ONNX model |
| `AI_DETECTOR_MODEL_URL` | (optional) direct `.onnx` URL; default = HF `onnx-community/ai-image-detection-ONNX` |
| `AI_DETECTOR_MODEL_DIR` | cache dir; default `<repo>/data/models` |

Flow: `_load_engine()` -> `_ensure_model()` downloads on first use -> cached
`onnxruntime.InferenceSession(CPUExecutionProvider)`. If `onnxruntime` or the file
is missing it fails open (`ran:false`, honest explanation) - never a crash.

### 2.4 Why it is NOT on Vercel

fp32 ViT-Base is ~ **340 MB**, larger than Vercel's 128 MB bundle, and
`onnxruntime` is commented out of `requirements.txt` as local-only. On Vercel you
either run provider `sightengine`, or host this model as a small CPU worker and
call it (SSRF-safe design: put the worker on an internal network, or gateway the
Vercel function to it).

---

## 3. Model 2 - YOLOv8-Nano ROI extractor (optional)

`app/yolo_roi.py` looks for 5 semantic zones on identity documents: `face`,
`document`, `signature`, `qr_code`, `mrz_zone`.

### 3.1 Dual mode

1. If `app/models/yolov8n.onnx` (or `YOLO_ROI_ONNX_PATH`) exists **and**
   `onnxruntime` is importable -> ONNX inference: 640x640 input, `[1,84,8400]`
   output, confidence >0.35, at most 4 boxes. **Class 0 is mapped to `face`**
   (so even the stock COCO `yolov8n` gives you person->face for free).
2. Otherwise -> vectorised OpenCV/NumPy heuristics: skin-tone chroma (Chai & Ngan)
   for the face, edge-density projection for the MRZ text strip, `cv2.QRCodeDetector`
   for QR, convex-hull contour for the document frame.

### 3.2 Placement

```
copy best.onnx  app\models\yolov8n.onnx              # default path
# or: export YOLO_ROI_ONNX_PATH=C:\path\my_card.onnx
```

---

## 4. How to train a replacement (your own weights)

> **Best starting point: `TRAINING.md`** — a step-by-step runbook (what to run,
> where to put the dataset and its optional manifest/"training database",
> trust-but-verify eval, ONNX export, weights versioning) plus a ready-made
> trainer in **`scripts/train_vit_onnx.py`** that mirrors the runtime ONNX
> contract (224x224, `/255`, no mean/std, 2 logits, opset 17). Sections 4.1-4.2
> below are the same material in condensed form.

### 4.1 Option A - fine-tune the ViT classifier

**Setup**

```
pip install torch transformers datasets onnx onnxruntime pillow numpy
```

**Dataset layout** (CIFAKE mirror or your own):

```
dataset/
  real/   *.jpg                 # authentic photos (CIFAKE: CIFAR-10 real split)
  fake/   *.jpg                 # AI/synthetic (CIFAKE: Stable Diffusion outputs)
```

**Fine-tune**

```python
import torch, numpy as np
from pathlib import Path
from PIL import Image
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import ViTForImageClassification

class RealFakeDataset(Dataset):
    def __init__(self, root):                        # root has real/ and fake/
        self.items = []
        for label, kind in enumerate(("real", "fake")):
            for p in (Path(root) / kind).glob("*.jpg"):
                self.items.append((str(p), label))   # 0=Real, 1=Fake (MUST match onnx_score)
    def __len__(self):
        return len(self.items)
    def __getitem__(self, i):
        p, lbl = self.items[i]
        a = np.asarray(Image.open(p).convert("RGB").resize((224, 224))) / 255.0
        # Plain /255 matches app/main.py::_preprocess. Do NOT add mean/std
        # unless you also teach _preprocess the same normalization (see 2.2).
        return torch.from_numpy(a.transpose(2, 0, 1)).float(), torch.tensor(lbl)

model = ViTForImageClassification.from_pretrained(
    "google/vit-base-patch16-224-in21k",
    num_labels=2, ignore_mismatched_sizes=True)
opt = AdamW(model.parameters(), lr=2e-5)
loader = DataLoader(RealFakeDataset("dataset"), batch_size=32, shuffle=True)
model.train()
for ep in range(3):                                  # 3 epochs is enough for CIFAKE-style sets
    for x, y in loader:
        loss = model(x, labels=y).loss
        opt.zero_grad(); loss.backward(); opt.step()
    print(f"epoch {ep}: loss={loss.item():.4f}")
model.save_pretrained("data/trained-ai-detector")
```

**Export to ONNX** (exact input shape for the repo)

```python
import torch
from transformers import ViTForImageClassification
model = ViTForImageClassification.from_pretrained("data/trained-ai-detector")
model.eval()
torch.onnx.export(
    model, torch.randn(1, 3, 224, 224), "model.onnx",
    input_names=["pixel_values"], output_names=["logits"],
    opset_version=17, do_constant_folding=True)
```

If PyTorch >= 2.4's exporter complains, add `dynamo=False`, or use Optimum:

```
optimum-cli export onnx --model data/trained-ai-detector model_onnx/
```

**Wire it in**

```
copy model.onnx  data\models\model.onnx
set AI_DETECTOR_PROVIDER=self-hosted
```

Restart the server. The detector JSON now reports
`"model": "Self-hosted ViT-Base (your fine-tune)"`.

**Evaluate on your own holdout set**

```bash
python -c "import sys; sys.path.insert(0,'app'); from main import onnx_detect; import glob; [print(f, onnx_detect(open(f,'rb').read())['ai_score']) for f in glob.glob('eval/fake/*.jpg')[:5]]"
```

### 4.2 Option B - train the ROI detector (YOLOv8-Nano)

`ultralytics` is a train-time dependency only; runtime just reads the ONNX file.

1. **Label** identity documents with `face`, `document`, `signature`, `qr_code`,
   `mrz_zone` (Roboflow / anylabelimg -> YOLO .txt export). **Put `face` as
   class 0** - `_run_yolo_onnx` maps class 0 -> `face`; any other class renders
   as `class_N` unless you extend the mapping.
2. **data.yaml**

   ```yaml
   path: dataset/card
   train: images/train
   val: images/val
   nc: 5
   names: ["face", "document", "signature", "qr_code", "mrz_zone"]
   ```

3. **Train**

   ```bash
   pip install ultralytics
   yolo detect train model=yolov8n.pt data=data.yaml epochs=50 imgsz=640
   ```

   Restart from the stock COCO `yolov8n.pt` weights (person detection is class 0
   there, matching the repo's `face` assumption) - do NOT train from random init.
4. **Export + drop in**

   ```bash
   yolo export model=runs/detect/train/weights/best.pt format=onnx imgsz=640 opset=17
   copy runs\detect\train\weights\best.onnx  app\models\yolov8n.onnx
   ```

5. Smoke-test that the network's output shape is still `[1, 84, 8400]` (that is
   what `_run_yolo_onnx` hard-codes), then run:

   ```bash
   python -m pytest tests/test_forensics.py -q
   ```

---

## 5. Versioning & pushing weights safely

Never commit `.onnx`/`.pt` files into `main` - a 340 MB file will break the Vercel
deploy bundle and bloat the repo. Standard options instead:

- **Pre-trained only (current):** keep the auto-download URL as the single source
  of truth; bump `MODEL_REPO` / `DEFAULT_URL` in `app/main.py` when you upgrade.
- **Track your fine-tune separately:** push the checkpoint to Hugging Face Hub
  (or a private release tag on GitHub) and point `AI_DETECTOR_MODEL_URL` at it.
  `data/models/` stays gitignored, so the runtime pulls your model on first use.
- **Community branch:** if weight files are really mission-critical, push them on
  a branch with `data/models/**` explicitly un-ignored, and note in the PR that
  Vercel cannot build that branch.

## 6. Decision rules for judge demos

- **"What model is this?"** -> ViT-Base (86 M params) fine-tuned on CIFAKE,
  exported to ONNX, running via onnxruntime on CPU; optional YOLOv8-Nano ROI on
  identity docs. Both Apache-2.0 lineage, so demoing is license-clean.
- **"Did you train it?"** -> No - we use the community CIFAKE fine-tune so the
  project ships without training infrastructure. Section 4 is the playbook to
  fine-tune on modern generators (Flux, Midjourney v6, SD3) and beat the
  pre-2024 training-data limitation.
- **"What are its limits?"** -> Trained mostly on pre-2024 generators;
  weak on heavily compressed images and images under 224x224; never make a
  consequential decision on AI-score alone - pair the model score with the
  cryptographic/forensic verdicts (the suite does).