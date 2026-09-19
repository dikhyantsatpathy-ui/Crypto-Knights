// ============================================================================
// WebcamLivenessSuite — Enterprise interactive liveness & deepfake detection
//
// Real-time camera stream capture with anti-virtual-camera injection detection,
// active challenge-response flows (blink, head turns), and multi-frame motion
// analysis.
// ============================================================================

import { useEffect, useRef, useState } from "react";
import { verifyWebcamLiveness, type LivenessResult } from "../api";
import { Button, Pill, Modal } from "./ui";

interface WebcamLivenessSuiteProps {
  isOpen: boolean;
  onClose: () => void;
  onVerified?: (res: LivenessResult) => void;
}

const CHALLENGES = [
  { id: "blink", label: "Eye Blink", instruction: "Look straight into the lens and blink your eyes twice naturally." },
  { id: "turn_left", label: "Turn Head Left", instruction: "Slowly turn your head to your left side and return to center." },
  { id: "turn_right", label: "Turn Head Right", instruction: "Slowly turn your head to your right side and return to center." },
  { id: "nod", label: "Head Nod", instruction: "Gently nod your head up and down once." },
];

export function WebcamLivenessSuite({ isOpen, onClose, onVerified }: WebcamLivenessSuiteProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  const [activeChallenge, setActiveChallenge] = useState<string>("blink");
  const [cameraLabel, setCameraLabel] = useState<string>("");
  const [isVirtualCam, setIsVirtualCam] = useState<boolean>(false);
  const [capturing, setCapturing] = useState<boolean>(false);
  const [result, setResult] = useState<LivenessResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string>("");

  useEffect(() => {
    if (!isOpen) {
      stopCamera();
      return;
    }

    startCamera();
    return () => {
      stopCamera();
    };
  }, [isOpen]);

  const startCamera = async () => {
    setErrorMsg("");
    setResult(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: "user",
          width: { ideal: 640 },
          height: { ideal: 480 },
        },
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
      }

      const track = stream.getVideoTracks()[0];
      if (track) {
        const label = track.label || "Default WebCam";
        setCameraLabel(label);
        const lower = label.toLowerCase();
        const virtualDetected = ["obs", "virtual", "manycam", "fake", "v4l2loopback", "camtwist", "wirecast"].some(
          (kw) => lower.includes(kw)
        );
        setIsVirtualCam(virtualDetected);
      }
    } catch (err: any) {
      setErrorMsg(`Camera access failed: ${err.message || err}. Please ensure webcam permissions are enabled.`);
    }
  };

  const stopCamera = () => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
  };

  const captureFrameBlob = (video: HTMLVideoElement): Promise<Blob> => {
    return new Promise((resolve, reject) => {
      const canvas = document.createElement("canvas");
      canvas.width = video.videoWidth || 640;
      canvas.height = video.videoHeight || 480;
      const ctx = canvas.getContext("2d");
      if (!ctx) return reject("Canvas 2D context error");
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      canvas.toBlob((blob) => {
        if (blob) resolve(blob);
        else reject("Frame capture failed");
      }, "image/jpeg", 0.90);
    });
  };

  const runChallengeFlow = async () => {
    if (!videoRef.current || !streamRef.current) {
      setErrorMsg("Video stream not active.");
      return;
    }

    setCapturing(true);
    setErrorMsg("");
    setResult(null);

    try {
      const frames: Blob[] = [];
      const timestamps: number[] = [];

      // Capture 3 sequential frames spaced by 160ms
      for (let i = 0; i < 3; i++) {
        const blob = await captureFrameBlob(videoRef.current);
        frames.push(blob);
        timestamps.push(performance.now());
        if (i < 2) {
          await new Promise((r) => setTimeout(r, 160));
        }
      }

      const clientMeta = {
        camera_label: cameraLabel,
        timestamps,
        virtual_cam_flag: isVirtualCam,
      };

      const res = await verifyWebcamLiveness(frames, activeChallenge, clientMeta);
      setCapturing(false);

      if (res.ok) {
        setResult(res.data);
        if (onVerified) onVerified(res.data);
      } else {
        setErrorMsg(res.error || "Liveness check failed.");
      }
    } catch (err: any) {
      setCapturing(false);
      setErrorMsg(`Verification error: ${err.message || err}`);
    }
  };

  if (!isOpen) return null;

  const currentChallengeObj = CHALLENGES.find((c) => c.id === activeChallenge) || CHALLENGES[0];

  return (
    <Modal title="Webcam Liveness & Deepfake Defense" onClose={onClose}>
      <div style={{ maxWidth: 640, width: "100%" }}>
        {/* Anti-Virtual Camera Injection Warning Banner */}
        {isVirtualCam && (
          <div
            className="screen-report mt-2 mb-3"
            data-tone="danger"
            style={{ borderLeft: "4px solid var(--bad, #ef4444)", background: "rgba(239, 68, 68, 0.1)" }}
          >
            <div className="row" style={{ gap: 8, alignItems: "center" }}>
              <Pill tone="danger">SECURITY INJECTION DETECTED</Pill>
              <strong>Virtual Camera Driver in Use</strong>
            </div>
            <p className="stat-note mt-2" style={{ color: "var(--bad, #ef4444)" }}>
              Detected video source <code>'{cameraLabel}'</code> is a virtual/synthetic camera loop. Liveness verification
              requires a direct physical hardware camera.
            </p>
          </div>
        )}

        {/* Video feed viewport */}
        <div
          style={{
            position: "relative",
            width: "100%",
            borderRadius: 10,
            overflow: "hidden",
            background: "#000",
            border: "1px solid var(--line-2)",
          }}
        >
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            style={{
              width: "100%",
              height: 340,
              objectFit: "cover",
              display: "block",
              transform: "scaleX(-1)", // Mirror mode for natural self-alignment
            }}
          />

          {/* Guiding Face Oval Overlay */}
          <div
            style={{
              position: "absolute",
              top: "14%",
              left: "30%",
              width: "40%",
              height: "72%",
              border: `2px dashed ${capturing ? "var(--accent, #3b82f6)" : "var(--seal, #22c55e)"}`,
              borderRadius: "50%",
              pointerEvents: "none",
              boxShadow: "0 0 0 9999px rgba(0, 0, 0, 0.35)",
            }}
          />

          {capturing && (
            <div
              style={{
                position: "absolute",
                inset: 0,
                background: "rgba(0,0,0,0.5)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#fff",
                fontWeight: 600,
              }}
            >
              Capturing sequential motion frames…
            </div>
          )}
        </div>

        {/* Active hardware metadata */}
        <div className="mt-2 row-between" style={{ fontSize: "0.8rem", opacity: 0.8 }}>
          <span>Camera: <strong>{cameraLabel || "Searching…"}</strong></span>
          <span>Status: <strong style={{ color: isVirtualCam ? "var(--bad, #ef4444)" : "var(--good, #22c55e)" }}>
            {isVirtualCam ? "Virtual Stream" : "Hardware Active"}
          </strong></span>
        </div>

        {/* Challenge selection buttons */}
        <div className="mt-3">
          <div className="kicker">Select Active Liveness Challenge</div>
          <div className="row mt-1" style={{ gap: 6, flexWrap: "wrap" }}>
            {CHALLENGES.map((c) => (
              <Button
                key={c.id}
                size="sm"
                variant={activeChallenge === c.id ? "seal" : "ghost"}
                onClick={() => {
                  setActiveChallenge(c.id);
                  setResult(null);
                }}
              >
                {c.label}
              </Button>
            ))}
          </div>
          <p className="stat-note mt-2">
            Instruction: <strong>{currentChallengeObj.instruction}</strong>
          </p>
        </div>

        {errorMsg && (
          <div className="screen-report mt-3" data-tone="danger">
            <span style={{ color: "var(--bad, #ef4444)" }}>{errorMsg}</span>
          </div>
        )}

        {/* Action Button */}
        <div className="mt-3 row" style={{ gap: 10 }}>
          <Button
            variant="seal"
            block
            busy={capturing}
            onClick={() => void runChallengeFlow()}
            disabled={capturing}
          >
            {capturing ? "Analyzing Liveness…" : `Perform '${currentChallengeObj.label}' Check`}
          </Button>
        </div>

        {/* Liveness results */}
        {result && (
          <div
            className="screen-report mt-3"
            data-tone={result.verdict === "LIVE" ? "seal" : "danger"}
          >
            <div className="row" style={{ gap: 10, alignItems: "center" }}>
              <Pill tone={result.verdict === "LIVE" ? "seal" : "danger"}>
                VERDICT: {result.verdict}
              </Pill>
              <span className="stat-note">
                Confidence: {Math.round(result.confidence * 100)}%
              </span>
              <span className="mono stat-note">
                Motion Score: {result.motion_score ?? "--"}
              </span>
              <span className="mono stat-note">{result.latency_ms ?? "--"} ms</span>
            </div>

            <ul className="screen-reasons mt-3">
              {result.checks.map((c, i) => (
                <li key={`check-${i}`}>
                  <span className="row" style={{ gap: 6, alignItems: "center" }}>
                    <span style={{ color: c.ok ? "var(--good, #22c55e)" : "var(--bad, #ef4444)" }}>
                      {c.ok ? "✓" : "✕"}
                    </span>
                    <strong className="mono">{c.label}</strong>
                    <span>{c.detail}</span>
                  </span>
                </li>
              ))}
            </ul>

            {result.signals && result.signals.length > 0 && (
              <div className="mt-2">
                {result.signals.map((s, idx) => (
                  <div key={`sig-${idx}`} className="stat-note" style={{ color: "var(--amber, #f59e0b)" }}>
                    ⚠ {s}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
