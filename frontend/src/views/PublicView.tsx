// ============================================================================
// PublicView — SSB NISCHAY Border Document Screening Desk (SIH26188)
// Ministry of Home Affairs, Sashastra Seema Bal (SSB), Police II Division.
// Primary flow:
// 1. Hero: Border Checkpoint Screening Desk & Key Metrics
// 2. Screening Desk: 1-Click Specimen Presets, OCR, MRZ, Tamper ELA, Live Face
// 3. 4-Module Architecture breakdown (M1 OCR, M2 Standards, M3 Tamper, M4 Face)
// 4. Border ICP Coverage & Syndicate Threat Intelligence Network
// 5. Zero-Storage Cryptographic Ledger Verification
// ============================================================================

import { IconDoc, IconHash, IconLayers, IconShield, Kicker } from "../components/ui";
import { ScreeningDesk } from "./AuthorityView";
import { VerifyPanel } from "../components/VerifyPanel";
import { NoticeBoard } from "../components/NoticeBoard";
import { TerminalDecrypt } from "../components/TerminalDecrypt";

export function PublicView() {

  return (
    <div className="public-flow">
      {/* -------------------------------------------------- Hero Header */}
      <section className="section section--hero hero hero--centered" id="top">
        <div className="hero__grid">
          <div className="hero__main">
            <div className="hero__kicker rv">
              <span className="dot" aria-hidden="true" /> 🇮🇳 Sashastra Seema Bal (SSB) · Ministry of Home Affairs | SIH26188
            </div>
            <h1 className="rv">
              AI-Based Fake Identity &amp; <TerminalDecrypt text="Document Screening" /> System
            </h1>
            <p className="hero__lede rv rv--d1">
              <strong>SSB NISCHAY Checkpoint Desk:</strong> Sub-second automated screening for{" "}
              <strong>Passports (ICAO Doc 9303 MRZ)</strong>, <strong>Visas</strong>,{" "}
              <strong>Driving Licences</strong>, and <strong>Identity Credentials</strong>.
              Detects photo replacement, text manipulation, and stamp forgery while verifying
              biometric face liveness and cross-border syndicate imposter patterns.
            </p>

            <div className="hero__cta rv rv--d2">
              <a className="btn btn--seal btn--lg" href="#desk">
                🛂 Open Screening Desk
              </a>
              <a className="btn btn--ghost btn--lg" href="#modules">
                4-Module Architecture
              </a>
            </div>

            <div className="hero__stats rv rv--d3" aria-label="System screening capabilities">
              <div className="stat-plate">
                <span className="stat-plate__icon">
                  <IconDoc size={22} />
                </span>
                <div>
                  <div className="stat-plate__num">&lt; 850 ms</div>
                  <div className="stat-plate__label">Average Decision Latency</div>
                </div>
              </div>
              <div className="stat-plate">
                <span className="stat-plate__icon stat-plate__icon--amber">
                  <IconShield size={22} />
                </span>
                <div>
                  <div className="stat-plate__num">4 Modules</div>
                  <div className="stat-plate__label">OCR · Checksum · Tamper · Face</div>
                </div>
              </div>
              <div className="stat-plate">
                <span className="stat-plate__icon">
                  <IconHash size={22} />
                </span>
                <div>
                  <div className="stat-plate__num">ICAO 9303</div>
                  <div className="stat-plate__label">TD1 / TD2 / TD3 MRZ Compliant</div>
                </div>
              </div>
              <div className="stat-plate">
                <span className="stat-plate__icon stat-plate__icon--amber">
                  <IconLayers size={22} />
                </span>
                <div>
                  <div className="stat-plate__num">Zero-Storage</div>
                  <div className="stat-plate__label">Evidentiary SHA-256 Hashes Only</div>
                </div>
              </div>
            </div>

            <div className="hero__meta rv rv--d4" aria-hidden="true">
              <span>Photo Replacement Detection</span>
              <span>2D-FFT Spectral PAPR</span>
              <span>Sensor PRNU Noise</span>
              <span>Webcam Biometric Liveness</span>
              <span>Syndicate Threat Intel</span>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------ Border Screening Desk */}
      <section className="section section--rule" id="desk">
        <div className="section__head rv">
          <div>
            <Kicker>MHA SIH26188 Operational Console</Kicker>
            <h2>Border Document Screening Desk</h2>
          </div>
          <p>
            Choose a 1-click test specimen or upload any travel document. The system runs all 4 SIH
            modules concurrently and provides an explainable forensic verdict in sub-second time.
          </p>
        </div>

        <div className="rv rv--d1">
          <ScreeningDesk />
        </div>
      </section>

      {/* --------------------------------------------- 4-Module Architecture */}
      <section className="section section--rule" id="modules">
        <div className="section__head rv">
          <div>
            <Kicker>Problem Statement Requirements</Kicker>
            <h2>The Four Core SIH26188 Modules</h2>
          </div>
          <p>
            Standardized border screening replacing minutes of manual inspection with seconds of
            explainable, court-admissible verification.
          </p>
        </div>

        <div className="feature-grid rv rv--d1" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 16 }}>
          <div className="feature-card" style={{ background: "var(--surface)", border: "1px solid var(--line-2)", borderRadius: "var(--r-lg)", padding: 20 }}>
            <div className="feature-icon" style={{ fontSize: 24, marginBottom: 8 }}>🔤</div>
            <h3 style={{ fontSize: 16, marginBottom: 6 }}>Module 1: OCR &amp; MRZ Extraction</h3>
            <p className="stat-note" style={{ fontSize: 12.5, lineHeight: 1.5 }}>
              Auto-extracts text and machine-readable data. Features dual ICAO Doc 9303 parsers for
              TD3 (passports, 2 lines of 44 chars) and TD1/TD2 (identity cards, 3 lines of 30 chars).
              Handles regex parsing for Indian DL (MoRTH), PAN, and Voter ID cards.
            </p>
          </div>

          <div className="feature-card" style={{ background: "var(--surface)", border: "1px solid var(--line-2)", borderRadius: "var(--r-lg)", padding: 20 }}>
            <div className="feature-icon" style={{ fontSize: 24, marginBottom: 8 }}>✅</div>
            <h3 style={{ fontSize: 16, marginBottom: 6 }}>Module 2: Document Standards Validation</h3>
            <p className="stat-note" style={{ fontSize: 12.5, lineHeight: 1.5 }}>
              Validates extracted data against official document issuing rules. Verifies Modulus-10
              weight-731 check digits on document numbers, birth dates, and composite checksums.
              Enforces 6-month international travel expiry windows and national registry formats.
            </p>
          </div>

          <div className="feature-card" style={{ background: "var(--surface)", border: "1px solid var(--line-2)", borderRadius: "var(--r-lg)", padding: 20 }}>
            <div className="feature-icon" style={{ fontSize: 24, marginBottom: 8 }}>🔬</div>
            <h3 style={{ fontSize: 16, marginBottom: 6 }}>Module 3: Tampering Detection (AI)</h3>
            <p className="stat-note" style={{ fontSize: 12.5, lineHeight: 1.5 }}>
              Deep-forensic layer detecting digital and physical alteration. Computes Error Level
              Analysis (ELA) compression heatmaps, 2D-FFT spectral PAPR, camera sensor PRNU noise
              variance consistency, and font inconsistency around key credential fields.
            </p>
          </div>

          <div className="feature-card" style={{ background: "var(--surface)", border: "1px solid var(--line-2)", borderRadius: "var(--r-lg)", padding: 20 }}>
            <div className="feature-icon" style={{ fontSize: 24, marginBottom: 8 }}>👤</div>
            <h3 style={{ fontSize: 16, marginBottom: 6 }}>Module 4: Biometric Face Verification</h3>
            <p className="stat-note" style={{ fontSize: 12.5, lineHeight: 1.5 }}>
              Matches the document owner against the live presented traveler. Extracts document portrait
              and compares it against a live webcam frame via normalized cosine similarity embeddings,
              with texture-based liveness analysis to detect screen re-capture or print spoofing.
            </p>
          </div>
        </div>
      </section>

      {/* --------------------------------------------- Checkpoints & Syndicate Intel */}
      <section className="section section--rule" id="syndicate">
        <div className="section__head rv">
          <div>
            <Kicker>Sashastra Seema Bal Border Coverage</Kicker>
            <h2>Cross-Border Syndicate Threat Intel</h2>
          </div>
          <p>
            Real-time graph analytics tracking suspicious travel document reuse across Indo-Nepal and
            Indo-Bhutan border Integrated Check Posts (ICPs).
          </p>
        </div>

        <div className="syndicate-overview rv rv--d1" style={{ background: "var(--surface-2)", border: "1px solid var(--line-2)", borderRadius: "var(--r-lg)", padding: "20px 24px" }}>
          <div className="row" style={{ gap: 12, flexWrap: "wrap", justifyContent: "space-between", marginBottom: 16 }}>
            <div>
              <strong style={{ fontSize: 14 }}>Monitored Border Checkpoints:</strong>
              <div className="row" style={{ gap: 8, flexWrap: "wrap", marginTop: 6 }}>
                <span className="screen-chip mono">Raxaul ICP (Bihar/Nepal)</span>
                <span className="screen-chip mono">Panitanki ICP (WB/Nepal)</span>
                <span className="screen-chip mono">Jogbani ICP (Bihar/Nepal)</span>
                <span className="screen-chip mono">Jaigaon ICP (WB/Bhutan)</span>
                <span className="screen-chip mono">Sonauli ICP (UP/Nepal)</span>
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div className="stat-note">Multi-Checkpoint Recidivism Engine</div>
              <strong style={{ color: "var(--seal)", fontFamily: "var(--font-mono)", fontSize: 13 }}>
                ACTIVE GRAPH LINKING
              </strong>
            </div>
          </div>
          <p className="stat-note" style={{ fontSize: 12, margin: 0 }}>
            The system flags <strong>Identity Clashes</strong> (same passport number presented under
            different traveler identities), <strong>Sector Bursts</strong> (coordinated multi-person
            crossings within short time windows), and <strong>Forged Specimen Reuse</strong> across
            remote border posts without transmitting sensitive passenger PII.
          </p>
        </div>
      </section>

      {/* ------------------------------------------------ Secondary Verifier (Provenance Ledger) */}
      <section className="section section--rule" id="ledger">
        <div className="section__head rv">
          <div>
            <Kicker>Evidentiary Audit Trail</Kicker>
            <h2>Cryptographic Ledger &amp; Public Verification</h2>
          </div>
          <p>
            Official documents issued with digital signatures can be verified against the immutable
            cryptographic registry. Zero raw document retention ensures full privacy compliance.
          </p>
        </div>

        <div className="verify-duo rv rv--d1">
          <VerifyPanel />
          <NoticeBoard />
        </div>
      </section>
    </div>
  );
}