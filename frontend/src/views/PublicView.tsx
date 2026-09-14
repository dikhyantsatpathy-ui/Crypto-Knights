// ============================================================================
// PublicView — the front page as a scroll-scrubbed video.
// Scene 1 (hero), Scene 2 (verifier), Scene 3 (how it works). Each scene is a
// `.scrolly-section` with scroll room; its `.scrolly-stage` sticks to the
// viewport and `useScrolly` writes the scene's progress into `--p`. `.sc-enter`
// children fade/rise in as `--p` grows and dissolve as it approaches 1 — so
// scrolling down plays the scene forward and scrolling up rewinds it, like
// scrubbing a timeline instead of flipping slides.
// ============================================================================

import { useEffect, useRef, useState } from "react";
import { getStats } from "../api";
import { useScrolly } from "../app/motion";
import { CountUp, IconDoc, IconHash, IconLayers, IconShield, Kicker } from "../components/ui";
import { VerifyPanel } from "../components/VerifyPanel";
import { NoticeBoard } from "../components/NoticeBoard";

// Smooth-scroll to a scene, landing just past its fade-in so the target
// content is already on screen (the scene then plays on as you scroll).
const scrollTo = (id: string) => {
  const el = document.getElementById(id);
  if (!el) return;
  const top = el.getBoundingClientRect().top + window.scrollY + window.innerHeight * 0.3;
  window.scrollTo({ top, behavior: "smooth" });
};

export function PublicView() {
  const [stats, setStats] = useState<{ signed_docs: number; trusted_issuers: number } | null>(null);
  const deckRef = useRef<HTMLDivElement>(null);
  useScrolly(deckRef);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const res = await getStats();
      if (res.ok && alive) setStats(res.data);
    };
    void load();
    const t = window.setInterval(load, 90_000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);

  return (
    <div className="scrolly" ref={deckRef}>
      {/* -------------------------------------------------- scene 1 · hero */}
      <div className="scrolly-section" id="top">
        <div className="scrolly-stage scrolly-stage--hero scrolly-stage--intro">
          <div className="sc-cam">
            <div className="hero__grid">
            <div className="hero__main">
              <div className="hero__kicker sc-enter sc-enter-1">
                <span className="dot" aria-hidden="true" /> Live provenance ledger — check before you share
              </div>
              <h1 className="sc-enter sc-enter-1">
                The time to doubt is <em>before</em> you forward.
              </h1>
              <p className="hero__lede sc-enter sc-enter-2">
                nocap is a public record of who signed what. Institutions sign official
                files with a cryptographic identity; you paste or drop any file and get a
                stamped verdict in under a second — real, forged, revoked, or unofficial.
              </p>

              <div className="hero__cta sc-enter sc-enter-3">
                <button className="btn btn--seal btn--lg" onClick={() => scrollTo("verify")}>
                  Verify a file
                </button>
                <button className="btn btn--ghost btn--lg" onClick={() => scrollTo("how")}>
                  How it works
                </button>
              </div>

              <div className="hero__stats sc-enter sc-enter-4" aria-label="Ledger statistics">
                <div className="stat-plate">
                  <span className="stat-plate__icon">
                    <IconDoc size={22} />
                  </span>
                  <div>
                    <div className="stat-plate__num">
                      <CountUp target={stats?.signed_docs ?? 0} />
                    </div>
                    <div className="stat-plate__label">Signed documents</div>
                  </div>
                </div>
                <div className="stat-plate">
                  <span className="stat-plate__icon stat-plate__icon--amber">
                    <IconShield size={22} />
                  </span>
                  <div>
                    <div className="stat-plate__num">
                      <CountUp target={stats?.trusted_issuers ?? 0} />
                    </div>
                    <div className="stat-plate__label">Trusted issuers</div>
                  </div>
                </div>
              </div>

              <div className="hero__meta sc-enter sc-enter-5" aria-hidden="true">
                <span>SHA-256 fingerprints</span>
                <span>blockchain-anchored</span>
                <span>open, replayable record</span>
              </div>
            </div>

            <aside className="hero__rail sc-enter sc-enter-2">
              <NoticeBoard />
            </aside>
            </div>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------ scene 2 · verifier */}
      <div className="scrolly-section" id="verify">
        <div className="scrolly-stage scrolly-stage--verify">
          <div className="sc-cam">
            <div className="sc-enter sc-enter-1 verify-wrap">
              <VerifyPanel />
            </div>
          </div>
        </div>
      </div>

      {/* --------------------------------------------- scene 3 · how it works */}
      <div className="scrolly-section" id="how">
        <div className="scrolly-stage scrolly-stage--how">
          <div className="sc-cam">
            <div className="how-wrap">
              <div className="section__head sc-enter sc-enter-1">
                <div>
                  <Kicker>How the record works</Kicker>
                  <h2>Three layers, one trust chain</h2>
                </div>
                <p>Sign, anchor, verify — each step leaves a public, replayable trace.</p>
              </div>
              <div className="grid-3">
                <div className="pillar sc-enter sc-enter-2">
                  <div className="pillar__num">
                    <span>01</span>
                    <IconHash size={15} />
                  </div>
                  <div className="pillar__title">The digest</div>
                  <p className="pillar__desc">
                    Every official file is reduced to a SHA-256 fingerprint. The
                    fingerprint is what gets signed — the file itself never lives on the
                    ledger, so nothing sensitive is ever stored here.
                  </p>
                </div>
                <div className="pillar sc-enter sc-enter-3">
                  <div className="pillar__num">
                    <span>02</span>
                    <IconShield size={15} />
                  </div>
                  <div className="pillar__title">The signature</div>
                  <p className="pillar__desc">
                    A real institution — its identity verified and its role assigned by a
                    super administrator, not self-claimed — binds its key to the digest
                    and stamps it onto the bulletin board.
                  </p>
                </div>
                <div className="pillar sc-enter sc-enter-4">
                  <div className="pillar__num">
                    <span>03</span>
                    <IconLayers size={15} />
                  </div>
                  <div className="pillar__title">The chain</div>
                  <p className="pillar__desc">
                    Each signature lands in an ordered ledger and is anchored to a public
                    blockchain transaction. Retractions leave the record intact — they
                    only mark it revoked.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}