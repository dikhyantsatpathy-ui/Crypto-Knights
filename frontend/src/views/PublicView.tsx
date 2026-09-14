// ============================================================================
// PublicView — the front page. Hero, live ledger stats, the verifier, the
// bulletin board, and the three-pillar explainer of how nocap works.
// ============================================================================

import { useEffect, useState } from "react";
import { getStats } from "../api";
import { CountUp, IconDoc, IconHash, IconLayers, IconShield, Kicker } from "../components/ui";
import { VerifyPanel } from "../components/VerifyPanel";
import { NoticeBoard } from "../components/NoticeBoard";

export function PublicView() {
  const [stats, setStats] = useState<{ signed_docs: number; trusted_issuers: number } | null>(null);

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
    <>
      {/* ------------------------------------------------------- hero */}
      <section className="hero">
        <div className="hero__kicker">
          <span className="dot" aria-hidden="true" /> Live provenance ledger — check before you share
        </div>
        <h1>
          The time to doubt is <em>before</em> you forward.
        </h1>
        <p className="hero__lede">
          nocap is a public record of who signed what. Institutions sign official
          files with a cryptographic identity; you paste or drop any file and get a
          stamped verdict in under a second — real, forged, revoked, or unofficial.
        </p>

        <div className="hero__stats" aria-label="Ledger statistics">
          <div className="stat-plate">
            <span className="stat-plate__icon">
              <IconDoc size={20} />
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
              <IconShield size={20} />
            </span>
            <div>
              <div className="stat-plate__num">
                <CountUp target={stats?.trusted_issuers ?? 0} />
              </div>
              <div className="stat-plate__label">Trusted issuers</div>
            </div>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------- verifier */}
      <section className="section" style={{ borderTop: "1px solid var(--line)" }}>
        <VerifyPanel />
      </section>

      {/* ------------------------------------------------------- bulletin */}
      <NoticeBoard />

      {/* ------------------------------------------------------- pillars */}
      <section className="section" style={{ borderTop: "1px solid var(--line)" }}>
        <div className="section__head">
          <div>
            <Kicker>How the record works</Kicker>
            <h2>Three layers, one trust chain</h2>
          </div>
          <p>Sign, anchor, verify — each step leaves a public, replayable trace.</p>
        </div>
        <div className="grid-3">
          <div className="pillar">
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
          <div className="pillar">
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
          <div className="pillar">
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
      </section>
    </>
  );
}