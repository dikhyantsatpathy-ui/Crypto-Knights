"""
Cross-Border Syndicate & Recidivism Graph Analytics (SIH26188).
Connects screening reports across border outposts (SSB Checkpoints: Raxaul,
Panitanki, Jogbani, Jaigaon, etc.) to detect organized document fraud rings:

1. Duplicate Identifier, Divergent Locations (Impossible Travel / Re-use)
2. Identity Clashing (Same doc number, contradictory names or DOBs)
3. Checkpoint Burst Alert (Surge of suspicious screenings in a localized sector)
"""

from datetime import datetime, timezone, timedelta
from typing import Any


def analyze_syndicate_patterns(
    current_doc: dict[str, Any],
    recent_reports: list[dict[str, Any]],
    burst_window_minutes: int = 60,
) -> dict[str, Any]:
    """Analyze current screening against recent historical passes for syndicate fraud.

    current_doc: {
        "file_hash": str,
        "checkpoint": str,
        "doc_number": str | None,
        "name": str | None,
        "dob": str | None,
        "verdict": str,
        "risk_score": int,
    }
    recent_reports: list of past report dicts (from DB or memory).
    """
    alerts = []
    syndicate_risk_bump = 0

    curr_cp = (current_doc.get("checkpoint") or "Border Checkpoint").strip()
    curr_doc_no = (current_doc.get("doc_number") or "").strip().upper()
    curr_name = (current_doc.get("name") or "").strip().upper()
    curr_dob = (current_doc.get("dob") or "").strip()

    now = datetime.now(timezone.utc)

    # 1. Check for Duplicate Identifier & Cross-Border Recidivism
    if curr_doc_no and len(curr_doc_no) >= 5:
        matches = [
            r for r in recent_reports
            if (r.get("doc_number") or "").strip().upper() == curr_doc_no
            and r.get("file_hash") != current_doc.get("file_hash")
        ]

        for m in matches:
            prev_cp = (m.get("checkpoint") or "Unknown Checkpoint").strip()
            prev_name = (m.get("name") or "").strip().upper()
            prev_dob = (m.get("dob") or "").strip()
            prev_verdict = m.get("verdict")
            prev_time_str = m.get("created_at") or ""
            time_suffix = f" on {prev_time_str[:10]}" if prev_time_str else ""

            # Check for conflicting identities under the same document number
            if curr_name and prev_name and curr_name != prev_name:
                alerts.append({
                    "level": "CRITICAL",
                    "type": "IDENTITY_CLASH",
                    "title": "Conflicting Name on Document Number",
                    "detail": (
                        f"Document number '{curr_doc_no}' was previously presented as '{prev_name}'{time_suffix} "
                        f"at {prev_cp}, now presented as '{curr_name}'. Counterfeit book suspected."
                    ),
                    "checkpoint": curr_cp,
                })
                syndicate_risk_bump += 35

            if curr_dob and prev_dob and curr_dob != prev_dob:
                alerts.append({
                    "level": "CRITICAL",
                    "type": "IDENTITY_CLASH",
                    "title": "Conflicting Date of Birth on Document Number",
                    "detail": (
                        f"Document number '{curr_doc_no}' was previously logged with DOB '{prev_dob}'{time_suffix} "
                        f"at {prev_cp}, now presented with DOB '{curr_dob}'. Forged biodata page suspected."
                    ),
                    "checkpoint": curr_cp,
                })
                syndicate_risk_bump += 35

            # Cross-checkpoint presentation
            if prev_cp and curr_cp and prev_cp != curr_cp:
                alerts.append({
                    "level": "HIGH",
                    "type": "CROSS_CHECKPOINT_REPRESENTATION",
                    "title": "Cross-Border Recidivism Detected",
                    "detail": (
                        f"Document '{curr_doc_no}' previously logged at {prev_cp}{time_suffix} "
                        f"(verdict: {prev_verdict}) has reappeared at {curr_cp}."
                    ),
                    "checkpoint": curr_cp,
                })
                syndicate_risk_bump += 25
            elif prev_verdict in ("FLAGGED", "REVIEW"):
                alerts.append({
                    "level": "HIGH",
                    "type": "PREVIOUSLY_FLAGGED_IDENTIFIER",
                    "title": "Previously Flagged Identifier",
                    "detail": (
                        f"Document '{curr_doc_no}' was flagged ({prev_verdict}) in past screening "
                        f"at {prev_cp}."
                    ),
                    "checkpoint": curr_cp,
                })
                syndicate_risk_bump += 20

    # 2. Checkpoint Burst Alert: Surge of suspicious screenings in localized sector
    window_start = now - timedelta(minutes=burst_window_minutes)
    recent_suspicious = 0
    for r in recent_reports:
        r_cp = (r.get("checkpoint") or "").strip()
        if r_cp == curr_cp and r.get("verdict") in ("FLAGGED", "REVIEW"):
            # Check timestamp if parseable
            ts_str = r.get("created_at")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts >= window_start:
                        recent_suspicious += 1
                except Exception:
                    recent_suspicious += 1
            else:
                recent_suspicious += 1

    if current_doc.get("verdict") in ("FLAGGED", "REVIEW"):
        recent_suspicious += 1

    if recent_suspicious >= 3:
        alerts.append({
            "level": "WARNING",
            "type": "SECTOR_BURST_ALERT",
            "title": f"Suspicious Activity Burst at {curr_cp}",
            "detail": (
                f"{recent_suspicious} flagged/review identity screenings detected at {curr_cp} "
                f"within the last {burst_window_minutes} minutes. Elevated risk posture active."
            ),
            "checkpoint": curr_cp,
        })
        syndicate_risk_bump += 10

    return {
        "alerts": alerts,
        "syndicate_risk_bump": syndicate_risk_bump,
        "has_alerts": len(alerts) > 0,
        "active_sector_alerts": [a for a in alerts if a["type"] == "SECTOR_BURST_ALERT"],
    }
