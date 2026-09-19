"""
DigiLocker issued-document verification provider (NeGD / MeitY).

DigiLocker is the consent-based route to authentic government-issued
documents: the holder approves on DigiLocker (OTP / login), the registered
Requester app exchanges the authorization code for an OAuth token, and the
Pull API returns issuer-signed documents (Aadhaar XML, PAN, DL, RC, EPIC...).
No scraping, no shared passwords — the holder's consent IS the credential.

Credential-less builds get a deterministic mock with the SAME response shape
(sample_data True, loudly labeled). Set the env below and the provider goes
live; the report builder and UI never branch on which backend answered.

Env contract:
    DIGILOCKER_CLIENT_ID       required to activate live mode
    DIGILOCKER_CLIENT_SECRET   required to activate live mode
    DIGILOCKER_REDIRECT_URI    where DigiLocker returns the holder after consent
    DIGILOCKER_TOKEN_URL       (default: .../public/oauth2/1/token)
    DIGILOCKER_API_BASE        (default: https://api.digilocker.gov.in)
    DIGILOCKER_FILES_PATH      pull path under API_BASE for issued documents
                               (default: /public/oauth2/2/files — match the
                               Requester API version you onboarded with)
    DIGILOCKER_TIMEOUT         request timeout in seconds (default 12)

Only digests and masks are ever stored or returned — the fetched document
bytes stay in memory for the single request, exactly like the Aadhaar QR
payload path.
"""

import os

import requests

from screening import norm, mask, sha256

TOKEN_PATH = "/public/oauth2/1/token"
FILES_PATH = "/public/oauth2/2/files"

# doctype -> (sample identifier, sample status). Names/addresses are always
# the mandated placeholder; digests use the same [:32] convention as identity.
_MOCK_DOCS = {
    "aadhaar": ("234512345670", "ISSUED"),
    "pan": ("ABCDP2234A", "ISSUED"),
    "driving_licence": ("KA0120201234567", "ISSUED"),
    "rc": ("KA01MJ1234", "ISSUED"),
    "voter_id": ("ABC1234567", "ISSUED"),
}

_DOCTYPE_LABELS = {
    "aadhaar": "Aadhaar XML",
    "pan": "PAN card",
    "driving_licence": "Driving licence",
    "rc": "Registration certificate",
    "voter_id": "Voter ID (EPIC)",
}


def _config() -> dict:
    base = os.getenv("DIGILOCKER_API_BASE", "https://api.digilocker.gov.in").rstrip("/")
    host = base.split("://", 1)[-1].split("/", 1)[0]
    return {
        "client_id": os.getenv("DIGILOCKER_CLIENT_ID", ""),
        "client_secret": os.getenv("DIGILOCKER_CLIENT_SECRET", ""),
        "redirect_uri": os.getenv("DIGILOCKER_REDIRECT_URI", ""),
        "token_url": os.getenv("DIGILOCKER_TOKEN_URL", base + TOKEN_PATH),
        "files_url": base + os.getenv("DIGILOCKER_FILES_PATH", FILES_PATH),
        "timeout": float(os.getenv("DIGILOCKER_TIMEOUT", "12") or 12),
        "provider_name": host,
    }


def configured() -> bool:
    cfg = _config()
    return bool(cfg["client_id"] and cfg["client_secret"])


def _mock_lookup(doctype: str, identifier: str, declared_name: str = "") -> dict:
    key = sha256(norm(identifier))
    label = _DOCTYPE_LABELS.get(doctype, doctype)
    base = {
        "source": "digilocker",
        "label": f"DigiLocker {label} (mock)",
        "masked_number": mask(identifier),
        "sample_data": True,
        "provider": "mock",
        "live": False,
    }
    sample_no, status = _MOCK_DOCS.get(doctype, ("", None))
    if sample_no and key == sha256(norm(sample_no)):
        match = sha256(declared_name)[:32] == sha256("[Aadhaar Redacted]")[:32] if declared_name else None
        return {**base, "registered": True, "status": status,
                "holder_match": match, "holder_label": "[Aadhaar Redacted]"}
    return {**base, "registered": False, "status": None,
            "reason": "No such issued document in the DigiLocker account."}


class DigilockerProvider:
    """Live HTTPS provider. All calls carry the holder's OAuth bearer token —
    there is no service-account backdoor; without holder consent nothing answers."""

    name = "live"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def auth_url(self, state: str = "nocap") -> str:
        """Where to send the holder's browser to start consent."""
        from urllib.parse import urlencode
        base = self.cfg["token_url"].rsplit("/1/token", 1)[0] + "/1/authorize"
        return base + "?" + urlencode({
            "response_type": "code",
            "client_id": self.cfg["client_id"],
            "redirect_uri": self.cfg["redirect_uri"],
            "state": state,
        })

    def exchange_code(self, code: str) -> dict:
        """Authorization code -> tokens. Returns {"access_token": ...} or {"error": ...}."""
        try:
            resp = requests.post(
                self.cfg["token_url"],
                data={"grant_type": "authorization_code", "code": code,
                      "client_id": self.cfg["client_id"],
                      "client_secret": self.cfg["client_secret"],
                      "redirect_uri": self.cfg["redirect_uri"]},
                timeout=self.cfg["timeout"])
            data = resp.json()
        except Exception as exc:
            return {"error": f"token exchange failed: {exc.__class__.__name__}"}
        if not data.get("access_token"):
            return {"error": data.get("error_description") or data.get("error") or "token denied"}
        return {"access_token": data["access_token"],
                "token_type": data.get("token_type", "Bearer"),
                "expires_in": data.get("expires_in")}

    def lookup(self, doctype: str, identifier: str, declared_name: str = "",
               access_token: str = "") -> dict:
        label = _DOCTYPE_LABELS.get(doctype, doctype)
        base = {
            "source": "digilocker",
            "label": f"DigiLocker {label}",
            "masked_number": mask(identifier),
            "sample_data": False,
            "provider": self.cfg["provider_name"],
            "live": True,
        }
        if not access_token:
            return {**base, "registered": None, "status": None,
                    "reason": ("Holder consent required — send the holder through "
                               "DigiLocker OAuth first, then retry with a token.")}
        try:
            resp = requests.get(
                self.cfg["files_url"],
                params={"doctype": doctype},
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.cfg["timeout"])
            payload = resp.json()
        except Exception as exc:
            return {**base, "registered": None, "status": None,
                    "reason": f"DigiLocker unreachable: {exc.__class__.__name__}"}
        docs = payload.get("documents") or payload.get("files") or []
        want = norm(identifier)
        for doc in docs:
            uri = str(doc.get("uri") or doc.get("id") or "")
            number = str(doc.get("number") or doc.get("docno") or "")
            if want and (want == norm(uri) or want == norm(number)):
                gov_name = doc.get("name") or doc.get("holder") or ""
                match = bool(declared_name and gov_name
                             and norm(declared_name) == norm(str(gov_name)))
                return {**base, "registered": True, "status": "ISSUED",
                        "holder_match": match if (declared_name and gov_name) else None,
                        "holder_label": "[Aadhaar Redacted]" if gov_name else None,
                        "uri": uri}
        return {**base, "registered": False, "status": None,
                "reason": "No such issued document in the holder's DigiLocker account."}


def digilocker_lookup(doctype: str, identifier: str, declared_name: str = "",
                      access_token: str = "") -> dict:
    """Cross-reference an issued document: live DigiLocker when configured,
    deterministic mock otherwise. Same shape from both paths."""
    cfg = _config()
    if not configured():
        return _mock_lookup(doctype, identifier, declared_name)
    return DigilockerProvider(cfg).lookup(doctype, identifier, declared_name, access_token)


def digilocker_coverage() -> dict:
    """Backend status for /api/identity/meta."""
    cfg = _config()
    if configured():
        return {"configured": True, "live": True, "provider": cfg["provider_name"],
                "mock": False, "doctypes": sorted(_MOCK_DOCS),
                "auth_url_ready": bool(cfg["redirect_uri"])}
    return {"configured": False, "live": False, "provider": "mock", "mock": True,
            "doctypes": sorted(_MOCK_DOCS), "auth_url_ready": False}
