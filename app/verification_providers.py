"""
Real registry verification adapters with a reproducible mock fallback.

identity.py's registry cross-reference used to be 100% mock. This module keeps
the same lookup CONTRACT but routes through a configurable provider:

  * IDV_<REGKEY>_URL is set  -> a live HTTP adapter to the government / partner
    verification endpoint (NSDL-backed PAN, Parivahan-Sarathi DL, Vahan RC,
    Election-Commission EPIC, Passport Seva), configured PURELY FROM ENV so no
    vendor SDK and no guessed schema gets baked into the codebase.
  * otherwise               -> the deterministic mock seeded with demo samples.

Both paths return an identical JSON shape, so the report builder, the frontend
and the existing tests run unchanged. Only `sample_data` flips to False for a
live provider and `provider` names the backend actually used. A live registry
that fails to answer returns `registered: None` with an honest `reason` — the
report builder turns that into a "needs human review" check, never a silent
pass and never a false fail.

Production wiring is contractual, not code: each agency licenses different
partners (See §"on boarding" in docs). A sandbox key from a partner such as
Setu/InPrANet or a DigiLocker-based flow is enough for a hackathon demo.

Env contract (REGKEY is PAN_NSDL / DL_PARIVAHAN / RC_VAHAN / EPIC_EC /
PASSPORT_REGISTRY):

    IDV_<REGKEY>_URL           required to activate live mode
    IDV_<REGKEY>_TOKEN         bearer token (falls back to IDV_TOKEN)
    IDV_<REGKEY>_NUMBER_FIELD  JSON request-body key for the number (default "number")
    IDV_<REGKEY>_NAME_FIELD    JSON request-body key for the declared name (default "name")
    IDV_<REGKEY>_REQUEST_EXTRA extra JSON body fields merged into the request
    IDV_<REGKEY>_RESP_EXISTS   dotted path to boolean "record exists" (default "exists")
    IDV_<REGKEY>_RESP_STATUS   dotted path to status string (default "status")
    IDV_<REGKEY>_RESP_NAME     dotted path to the holder name the DB holds (default "name")
    IDV_AUTH_HEADER            (default "Authorization")
    IDV_AUTH_SCHEME            (default "Bearer")
    IDV_TIMEOUT                request timeout in seconds (default 12)
"""

import json
import os

import requests

from screening import norm, mask, sha256

# --------------------------------------------------------------------------- #
# Mock registry seeds (reproducible stand-ins for the demo / unlicensed builds)
# --------------------------------------------------------------------------- #

def _pan_check_char(first9: str) -> str:
    """The community PAN trailing-letter rule (used in several open-source
    validators). It is NOT authoritative — NSDL never published the formula —
    so callers treat it as a consistency hint, never a hard pass/fail."""
    total = 0
    for ch in first9:
        total += int(ch) if ch.isdigit() else ord(ch) - 55
    rem = total % 36
    return str(rem) if rem < 10 else chr(rem + 55)


def _seed(name: str, status: str) -> dict:
    """One registry row: keyed by the SHA-256 of the normalized number, storing
    only a digest of the holder name (sample data uses the mandated placeholder)
    plus a public status. No raw PII anywhere. The digest is truncated to 32 hex
    chars — the same convention the Aadhaar parse uses, so name comparisons are
    apples-to-apples."""
    return {"name_sha256": sha256(name)[:32], "holder_label": "[Aadhaar Redacted]", "status": status}


def _registry(rows: list, extra_sample: str, extra_status: str) -> dict:
    d = {}
    for number, name, status in rows:
        d[sha256(number)] = _seed(name, status)
    # Guarantee at least one REPORTED (lost/stolen) sample per registry so the
    # demo can exercise the danger path without knowing a real victim's number.
    d[sha256(extra_sample)] = _seed("[Aadhaar Redacted]", extra_status)
    return d


# Sample identifiers — every name/address literal is the mandated placeholder.
_SAMPLE_PAN = "ABCDP2234" + _pan_check_char("ABCDP2234")  # trailing char stays a letter
_SAMPLE_DL = "KA0120201234567"
_SAMPLE_RC = "KA01MJ1234"
_SAMPLE_EPIC = "ABC1234567"
_SAMPLE_AADHAAR = "234512345670"

_REGISTRIES = {
    "pan_nsdl": _registry(
        [(_SAMPLE_PAN, "[Aadhaar Redacted]", "ACTIVE")],
        "ZZZPM9999Z", "REPORTED",
    ),
    "dl_parivahan": _registry(
        [(_SAMPLE_DL, "[Aadhaar Redacted]", "ACTIVE")],
        "XX0199999999999", "REPORTED",
    ),
    "rc_vahan": _registry(
        [(_SAMPLE_RC, "[Aadhaar Redacted]", "ACTIVE")],
        "XX0000000000", "REPORTED",
    ),
    "epic_ec": _registry(
        [(_SAMPLE_EPIC, "[Aadhaar Redacted]", "ACTIVE")],
        "ZZZ9999999", "INACTIVE",
    ),
    "passport_registry": _registry(
        [], "[Aadhaar Redacted]", "REPORTED",  # lost/stolen LIST: absence is good news
    ),
}

_REGISTRY_LABELS = {
    "pan_nsdl": "NSDL / Protean PAN",
    "dl_parivahan": "Parivahan SARATHI DL",
    "rc_vahan": "Vahan RC",
    "epic_ec": "Election Commission EPIC",
    "passport_registry": "Passport Seva lost/stolen",
}

# What absence means: membership registries expect the number to EXIST;
# a lost/stolen list expects it to NOT exist.
MEMBERSHIP_REGISTRIES = {"pan_nsdl", "dl_parivahan", "rc_vahan", "epic_ec"}
LOST_OR_STOLEN_REGISTRIES = {"passport_registry"}

GUARD_LOOKUP_FIELDS = {"pan": "pan_nsdl", "driving_licence": "dl_parivahan",
                       "rc": "rc_vahan", "voter_id": "epic_ec", "passport": "passport_registry"}


# --------------------------------------------------------------------------- #
# Provider protocol + mocks
# --------------------------------------------------------------------------- #

class MockProvider:
    """Deterministic sample registry. `sample_data: True` so the UI and report
    loudly label it as demo data rather than presenting it as official."""

    name = "mock"

    def lookup(self, registry: str, number: str, declared_name: str = "") -> dict:
        key = sha256(norm(number))
        row = _REGISTRIES.get(registry, {}).get(key)
        base = {
            "label": _REGISTRY_LABELS.get(registry, registry) + " (mock)",
            "sample_data": True,
            "provider": self.name,
            "live": False,
        }
        if not row or not number:
            gone = registry in LOST_OR_STOLEN_REGISTRIES
            return {
                **base,
                "registry": registry,
                "masked_number": mask(number),
                "registered": False,
                "lost_or_stolen": True if gone else None,
                "status": None,
                "reason": ("Not flagged in the lost/stolen sample registry."
                           if gone else "No active record for this number in the registry."),
            }
        match = sha256(declared_name)[:32] == row["name_sha256"] if declared_name else None
        return {
            **base,
            "registry": registry,
            "masked_number": mask(number),
            "registered": True,
            "status": row["status"],
            "holder_match": match,
            "holder_label": row["holder_label"],
        }


def _dot(data, path: str):
    """Walk a dotted path ('data.full_name', 'response[0].name') through dicts/lists."""
    cur = data
    for part in str(path or "").split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


class HttpRegistryProvider:
    """Environment-configured HTTP adapter. Sends {number, name} JSON (field
    names overridable per registry) to IDV_<REGKEY>_URL and maps the response
    back into the registry shape — no vendor schema hard-coded."""

    name = "live"

    def __init__(self, registry: str, cfg: dict):
        self.registry = registry
        self.cfg = cfg
        self._label = _REGISTRY_LABELS.get(registry, registry)

    def lookup(self, registry: str, number: str, declared_name: str = "") -> dict:
        cfg = self.cfg
        body = {cfg["number_field"]: number}
        if declared_name:
            body[cfg["name_field"]] = declared_name
        if cfg.get("extra"):
            try:
                extra = json.loads(cfg["extra"])
                if isinstance(extra, dict):
                    body.update(extra)
            except Exception:
                pass

        headers = {"Content-Type": "application/json"}
        if cfg.get("token"):
            headers.setdefault(cfg["auth_header"], f'{cfg["auth_scheme"]} {cfg["token"]}'.strip())

        base = {
            "registry": registry,
            "label": self._label,
            "masked_number": mask(number),
            "sample_data": False,
            "provider": cfg["provider_name"],
            "live": True,
        }
        try:
            resp = requests.post(cfg["url"], json=body, headers=headers, timeout=cfg["timeout"])
            payload = resp.json()
        except Exception as exc:
            return {**base, "registered": None, "lost_or_stolen": None, "status": None,
                    "reason": f"live registry unreachable: {exc.__class__.__name__}"}

        exists = _dot(payload, cfg["resp_exists"])
        status = _dot(payload, cfg["resp_status"])
        gov_name = _dot(payload, cfg["resp_name"])
        hub_status_ok = 200 <= resp.status_code < 300
        registered = bool(exists) if isinstance(exists, (bool, int)) else bool(hub_status_ok and (status or len(status or "") > 0))

        match = bool(declared_name and gov_name and norm(declared_name) == norm(str(gov_name)))
        if registered:
            return {
                **base,
                "registered": True,
                "lost_or_stolen": None,
                "status": str(status) if status else "ACTIVE",
                "holder_match": match if (declared_name and gov_name) else None,
                "holder_label": "[Aadhaar Redacted]" if gov_name else None,
            }
        gone = registry in LOST_OR_STOLEN_REGISTRIES
        return {
            **base,
            "registered": False,
            "lost_or_stolen": True if gone else None,
            "status": None,
            "reason": ("Not found on the signed lost/stolen list."
                       if gone else "No active record returned by the registry."),
        }


# --------------------------------------------------------------------------- #
# Resolution + public API
# --------------------------------------------------------------------------- #

def _host_from_url(url: str) -> str:
    try:
        return url.split("://", 1)[1].split("/", 1)[0]
    except Exception:
        return url


def _config_for(registry: str) -> dict:
    """Read the env contract for one registry — always returns a full dict, so
    a missing URL simply means 'stay on mock'."""
    key = registry.upper().replace("-", "_")
    def get(name, default=""):
        return os.getenv(name, default)

    url = get(f"IDV_{key}_URL")
    return {
        "url": url,
        "token": get(f"IDV_{key}_TOKEN", get("IDV_TOKEN")),
        "auth_header": get("IDV_AUTH_HEADER", "Authorization"),
        "auth_scheme": get("IDV_AUTH_SCHEME", "Bearer"),
        "number_field": get(f"IDV_{key}_NUMBER_FIELD", "number"),
        "name_field": get(f"IDV_{key}_NAME_FIELD", "name"),
        "extra": get(f"IDV_{key}_REQUEST_EXTRA"),
        "resp_exists": get(f"IDV_{key}_RESP_EXISTS", "exists"),
        "resp_status": get(f"IDV_{key}_RESP_STATUS", "status"),
        "resp_name": get(f"IDV_{key}_RESP_NAME", "name"),
        "timeout": float(get("IDV_TIMEOUT", "12") or 12),
        "provider_name": _host_from_url(url) if url else "mock",
    }


def get_provider(registry: str):
    """Pick the provider for one registry: live HTTP when configured, mock else."""
    cfg = _config_for(registry)
    return HttpRegistryProvider(registry, cfg) if cfg["url"] else MockProvider()


def registry_lookup(registry: str, number: str, declared_name: str = "") -> dict:
    """Cross-reference a number through whichever provider is configured for the
    registry. Same shape from mock and live paths; callers never branch."""
    return get_provider(registry).lookup(registry, number, declared_name)


def registries_coverage() -> list:
    """Which backend each registry is using right now (for /api/identity/meta)."""
    out = []
    for key, label in _REGISTRY_LABELS.items():
        cfg = _config_for(key)
        if cfg["url"]:
            out.append({"key": key, "label": label, "mock": False, "live": True,
                        "provider": cfg["provider_name"], "sample_rows": len(_REGISTRIES.get(key, {}))})
        else:
            out.append({"key": key, "label": label, "mock": True, "live": False,
                        "provider": "mock", "sample_rows": len(_REGISTRIES.get(key, {}))})
    return out