# Real Registry Verification Adapters

`app/verification_providers.py` turns the identity registry cross-reference from
100% mock into a provider-selected lookup: every registry ships a deterministic
**mock** fallback AND an env-configured **live HTTP** adapter. One registry can
go live while the rest stay mock — and the report builder, the `/api/identity/*`
routes, the frontend cards and the existing tests never change shape.

## How it works

To bring a registry online, set `IDV_<REGKEY>_URL` in `.env`. That's it — no
code change. Example:

```env
IDV_PAN_NSDL_URL=https://api.sandbox.example/pan/v2/verify
IDV_PAN_NSDL_TOKEN=<sandbox token>
IDV_PAN_NSDL_RESP_NAME=data.holder_name
IDV_PAN_NSDL_REQUEST_EXTRA={"partner_id":"you-123"}
```

The adapter POSTs JSON `{ "number": "...", "name": "[Aadhaar Redacted]" }`
(field names overridable via `IDV_<REGKEY>_NUMBER_FIELD` / `_NAME_FIELD`,
extra body via `_REQUEST_EXTRA`) with `Authorization: Bearer <token>`, and maps
the response back through dotted paths (`IDV_<REGKEY>_RESP_*`). If the backend
never answers, the lookup returns `registered: null` + a reason so the UI shows
"no verdict — verify with the issuing authority" instead of guessing.

| Env var | Meaning | Default |
|---|---|---|
| `IDV_<REGKEY>_URL` | activates live mode for that registry | (none ⇒ mock) |
| `IDV_<REGKEY>_TOKEN` / `IDV_TOKEN` | bearer token | — |
| `IDV_<REGKEY>_NUMBER_FIELD` / `_NAME_FIELD` | request body keys | `number` / `name` |
| `IDV_<REGKEY>_REQUEST_EXTRA` | extra JSON body merged in | — |
| `IDV_<REGKEY>_RESP_EXISTS` | dotted path to record-exists bool | `exists` |
| `IDV_<REGKEY>_RESP_STATUS` | dotted path to status string | `status` |
| `IDV_<REGKEY>_RESP_NAME` | dotted path to DB holder name | `name` |
| `IDV_AUTH_HEADER` / `IDV_AUTH_SCHEME` / `IDV_TIMEOUT` | global HTTP knobs | `Authorization` / `Bearer` / 12 |

Registry keys: `PAN_NSDL`, `DL_PARIVAHAN`, `RC_VAHAN`, `EPIC_EC`,
`PASSPORT_REGISTRY`. Coverage is surfaced live at
`GET /api/identity/meta`.

## On-boarding checklist (per agency)

Real access to a government verification database is *licensing*, not code.
Acquiring the credential is the project — the adapter is already built.

- **PAN**: NSDL / Protean partner API. Licensed verifiers only; sandboxes from
  Setu, Eko and InPrANet exist for a hackathon demo. Expect SOAP/XML or a
  partner JSON contract — adapt via the `IDV_*_REQUEST_EXTRA` / `*_RESP_*`
  knobs or a thin wrapper that translates the vendor body.
- **Driving licence**: Parivahan / SARATHI API, sidecar OCR + keyed number.
  Partner licensing via NIC/Ministry of Road Transport (MoRTH).
- **RC**: Vahan API, same MoRTH partner program.
- **EPIC**: Election Commission of India voter dataset — no public API; the
  national electoral roll is accessed by recognized entities only.
- **Passport**: Passport Seva (MHA) — issued-passenger verification is for
  registered users; the lost/stolen list is internal NIA/PSK data.
- **Aadhaar**: already REAL in this codebase without any of the above — the
  offline SecureQR signature is RSA-SHA1 verified locally against the UIDAI
  public key (`UIDAI_AADHAAR_PUBKEY_PEM`), with zero storage. Online "KUA/AUA"
  verification requires a System/Sub-AUA license under the Aadhaar Act.

## Zero-storage rules that survive going live

- Store only `sha256(norm(value))[:32]` digests and masked tails; sample data
  uses the `[Aadhaar Redacted]` placeholder.
- Never cache the raw number, name or photo. Provider instances are built per
  lookup from env precisely so credentials can rotate without restarts and so
  nothing sensitive persists between requests.
- The mock path is deliberate: a build with NO `IDV_*_URL` is honest about
  being sample data in the UI, rather than dressing fake data up as official.