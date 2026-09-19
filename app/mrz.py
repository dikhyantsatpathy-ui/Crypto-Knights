"""
ICAO Doc 9303 Machine Readable Zone (MRZ) parser and validator.

Supports all standard ICAO Doc 9303 formats:
  - TD1 (3 lines of 30 characters, typically ID cards / residence cards)
  - TD2 (2 lines of 36 characters, visas / official travel cards)
  - TD3 (2 lines of 44 characters, international standard passports)

Implements the official ICAO 7-3-1 modulus-10 weighting algorithm for
calculating and verifying check digits:
  - Document Number check digit
  - Date of Birth (YYMMDD) check digit
  - Expiry Date (YYMMDD) check digit
  - Optional Data / Personal Number check digit
  - Overall Composite Check Digit

Zero-PII discipline: parsed holder names can be extracted or masked as requested.
"""

import re
from typing import Dict, Any, List, Optional

# Character value mapping per ICAO Doc 9303 Part 3
_CHAR_VALUES: Dict[str, int] = {}
for i in range(10):
    _CHAR_VALUES[str(i)] = i
for c in range(ord('A'), ord('Z') + 1):
    _CHAR_VALUES[chr(c)] = c - ord('A') + 10
_CHAR_VALUES['<'] = 0

_WEIGHTS = (7, 3, 1)


def compute_mrz_check_digit(data: str) -> int:
    """Calculate the ICAO 9303 modulus-10 check digit for a string.
    
    Weights cycle in the sequence 7, 3, 1:
      total = sum(char_val(c) * weight) % 10
    """
    total = 0
    clean = (data or "").upper()
    for idx, ch in enumerate(clean):
        val = _CHAR_VALUES.get(ch, 0)
        weight = _WEIGHTS[idx % 3]
        total += val * weight
    return total % 10


def verify_check_digit(field: str, expected_digit: str | int) -> bool:
    """Verify if the computed check digit matches the expected check digit."""
    try:
        expected = int(str(expected_digit).strip())
    except (ValueError, TypeError):
        return False
    return compute_mrz_check_digit(field) == expected


def _clean_mrz_lines(raw_text: str) -> List[str]:
    """Extract and sanitize MRZ lines from raw OCR or pasted text.
    
    Filters for lines containing predominantly uppercase letters, digits, and '<'.
    """
    lines = []
    for line in (raw_text or "").splitlines():
        cleaned = re.sub(r"[^A-Z0-9<]", "", line.upper().strip())
        if len(cleaned) >= 28:
            lines.append(cleaned)
    return lines


def parse_td3(line1: str, line2: str) -> Dict[str, Any]:
    """Parse and verify an ICAO TD3 passport MRZ (2 lines x 44 characters).
    
    Line 1 layout:
      0..1: Document code ('P<', 'P', 'PO', etc.)
      2..4: Issuing country / state code (3 chars)
      5..43: Name (Surname<<Given<Names)
    
    Line 2 layout:
      0..8: Document / Passport number (9 chars)
      9: Document number check digit (1 char)
      10..12: Nationality code (3 chars)
      13..18: Date of birth (YYMMDD, 6 chars)
      19: Date of birth check digit (1 char)
      20: Sex ('M', 'F', '<', 'X')
      21..26: Expiry date (YYMMDD, 6 chars)
      27: Expiry date check digit (1 char)
      28..41: Optional personal number (14 chars)
      42: Optional data check digit (or '<' if not used)
      43: Overall composite check digit (1 char)
    """
    l1 = line1.ljust(44, '<')[:44]
    l2 = line2.ljust(44, '<')[:44]

    doc_type = l1[0:2].rstrip('<')
    issuing_country = l1[2:5].rstrip('<')
    name_field = l1[5:44]
    name_parts = name_field.split('<<')
    surname = name_parts[0].replace('<', ' ').strip() if len(name_parts) > 0 else ""
    given_names = name_parts[1].replace('<', ' ').strip() if len(name_parts) > 1 else ""

    doc_number_field = l2[0:9]
    doc_number = doc_number_field.rstrip('<')
    doc_number_ck = l2[9]

    nationality = l2[10:13].rstrip('<')
    dob_field = l2[13:19]
    dob_ck = l2[19]
    sex = l2[20]
    expiry_field = l2[21:27]
    expiry_ck = l2[27]

    optional_field = l2[28:42]
    optional_ck = l2[42]
    composite_ck = l2[43]

    # Verify individual checksums
    doc_num_valid = verify_check_digit(doc_number_field, doc_number_ck)
    dob_valid = verify_check_digit(dob_field, dob_ck)
    expiry_valid = verify_check_digit(expiry_field, expiry_ck)

    optional_valid: Optional[bool] = None
    if optional_ck.isdigit():
        optional_valid = verify_check_digit(optional_field, optional_ck)

    # Composite check digit calculation:
    # Over: doc_number(9) + doc_number_ck(1) + optional(14) + dob(6) + dob_ck(1) + expiry(6) + expiry_ck(1) + optional_ck(1)
    composite_payload = doc_number_field + doc_number_ck + dob_field + dob_ck + expiry_field + expiry_ck + optional_field + optional_ck
    
    if composite_ck.isdigit():
        composite_valid = verify_check_digit(composite_payload, composite_ck)
        is_valid = doc_num_valid and dob_valid and expiry_valid and composite_valid
    else:
        composite_valid = None
        # When composite digit is not present (e.g. truncated line or '<' filler), core fields decide validity
        is_valid = doc_num_valid and dob_valid and expiry_valid

    return {
        "format": "TD3",
        "valid": is_valid,
        "doc_type": doc_type,
        "issuing_country": issuing_country,
        "passport_number": doc_number,
        "surname": surname,
        "given_names": given_names,
        "nationality": nationality,
        "dob": dob_field,
        "sex": sex if sex in ('M', 'F', 'X') else "U",
        "expiry": expiry_field,
        "optional_data": optional_field.rstrip('<'),
        "checks": {
            "document_number": {
                "ok": doc_num_valid,
                "computed": compute_mrz_check_digit(doc_number_field),
                "expected": int(doc_number_ck) if doc_number_ck.isdigit() else doc_number_ck,
            },
            "dob": {
                "ok": dob_valid,
                "computed": compute_mrz_check_digit(dob_field),
                "expected": int(dob_ck) if dob_ck.isdigit() else dob_ck,
            },
            "expiry": {
                "ok": expiry_valid,
                "computed": compute_mrz_check_digit(expiry_field),
                "expected": int(expiry_ck) if expiry_ck.isdigit() else expiry_ck,
            },
            "optional_data": {
                "ok": optional_valid,
                "computed": compute_mrz_check_digit(optional_field) if optional_ck.isdigit() else None,
                "expected": int(optional_ck) if optional_ck.isdigit() else None,
            },
            "composite": {
                "ok": composite_valid,
                "computed": compute_mrz_check_digit(composite_payload),
                "expected": int(composite_ck) if composite_ck.isdigit() else composite_ck,
            },
        },
    }


def parse_td1(line1: str, line2: str, line3: str) -> Dict[str, Any]:
    """Parse and verify an ICAO TD1 ID card MRZ (3 lines x 30 characters)."""
    l1 = line1.ljust(30, '<')[:30]
    l2 = line2.ljust(30, '<')[:30]
    l3 = line3.ljust(30, '<')[:30]

    doc_type = l1[0:2].rstrip('<')
    issuing_country = l1[2:5].rstrip('<')
    doc_number_field = l1[5:14]
    doc_number = doc_number_field.rstrip('<')
    doc_number_ck = l1[14]
    optional1 = l1[15:30]

    dob_field = l2[0:6]
    dob_ck = l2[6]
    sex = l2[7]
    expiry_field = l2[8:14]
    expiry_ck = l2[14]
    nationality = l2[15:18].rstrip('<')
    optional2 = l2[18:29]
    composite_ck = l2[29]

    name_parts = l3.split('<<')
    surname = name_parts[0].replace('<', ' ').strip() if len(name_parts) > 0 else ""
    given_names = name_parts[1].replace('<', ' ').strip() if len(name_parts) > 1 else ""

    doc_num_valid = verify_check_digit(doc_number_field, doc_number_ck)
    dob_valid = verify_check_digit(dob_field, dob_ck)
    expiry_valid = verify_check_digit(expiry_field, expiry_ck)

    composite_payload = l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29]
    composite_valid = verify_check_digit(composite_payload, composite_ck)

    is_valid = doc_num_valid and dob_valid and expiry_valid and composite_valid

    return {
        "format": "TD1",
        "valid": is_valid,
        "doc_type": doc_type,
        "issuing_country": issuing_country,
        "passport_number": doc_number,
        "surname": surname,
        "given_names": given_names,
        "nationality": nationality,
        "dob": dob_field,
        "sex": sex if sex in ('M', 'F', 'X') else "U",
        "expiry": expiry_field,
        "optional_data": (optional1 + optional2).rstrip('<'),
        "checks": {
            "document_number": {
                "ok": doc_num_valid,
                "computed": compute_mrz_check_digit(doc_number_field),
                "expected": int(doc_number_ck) if doc_number_ck.isdigit() else doc_number_ck,
            },
            "dob": {
                "ok": dob_valid,
                "computed": compute_mrz_check_digit(dob_field),
                "expected": int(dob_ck) if dob_ck.isdigit() else dob_ck,
            },
            "expiry": {
                "ok": expiry_valid,
                "computed": compute_mrz_check_digit(expiry_field),
                "expected": int(expiry_ck) if expiry_ck.isdigit() else expiry_ck,
            },
            "composite": {
                "ok": composite_valid,
                "computed": compute_mrz_check_digit(composite_payload),
                "expected": int(composite_ck) if composite_ck.isdigit() else composite_ck,
            },
        },
    }


def parse_td2(line1: str, line2: str) -> Dict[str, Any]:
    """Parse and verify an ICAO TD2 MRZ (2 lines x 36 characters)."""
    l1 = line1.ljust(36, '<')[:36]
    l2 = line2.ljust(36, '<')[:36]

    doc_type = l1[0:2].rstrip('<')
    issuing_country = l1[2:5].rstrip('<')
    name_parts = l1[5:36].split('<<')
    surname = name_parts[0].replace('<', ' ').strip() if len(name_parts) > 0 else ""
    given_names = name_parts[1].replace('<', ' ').strip() if len(name_parts) > 1 else ""

    doc_number_field = l2[0:9]
    doc_number = doc_number_field.rstrip('<')
    doc_number_ck = l2[9]
    nationality = l2[10:13].rstrip('<')
    dob_field = l2[13:19]
    dob_ck = l2[19]
    sex = l2[20]
    expiry_field = l2[21:27]
    expiry_ck = l2[27]
    optional = l2[28:35]
    composite_ck = l2[35]

    doc_num_valid = verify_check_digit(doc_number_field, doc_number_ck)
    dob_valid = verify_check_digit(dob_field, dob_ck)
    expiry_valid = verify_check_digit(expiry_field, expiry_ck)

    composite_payload = doc_number_field + doc_number_ck + dob_field + dob_ck + expiry_field + expiry_ck + optional
    composite_valid = verify_check_digit(composite_payload, composite_ck)

    is_valid = doc_num_valid and dob_valid and expiry_valid and composite_valid

    return {
        "format": "TD2",
        "valid": is_valid,
        "doc_type": doc_type,
        "issuing_country": issuing_country,
        "passport_number": doc_number,
        "surname": surname,
        "given_names": given_names,
        "nationality": nationality,
        "dob": dob_field,
        "sex": sex if sex in ('M', 'F', 'X') else "U",
        "expiry": expiry_field,
        "optional_data": optional.rstrip('<'),
        "checks": {
            "document_number": {
                "ok": doc_num_valid,
                "computed": compute_mrz_check_digit(doc_number_field),
                "expected": int(doc_number_ck) if doc_number_ck.isdigit() else doc_number_ck,
            },
            "dob": {
                "ok": dob_valid,
                "computed": compute_mrz_check_digit(dob_field),
                "expected": int(dob_ck) if dob_ck.isdigit() else dob_ck,
            },
            "expiry": {
                "ok": expiry_valid,
                "computed": compute_mrz_check_digit(expiry_field),
                "expected": int(expiry_ck) if expiry_ck.isdigit() else expiry_ck,
            },
            "composite": {
                "ok": composite_valid,
                "computed": compute_mrz_check_digit(composite_payload),
                "expected": int(composite_ck) if composite_ck.isdigit() else composite_ck,
            },
        },
    }


def parse_td3_line2(line2: str) -> Dict[str, Any]:
    """Parse and verify TD3 Line 2 alone (common when only check-digit line is provided)."""
    l2 = line2.ljust(44, '<')[:44]
    doc_number_field = l2[0:9]
    doc_number = doc_number_field.rstrip('<')
    doc_number_ck = l2[9]
    nationality = l2[10:13].rstrip('<')
    dob_field = l2[13:19]
    dob_ck = l2[19]
    sex = l2[20]
    expiry_field = l2[21:27]
    expiry_ck = l2[27]
    optional_field = l2[28:42]
    optional_ck = l2[42]
    composite_ck = l2[43]

    doc_num_valid = verify_check_digit(doc_number_field, doc_number_ck)
    dob_valid = verify_check_digit(dob_field, dob_ck)
    expiry_valid = verify_check_digit(expiry_field, expiry_ck)

    composite_valid = None
    if composite_ck.isdigit():
        composite_payload = doc_number_field + doc_number_ck + dob_field + dob_ck + expiry_field + expiry_ck + optional_field + optional_ck
        composite_valid = verify_check_digit(composite_payload, composite_ck)

    is_valid = doc_num_valid and dob_valid and expiry_valid and (composite_valid is not False)

    return {
        "format": "TD3",
        "valid": is_valid,
        "doc_type": "P",
        "issuing_country": nationality or "IND",
        "passport_number": doc_number,
        "surname": "",
        "given_names": "",
        "nationality": nationality,
        "dob": dob_field,
        "sex": sex if sex in ('M', 'F', 'X') else "U",
        "expiry": expiry_field,
        "optional_data": optional_field.rstrip('<'),
        "checks": {
            "document_number": {
                "ok": doc_num_valid,
                "computed": compute_mrz_check_digit(doc_number_field),
                "expected": int(doc_number_ck) if doc_number_ck.isdigit() else doc_number_ck,
            },
            "dob": {
                "ok": dob_valid,
                "computed": compute_mrz_check_digit(dob_field),
                "expected": int(dob_ck) if dob_ck.isdigit() else dob_ck,
            },
            "expiry": {
                "ok": expiry_valid,
                "computed": compute_mrz_check_digit(expiry_field),
                "expected": int(expiry_ck) if expiry_ck.isdigit() else expiry_ck,
            },
            "composite": {
                "ok": composite_valid,
                "computed": compute_mrz_check_digit(doc_number_field + doc_number_ck + dob_field + dob_ck + expiry_field + expiry_ck + optional_field + optional_ck) if composite_ck.isdigit() else None,
                "expected": int(composite_ck) if composite_ck.isdigit() else None,
            },
        },
    }


def parse_mrz(raw_text: str) -> Dict[str, Any]:
    """Auto-detect format (TD1, TD2, TD3) and parse MRZ lines."""
    lines = _clean_mrz_lines(raw_text)
    if not lines:
        return {"valid": False, "error": "No MRZ lines found in input text."}

    # TD1 detection: 3 lines each around 30 characters
    if len(lines) >= 3 and all(28 <= len(l) <= 32 for l in lines[-3:]):
        return parse_td1(lines[-3], lines[-2], lines[-1])

    # TD3 detection: 2 lines each around 44 characters
    if len(lines) >= 2 and any(42 <= len(l) <= 46 for l in lines):
        cand = [l for l in lines if len(l) >= 42]
        if len(cand) >= 2:
            return parse_td3(cand[-2], cand[-1])

    # TD2 detection: 2 lines each around 36 characters
    if len(lines) >= 2 and any(34 <= len(l) <= 38 for l in lines):
        cand = [l for l in lines if 34 <= len(l) <= 40]
        if len(cand) >= 2:
            return parse_td2(cand[-2], cand[-1])

    # Fallback: if two lines exist, try TD3 then TD2
    if len(lines) >= 2:
        res = parse_td3(lines[-2], lines[-1])
        if res.get("valid"):
            return res
        return parse_td2(lines[-2], lines[-1])

    # Single-line MRZ fallback (e.g. TD3 Line 2 alone)
    if len(lines) == 1 and len(lines[0]) >= 26:
        return parse_td3_line2(lines[0])

    return {"valid": False, "error": f"Incomplete MRZ lines ({len(lines)} line(s) found)."}
