"""
Tests for the MHA screening pipeline's deterministic identifier layer.

Covers normalization/masking, the Verhoeff (Aadhaar) checksum, ICAO 9303 MRZ
check digits and the regex extraction layer (incl. voter-ID/EPIC).

Run either way (no deps beyond what the app already needs):
    python tests/test_screening.py        # plain asserts
    pytest tests/test_screening.py        # pytest runner

Vectors: the MRZ line is the ICAO 9303 TD3 specimen (passport L898902C,
DOB 690806, expiry 940623 — check digits 3 / 1 / 6). Aadhaar vectors were
derived with the Verhoeff algorithm directly, so the tests are independent of
the implementation under test.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

from screening import (
    extract_fields,
    extract_mrz,
    mask,
    norm,
    mrz_checkdigit,
    sha256,
    verhoeff_valid,
)

_MRZ_LINE2 = "L898902C<3UTO6908061F9406236"


def test_norm_collapses_spacing_and_case():
    assert norm("ka-01/2020/1234567") == norm("KA 012020 1234567")
    assert norm("  AbC 12-34 ") == "ABC1234"
    assert norm("2345 1234 5678") == "234512345678"


def test_norm_handles_empty_and_non_string():
    assert norm("") == ""
    assert norm(None) == ""
    assert norm(987654321096) == "987654321096"


def test_mask_keeps_only_tail():
    assert mask("234512345670") == "********5670"
    assert mask("ABC1234567") == "******4567"
    assert mask("abc") == "ABC"  # short values are returned whole, normalized


def test_sha256_deterministic_and_normalized():
    assert sha256("2345 1234 5678") == sha256("234512345678")
    assert len(sha256("x")) == 64


def test_verhoeff_known_valid_vectors():
    for n in ("234512345670", "987654321096", "500000000006", "700012345678"):
        assert verhoeff_valid(n) is True


def test_verhoeff_rejects_mutated_check():
    # A single changed digit must always fail (Verhoeff's single-error guarantee).
    assert verhoeff_valid("234512345671") is False
    assert verhoeff_valid("987654321096") is True


def test_verhoeff_rejects_bad_shape():
    assert verhoeff_valid("23451234567") is False     # 11 digits
    assert verhoeff_valid("2345123456709") is False   # 13 digits
    assert verhoeff_valid("2345X2345670") is False    # non-numeric
    assert verhoeff_valid("") is False


def test_mrz_checkdigit_icao_specimen():
    assert mrz_checkdigit("L898902C<") == 3
    assert mrz_checkdigit("690806") == 1
    assert mrz_checkdigit("940623") == 6


def test_extract_mrz_valid_specimen():
    out = extract_mrz(_MRZ_LINE2)
    assert out["passport"] == "L898902C"      # ICAO '<' padding stripped
    assert out["mrz_valid"] is True
    assert out["mrz_dob"] == "690806"


def test_extract_mrz_tampered_expiry_fails():
    # Flip the expiry check digit: the MRZ must no longer validate.
    tampered = _MRZ_LINE2[:-1] + str((int(_MRZ_LINE2[-1]) + 1) % 10)
    out = extract_mrz(tampered)
    assert out["mrz_valid"] is False
    assert out["mrz_expiry_ck"] is False


def test_extract_fields_aadhaar():
    out = extract_fields("References 2345 1234 5670 elsewhere in the text.")
    assert out["aadhaar"] == "234512345670"


def test_extract_fields_aadhaar_verhoeff_gate():
    # Matches the digit pattern but fails the checksum -> must NOT be extracted.
    out = extract_fields("Aadhaar 234512345671 printed here.")
    assert out["aadhaar"] is None


def test_extract_fields_pan():
    out = extract_fields("PAN AAAPL1234C on the corner.")
    assert out["pan"] == "AAAPL1234C"


def test_extract_fields_driving_licence():
    out = extract_fields("DL MH01 2015 0001234, valid till 2035.")
    assert out["driving_licence"] is not None


def test_extract_fields_voter_id_epic():
    out = extract_fields("EPIC card number ABC1234567 issued by the ECI.")
    assert out["voter_id"] == "ABC1234567"


def test_extract_fields_voter_id_rejects_bad_shape():
    assert extract_fields("EPIC AB1234567 (two letters is invalid)")["voter_id"] is None
    assert extract_fields("EPIC ABCD1234567 (four letters invalid)")["voter_id"] is None


def test_extract_fields_phone_and_dob():
    out = extract_fields("Contact 9876543210, DOB 06/08/1969.")
    assert out["phone"] == "9876543210"
    assert out["dob"] == "1969-08-06"


def test_extract_fields_mrz_populates_adult_dob():
    # No plain-text DOB, but the MRZ is valid -> century heuristic yields 1969.
    out = extract_fields(f"Passport page. {_MRZ_LINE2} footer.")
    assert out["passport"] == "L898902C"
    assert out["dob"] == "1969-08-06"
    assert out["mrz_valid"] is True


def test_extract_fields_mrz_populates_child_dob():
    # YYMMDD "050104" with current 2-digit year 26 -> born in 2005 (not 1905).
    pno = "P1234567<"
    line = f"{pno}{mrz_checkdigit(pno)}UTO050104{mrz_checkdigit('050104')}M160905{mrz_checkdigit('160905')}"
    out = extract_fields(f"footer {line} more")
    assert out["passport"] == "P1234567"
    assert out["dob"] == "2005-01-04"
    assert out["mrz_valid"] is True


def test_extract_mrz_stateless_nationality():
    # UN/stateless passports print '<<<' in the nationality field — the zone
    # must still parse and validate (regression: previously returned {}).
    pno = "ABCD1234<"
    nat = "<<<"
    dob = "690806"
    exp = "241231"
    line = f"{pno}{mrz_checkdigit(pno)}{nat}{dob}{mrz_checkdigit(dob)}M{exp}{mrz_checkdigit(exp)}"
    out = extract_mrz(line)
    assert out["mrz_valid"] is True
    assert out["passport"] == "ABCD1234"


def test_extract_fields_dob_ignores_future_expiry():
    # A document prints 'VALID TILL' BEFORE the DOB — the first date must not
    # be mistaken for a birth date (the DOB is the oldest date on the page).
    out = extract_fields("VALID TILL: 31-12-2031  DOB: 15-08-1990")
    assert out["dob"] == "1990-08-15"


if __name__ == "__main__":
    fns = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print("PASS", fn.__name__)
    print(f"{passed}/{len(fns)} tests passed")