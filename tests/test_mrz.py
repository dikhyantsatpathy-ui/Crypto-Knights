"""
Unit tests for ICAO Doc 9303 Machine Readable Zone (MRZ) parser and
modulus-10 checksum validation across TD1, TD2, and TD3 specifications.

Run:
    .venv/Scripts/python tests/test_mrz.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

import mrz


def test_td3_official_specimen():
    line1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
    line2 = "L898902C<3UTO6908061F9406236ZE184226B<<<<<14"
    res = mrz.parse_td3(line1, line2)
    assert res["valid"] is True
    assert res["format"] == "TD3"
    assert res["passport_number"] == "L898902C"
    assert res["surname"] == "ERIKSSON"
    assert res["given_names"] == "ANNA MARIA"
    assert res["nationality"] == "UTO"
    assert res["dob"] == "690806"
    assert res["sex"] == "F"
    assert res["expiry"] == "940623"
    assert res["checks"]["document_number"]["ok"] is True
    assert res["checks"]["dob"]["ok"] is True
    assert res["checks"]["expiry"]["ok"] is True
    assert res["checks"]["composite"]["ok"] is True


def test_td3_tampered_dob_checkdigit_fails():
    line1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
    # Tamper DOB check digit from 1 to 9
    line2 = "L898902C<3UTO6908069F9406236ZE184226B<<<<<14"
    res = mrz.parse_td3(line1, line2)
    assert res["valid"] is False
    assert res["checks"]["dob"]["ok"] is False


def test_td1_official_specimen():
    line1 = "I<UTOD231458907<<<<<<<<<<<<<<<"
    line2 = "7408122F1204159UTO<<<<<<<<<<<6"
    line3 = "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
    res = mrz.parse_td1(line1, line2, line3)
    assert res["valid"] is True
    assert res["format"] == "TD1"
    assert res["passport_number"] == "D23145890"
    assert res["checks"]["document_number"]["ok"] is True
    assert res["checks"]["dob"]["ok"] is True
    assert res["checks"]["expiry"]["ok"] is True
    assert res["checks"]["composite"]["ok"] is True


def test_td2_specimen():
    line1 = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<"
    line2 = "D231458907UTO7408122F1204159<<<<<<<6"
    res = mrz.parse_td2(line1, line2)
    assert res["valid"] is True
    assert res["format"] == "TD2"
    assert res["passport_number"] == "D23145890"


def test_check_digit_calculation():
    # Character '0'..'9' have value 0..9, 'A'..'Z' have value 10..35, '<' is 0
    # Weights cycle: 7, 3, 1
    # Example: 'L898902C<' -> L(21)*7 + 8*3 + 9*1 + 8*7 + 9*3 + 0*1 + 2*7 + C(12)*3 + <(0)*1
    assert mrz.compute_mrz_check_digit("L898902C<") == 3
    assert mrz.compute_mrz_check_digit("690806") == 1
    assert mrz.compute_mrz_check_digit("940623") == 6


def _run():
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok  {name}")
            except Exception as e:
                failures += 1
                print(f"FAIL  {name}: {e}")
    print(f"\n{len([1 for k in globals() if k.startswith('test_') and callable(globals()[k])]) - failures} passed, {failures} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    _run()
