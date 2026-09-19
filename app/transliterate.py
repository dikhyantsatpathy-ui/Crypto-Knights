"""
Devanagari to Latin transliteration and name fuzzy-matching (Feature 5).

Pure-Python, zero-dependency. Covers all 47 standard Devanagari vowels and
consonants used in Hindi names printed on Indian identity documents.

Two public functions:
  transliterate_devanagari(text)  ->  approximate Latin string
  names_match(a, b, threshold)    ->  (match: bool|None, score: float, detail: str)
"""

_VOWELS = {
    "a": "A", "A": "AA", "i": "I", "I": "II",
    "u": "U", "U": "UU", "e": "E", "E": "AI",
    "o": "O", "O": "AU",
}

_TABLE = {
    "\u0905": "A",  "\u0906": "AA", "\u0907": "I",  "\u0908": "II",
    "\u0909": "U",  "\u090A": "UU", "\u090F": "E",  "\u0910": "AI",
    "\u0913": "O",  "\u0914": "AU", "\u090B": "RI", "\u0960": "RI",
    "\u093E": "AA", "\u093F": "I",  "\u0940": "II", "\u0941": "U",
    "\u0942": "UU", "\u0947": "E",  "\u0948": "AI", "\u094B": "O",
    "\u094C": "AU", "\u0943": "RI",
    "\u0915": "K",  "\u0916": "KH", "\u0917": "G",  "\u0918": "GH", "\u0919": "NG",
    "\u091A": "CH", "\u091B": "CHH","\u091C": "J",  "\u091D": "JH", "\u091E": "NY",
    "\u091F": "T",  "\u0920": "TH", "\u0921": "D",  "\u0922": "DH", "\u0923": "N",
    "\u0924": "T",  "\u0925": "TH", "\u0926": "D",  "\u0927": "DH", "\u0928": "N",
    "\u092A": "P",  "\u092B": "PH", "\u092C": "B",  "\u092D": "BH", "\u092E": "M",
    "\u092F": "Y",  "\u0930": "R",  "\u0932": "L",  "\u0935": "V",
    "\u0936": "SH", "\u0937": "SH", "\u0938": "S",  "\u0939": "H",
    "\u0933": "L",
    "\u0902": "N",  "\u0901": "N",  "\u0903": "H",  "\u094D": "",
    "\u200C": "",   "\u200D": "",
    "\u0958": "Q",  "\u0959": "KH", "\u095A": "G",  "\u095B": "Z",
    "\u095C": "R",  "\u095D": "RH", "\u095E": "F",
}


def transliterate_devanagari(text: str) -> str:
    if not text:
        return ""
    out = []
    for ch in text:
        if ch in _TABLE:
            out.append(_TABLE[ch])
        elif not ("\u0900" <= ch <= "\u097F"):
            out.append(ch.upper() if ch.isalpha() else ch)
    return "".join(out).strip()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    dist = _levenshtein(a, b)
    return 1.0 - dist / max(len(a), len(b))


def names_match(latin_a: str, latin_b: str, threshold: float = 0.72):
    a = transliterate_devanagari(latin_a).upper().replace(" ", "")
    b = transliterate_devanagari(latin_b).upper().replace(" ", "")
    if not a or not b:
        return None, 0.0, "One or both name fields are empty."
    score = _similarity(a, b)
    gap = 0.10
    if score >= threshold:
        return True, score, f"Names match (similarity {score:.2f})."
    elif score < threshold - gap:
        return False, score, (
            f"Name mismatch: MRZ '{a}' vs document '{b}' (similarity {score:.2f}). "
            "Possible photo-swap or page-substitution — verify by eye."
        )
    else:
        return None, score, f"Names are close but not conclusive (similarity {score:.2f}). Confirm by eye."
