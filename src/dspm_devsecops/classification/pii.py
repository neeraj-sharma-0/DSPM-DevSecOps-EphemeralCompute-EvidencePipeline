from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b")

@dataclass(frozen=True)
class ClassificationFinding:
    asset_id: str
    classification: str  # public|internal|pii_low|pii_high|regulated
    signals: Dict[str, int]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent

def classify_text(asset_id: str, text: str, entropy_threshold: float = 4.1) -> ClassificationFinding:
    signals = {
        "email": len(EMAIL_RE.findall(text)),
        "ssn": len(SSN_RE.findall(text)),
        "cc_like": len(CC_RE.findall(text)),
        "phone": len(PHONE_RE.findall(text)),
    }
    ent = shannon_entropy(text)
    signals["entropy_hi"] = 1 if ent >= entropy_threshold and len(text) >= 64 else 0

    # Classification rules (demo, deterministic)
    if signals["ssn"] > 0:
        cls = "pii_high"
    elif signals["cc_like"] > 0:
        cls = "regulated"  # treat payment-like strings as regulated for demo
    elif signals["email"] > 0 or signals["phone"] > 0:
        cls = "pii_low"
    elif signals["entropy_hi"] > 0:
        cls = "internal"
    else:
        cls = "public"

    return ClassificationFinding(asset_id=asset_id, classification=cls, signals=signals)

CLASS_MULTIPLIER = {
    "public": 0.6,
    "internal": 1.0,
    "pii_low": 1.3,
    "pii_high": 1.7,
    "regulated": 1.9,
}
