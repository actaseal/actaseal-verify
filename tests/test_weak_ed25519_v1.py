"""verify.py rejects mixed-order and non-canonical Ed25519 keys and weak R values by itself.

The library underneath accepts some of these (a key that is a prime-order point plus an order-8 torsion
point; a y coordinate >= p), so verify.py has to say no before it asks. Each case is run twice: against
the real library, and against a stand-in library that says yes to everything, which proves the refusal
is verify.py's own. The reference arithmetic is written out here, independent of verify.py.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import verify as v  # noqa: E402

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
IDENT = (0, 1)
BASE_Y = 4 * pow(5, P - 2, P) % P


def _x_for(y, sign):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - xx) % P:
        return None
    return x if x % 2 == sign else P - x


def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, P - 2, P) % P, (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P)


def _mul(k, pt):
    out = IDENT
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def _enc(pt):
    return (pt[1] | ((pt[0] & 1) << 255)).to_bytes(32, "little")


BASE = (_x_for(BASE_Y, 0), BASE_Y)


def _order8():
    y = 2
    while True:
        x = _x_for(y, 0)
        if x is not None:
            t = _mul(L, (x, y))
            if _mul(4, t) != IDENT and _mul(8, t) == IDENT:
                return t
        y += 1


T8 = _order8()
BAD = {
    "identity": _enc(IDENT),
    "all zero": bytes(32),
    "order-8 torsion point": _enc(T8),
    "base point + order-8 torsion point": _enc(_add(BASE, T8)),
    "non-canonical y = p + 1": (P + 1).to_bytes(32, "little"),
    "y = p": P.to_bytes(32, "little"),
    "not on the curve": (2).to_bytes(32, "little"),
}


class AcceptsEverything:
    @classmethod
    def from_public_bytes(cls, data):
        return cls()

    def verify(self, signature, data):
        return None


def _crypto(accept_all=False):
    return {
        "ed25519_public_key_cls": AcceptsEverything if accept_all else Ed25519PublicKey,
        "invalid_signature_error": InvalidSignature,
        "unsupported_algorithm_error": UnsupportedAlgorithm,
        "load_der_public_key": serialization.load_der_public_key,
        "ecdsa_sha256": None,
    }


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _signed_receipt():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    unsigned = {"decision": "ALLOW", "algorithm": "ed25519", "policy_hash": "p" * 8}
    receipt = {**unsigned, "signature": key.sign(_canonical(unsigned).encode()).hex()}
    return receipt, pub.hex()


def _failures(receipt, key_hex, *, accept_all):
    failures = []
    v.verify_receipt({"receipt_public_key_hex": key_hex, "action_id": "a"}, receipt, [], failures, _crypto(accept_all))
    return failures


@pytest.mark.parametrize("accept_all", [False, True])
def test_a_real_signature_still_verifies(accept_all):
    receipt, pub = _signed_receipt()
    assert "RECEIPT_SIGNATURE_INVALID" not in _failures(receipt, pub, accept_all=accept_all)


@pytest.mark.parametrize("accept_all", [False, True])
@pytest.mark.parametrize("name", list(BAD))
def test_a_weak_public_key_is_signature_invalid(name, accept_all):
    receipt, _ = _signed_receipt()
    assert "RECEIPT_SIGNATURE_INVALID" in _failures(receipt, BAD[name].hex(), accept_all=accept_all)


@pytest.mark.parametrize("name", list(BAD))
def test_a_weak_r_is_signature_invalid_even_if_the_library_accepts_it(name):
    receipt, pub = _signed_receipt()
    forged = {**receipt, "signature": (BAD[name] + bytes.fromhex(receipt["signature"])[32:]).hex()}
    assert "RECEIPT_SIGNATURE_INVALID" in _failures(forged, pub, accept_all=True)


@pytest.mark.parametrize("accept_all", [False, True])
@pytest.mark.parametrize("name", list(BAD))
def test_the_tree_head_signature_check_refuses_weak_keys_and_weak_r(name, accept_all):
    sth = {"algorithm": "ed25519", "tree_size": 1, "root_hash": "r", "timestamp": "t", "signature": "00" * 64}
    assert v._verify_sth_signature(sth, BAD[name].hex(), _crypto(accept_all)) is False
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    weak_r = {**sth, "signature": (BAD[name] + bytes(32)).hex()}
    assert v._verify_sth_signature(weak_r, pub, _crypto(True)) is False


def test_verify_py_stays_standard_library_for_this_check():
    source = (ROOT / "verify.py").read_text(encoding="utf-8")
    assert "weak_key_guard" not in source and "from actaseal" not in source
