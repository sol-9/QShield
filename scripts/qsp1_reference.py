#!/usr/bin/env python3
"""Independent QSP-1 encoder (Python, standard library only).

Written directly from docs/QSP-1.md, without reference to the Rust code, to
check that two implementations produce identical bytes and SHA-256 digests
for every positive vector in tests/vectors/qsp1/qsp1-vectors.json.

Usage: scripts/qsp1_reference.py [path/to/qsp1-vectors.json]
Exit status 0 if every vector matches.
"""
import hashlib
import json
import struct
import sys

DOMAIN = b"QSHIELD_SOLANA_AUTH_V1"
VERSION = 1
KEY_ID_DOMAIN = b"QSHIELD_KEY_ID_V1"


def encode(f, domain=DOMAIN, version=VERSION):
    b32 = lambda h: bytes.fromhex(h)  # noqa: E731
    out = bytearray()
    out += domain                                   # 0   domain        22
    out += struct.pack("<H", version)               # 22  version        2
    out += b32(f["cluster_id"])                     # 24  cluster_id    32
    out += b32(f["program_id"])                     # 56  program_id    32
    out += b32(f["vault"])                          # 88  vault         32
    out += struct.pack("<B", f["action"])           # 120 action         1
    out += struct.pack("<B", f["asset_type"])       # 121 asset_type     1
    out += struct.pack("<Q", int(f["nonce"]))       # 122 nonce          8
    out += struct.pack("<q", int(f["valid_after"])) # 130 valid_after    8
    out += struct.pack("<q", int(f["expires_at"]))  # 138 expires_at     8
    out += b32(f["mint"])                           # 146 mint          32
    out += b32(f["destination"])                    # 178 destination   32
    out += struct.pack("<Q", int(f["amount"]))      # 210 amount         8
    out += struct.pack("<B", f["decimals"])         # 218 decimals       1
    out += b32(f["fee_recipient"])                  # 219 fee_recipient 32
    out += struct.pack("<Q", int(f["fee_lamports"]))# 251 fee_lamports   8
    out += b32(f["new_key_id"])                     # 259 new_key_id    32
    out += struct.pack("<B", f["new_algorithm"])    # 291 new_algorithm  1
    assert len(out) == 292
    return bytes(out)


def encode_v2(f):
    """QSP-1 version 2 (docs/QSP-1.md section 11): v1 layout with domain
    QSHIELD_SOLANA_AUTH_V2 / version 2, then role, ref_id, limit fields."""
    out = bytearray(encode(f, b"QSHIELD_SOLANA_AUTH_V2", 2))
    out += struct.pack("<B", f["role"])                 # 292 role           1
    out += struct.pack("<Q", int(f["ref_id"]))          # 293 ref_id         8
    out += struct.pack("<Q", int(f["limit_lamports"]))  # 301 limit_lamports 8
    out += struct.pack("<q", int(f["limit_period"]))    # 309 limit_period   8
    assert len(out) == 317
    return bytes(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/vectors/qsp1/qsp1-vectors.json"
    data = json.load(open(path))
    for k in data["keys"]:
        pk = bytes.fromhex(k["public_key_hex"])
        kid = hashlib.sha256(KEY_ID_DOMAIN + b"\x01" + pk).hexdigest()
        assert kid == k["key_id_hex"], "key id mismatch"
    checked = 0
    for v in data["vectors"]:
        if "fields" not in v:
            continue
        enc = encode(v["fields"])
        assert enc.hex() == v["auth_hex"], f"{v['name']}: encoding mismatch"
        assert hashlib.sha256(enc).hexdigest() == v["auth_sha256"], f"{v['name']}: digest mismatch"
        checked += 1
    print(f"QSP-1 reference encoder: {checked} vectors and {len(data['keys'])} key ids match")
    v2 = json.load(open(path.replace("qsp1-vectors.json", "qsp1-v2-vectors.json")))
    pk = bytes.fromhex(v2["key"]["public_key_hex"])
    assert hashlib.sha256(KEY_ID_DOMAIN + b"\x01" + pk).hexdigest() == v2["key"]["key_id_hex"]
    n = 0
    for v in v2["vectors"]:
        if "fields" in v:
            assert encode_v2(v["fields"]).hex() == v["auth_hex"], f"v2 {v['name']}: encoding mismatch"
            n += 1
    print(f"QSP-1 v2 reference encoder: {n} vectors match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
