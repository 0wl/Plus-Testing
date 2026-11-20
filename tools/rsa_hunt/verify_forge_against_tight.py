#!/usr/bin/env python3
"""
Offline model of the EXACT verifier found in swap @ FUN_0016e760.

Verifier does:
  1. em_prefix = digestInfo_bytes || hash_bytes             (len = 15+20 = 35)
  2. expected  = 00 01 FF*(128 - 35 - 3) 00 em_prefix        (len = 128)
                 = 00 01 FF*90 00 digestInfo(15) hash(20)
  3. actual    = pow(sig, 3, N).to_bytes(128, 'big')
  4. memcmp(expected, actual, 128) must be 0

Bleichenbacher '06 forge produced ff_count=6 in our run, so:
  - actual bytes [0..43]  : 00 01 FF*6 00 digestInfo(15) hash(20)   ← matches
  - actual bytes [44..127]: 84 bytes of math-residue garbage        ← DIFFERS
  - expected bytes [2..91]: FF*90 (NOT FF*6)                        ← DIFFERS

Full 128-byte memcmp → mismatch at offset 8 (first non-FF in the forge where
expected is still FF). Verifier returns 0. "signature is invalid" branch.

This script runs the check against the stock-signed toolbox sig AND the
forged sig, prints the mismatch offset, and reports accept/reject.
"""
import hashlib, re, sys, os, struct

SHA1_DI = bytes.fromhex("3021300906052b0e03021a05000414")  # 15 bytes


def rsa_decode(sig_bytes, modulus_bytes, exp=3):
    N = int.from_bytes(modulus_bytes, "big")
    s = int.from_bytes(sig_bytes, "big")
    m = pow(s, exp, N)
    return m.to_bytes(len(modulus_bytes), "big")


def tight_verify(sig_bytes, modulus_bytes, msg_hash, hash_algo="sha1"):
    k = len(modulus_bytes)
    if hash_algo != "sha1":
        raise ValueError("SHA-1 only here")
    em_prefix = SHA1_DI + msg_hash          # 35 bytes
    pad_count = k - len(em_prefix) - 3      # 128 - 35 - 3 = 90
    if pad_count < 8:
        return False, "pad_count<8 invalid"
    expected = bytes([0x00, 0x01]) + b"\xff" * pad_count + bytes([0x00]) + em_prefix
    assert len(expected) == k
    actual = rsa_decode(sig_bytes, modulus_bytes)
    if expected == actual:
        return True, "memcmp match"
    # First diff offset
    for i, (e, a) in enumerate(zip(expected, actual)):
        if e != a:
            return False, (f"first diff at offset {i} (0x{i:02x}): "
                          f"expected {e:02x}, got {a:02x}")
    return False, "length mismatch"


def load_metainfo_sig(path):
    text = open(path, encoding="latin1").read()
    sig_hex = ""
    for i in range(1, 9):
        m = re.search(rf'^signature{i}\s*=\s*"([0-9a-fA-F]+)"', text, flags=re.MULTILINE)
        if not m:
            raise ValueError(f"missing signature{i}")
        sig_hex += m.group(1)
    sig = bytes.fromhex(sig_hex)
    assert len(sig) == 128
    return sig, text


def compute_signed_slice_sha1(text):
    i = text.find("[Signature]")
    return hashlib.sha1(text[:i].encode("latin1")).digest()


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    pubkey = open(os.path.join(root, "extracted", "swapkeys", "tsd", "etc",
                               "swap_keys", "tmp",
                               "Metainfo_key_public_signed.bin"), "rb").read()
    modulus = pubkey[:128]
    print(f"[+] modulus bits: {int.from_bytes(modulus,'big').bit_length()}")

    # --- Stock toolbox metainfo ---
    stock_path = os.path.join(root, "extracted", "toolbox", "metainfo2.txt")
    sig_stock, text_stock = load_metainfo_sig(stock_path)
    h_stock = compute_signed_slice_sha1(text_stock)
    ok, why = tight_verify(sig_stock, modulus, h_stock)
    print(f"[STOCK]  hash={h_stock.hex()}  verify={'ACCEPT' if ok else 'REJECT'}  ({why})")

    # --- Forged metainfo ---
    forge_path = "/tmp/forge_verify_test.txt"
    if not os.path.exists(forge_path):
        print("[!] run forge_custom_metainfo.py first to produce /tmp/forge_verify_test.txt")
    else:
        sig_forge, text_forge = load_metainfo_sig(forge_path)
        h_forge = compute_signed_slice_sha1(text_forge)
        ok, why = tight_verify(sig_forge, modulus, h_forge)
        print(f"[FORGE]  hash={h_forge.hex()}  verify={'ACCEPT' if ok else 'REJECT'}  ({why})")
        decoded = rsa_decode(sig_forge, modulus)
        print(f"         decoded(first 48): {decoded[:48].hex()}")
        print(f"         decoded(last  48): {decoded[-48:].hex()}")

    # --- Also show what the tight verifier expects vs forge decoded ---
    exp = (bytes([0, 1]) + b"\xff" * 90 + bytes([0]) + SHA1_DI +
           h_stock)
    print(f"\n[expected stock (first 48)]: {exp[:48].hex()}")
    print(f"[expected stock (last  48)]: {exp[-48:].hex()}")
    print(f"[stock decoded (first 48)] : {rsa_decode(sig_stock, modulus)[:48].hex()}")


if __name__ == "__main__":
    main()
