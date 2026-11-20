#!/usr/bin/env python3
"""
Brute-force slice-definition search to identify what the signer
actually SHA-1'd before signing stock toolbox metainfo2.txt.

Target hash: eabf0ec5a2b0010ed0751b5f5621282373f07732
"""
import hashlib, re, os, itertools

TARGET = "eabf0ec5a2b0010ed0751b5f5621282373f07732"


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(root, "extracted", "toolbox", "metainfo2.txt")
    raw = open(path, "rb").read()

    i_sig = raw.find(b"[Signature]")
    print(f"[Signature] at offset {i_sig}")
    print(f"file size: {len(raw)}")

    def check(label, data):
        h = hashlib.sha1(data).hexdigest()
        if h == TARGET:
            print(f"  [MATCH] {label}  len={len(data)}")
            return True
        return False

    # Normalizations
    raw_lf = raw.replace(b"\r\n", b"\n")
    raw_crlf = raw_lf.replace(b"\n", b"\r\n")

    # MetafileChecksum zeroed vs removed vs kept
    mc_regex = re.compile(rb'(^MetafileChecksum\s*=\s*")([0-9a-fA-F]*)(")',
                          flags=re.MULTILINE)
    raw_mc_zero = mc_regex.sub(lambda m: m.group(1) + b"0"*40 + m.group(3), raw)
    raw_mc_empty = mc_regex.sub(lambda m: m.group(1) + b"" + m.group(3), raw)
    raw_mc_gone = mc_regex.sub(b"", raw)
    # full line gone (including newline)
    raw_mc_line_gone = re.sub(rb'^MetafileChecksum\s*=\s*"[0-9a-fA-F]*"\r?\n?',
                              b"", raw, flags=re.MULTILINE)

    variants = {
        "raw": raw,
        "raw_lf": raw_lf,
        "raw_crlf": raw_crlf,
        "raw_mc_zero": raw_mc_zero,
        "raw_mc_empty": raw_mc_empty,
        "raw_mc_gone": raw_mc_gone,
        "raw_mc_line_gone": raw_mc_line_gone,
    }
    cuts = {
        "upto_sig": lambda b: b[:b.find(b"[Signature]")],
        "upto_sig_rstrip": lambda b: b[:b.find(b"[Signature]")].rstrip(),
        "upto_sig_rstrip_ws": lambda b: b[:b.find(b"[Signature]")].rstrip(b" \t\r\n"),
        "upto_sig_stripnl": lambda b: b[:b.find(b"[Signature]")].rstrip(b"\r\n"),
        "whole": lambda b: b,
    }
    print(f"\n=== searching combinations ===")
    found = False
    for vname, vdata in variants.items():
        for cname, cfn in cuts.items():
            d = cfn(vdata)
            if check(f"{vname}/{cname}", d):
                found = True

    # Try: remove each INDIVIDUAL LINE from file, check
    if not found:
        print(f"\n=== line-deletion sweep (up to [Signature]) ===")
        sig_region = raw[:i_sig]
        lines = sig_region.splitlines(keepends=True)
        for i, L in enumerate(lines):
            joined = b"".join(lines[:i] + lines[i+1:])
            h = hashlib.sha1(joined).hexdigest()
            if h == TARGET:
                print(f"  [MATCH] deleting line {i}: {L!r}")
                found = True
                break
        if not found:
            print(f"  (no single-line deletion matches)")

    # Try: normalize each line's trailing whitespace
    if not found:
        print(f"\n=== line-normalized ===")
        sig_region = raw[:i_sig]
        normalized = b"\n".join(L.rstrip(b" \t\r") for L in sig_region.splitlines()) + b"\n"
        check("normalized_lines_LF", normalized)
        normalized_no_trail = b"\n".join(L.rstrip(b" \t\r") for L in sig_region.splitlines())
        check("normalized_lines_LF_no_trail", normalized_no_trail)

    # Try: raw with the MetafileChecksum line REPLACED by just its key with new value
    if not found:
        print(f"\n=== MetafileChecksum replaced ===")
        mcm = mc_regex.search(raw)
        if mcm:
            full_line_re = re.compile(rb'^MetafileChecksum\s*=\s*"[0-9a-fA-F]*"', re.MULTILINE)
            # Replace with placeholder patterns
            for repl in [b'', b'MetafileChecksum = "0"',
                         b'MetafileChecksum = ""']:
                r2 = full_line_re.sub(repl, raw)[:raw.find(b"[Signature]")]
                check(f"mc_line_repl_{repl}", r2)


if __name__ == "__main__":
    main()
