#!/usr/bin/env python3
"""
Decode stock toolbox metainfo [Signature] under the Metainfo pubkey, extract
the SHA-1 hash that IS inside the PKCS envelope, then try several candidate
SHA-1 slices of the metainfo file to identify which one the signer actually
covered. That slice is the canonical "signed slice".
"""
import hashlib, re, os, sys

SHA1_DI = bytes.fromhex("3021300906052b0e03021a05000414")


def load_sig(path):
    text = open(path, encoding="latin1").read()
    sig_hex = ""
    for i in range(1, 9):
        m = re.search(rf'^signature{i}\s*=\s*"([0-9a-fA-F]+)"', text, flags=re.MULTILINE)
        sig_hex += m.group(1)
    return bytes.fromhex(sig_hex), text


def rsa_decode(sig, modulus):
    N = int.from_bytes(modulus, "big")
    s = int.from_bytes(sig, "big")
    m = pow(s, 3, N)
    return m.to_bytes(len(modulus), "big")


def parse_pkcs_hash(decoded):
    """Expect 00 01 FF..FF 00 digestInfo(15) hash(20) at offset 0."""
    assert decoded[0] == 0x00 and decoded[1] == 0x01
    # skip FF
    i = 2
    while i < len(decoded) and decoded[i] == 0xFF:
        i += 1
    assert decoded[i] == 0x00
    i += 1
    di = decoded[i:i+15]
    hash_ = decoded[i+15:i+15+20]
    return di.hex(), hash_.hex(), i, len(decoded) - (i + 15 + 20)


def try_slices(text, target_hash_hex):
    """Try many plausible slice definitions and see which SHA-1 matches."""
    target = bytes.fromhex(target_hash_hex)
    tries = []

    raw = text.encode("latin1")

    # 1) Whole file
    tries.append(("whole_file", raw))

    # 2) Up to [Signature]
    i = raw.find(b"[Signature]")
    tries.append(("up_to_Signature_header", raw[:i]))

    # 3) Up to [Signature], MetafileChecksum line REMOVED
    without_mc = re.sub(rb'^MetafileChecksum\s*=\s*"[0-9a-fA-F]*"\s*$\r?\n?',
                        b"", raw, flags=re.MULTILINE)
    i2 = without_mc.find(b"[Signature]")
    tries.append(("sans_MetafileChecksum_up_to_Signature", without_mc[:i2]))

    # 4) Up to [Signature] rstripped
    tries.append(("up_to_Signature_header_rstripped", raw[:i].rstrip()))
    tries.append(("sans_MC_up_to_Signature_rstripped", without_mc[:i2].rstrip()))

    # 5) Just [common] section only
    c_start = raw.find(b"[common]")
    c_end = raw.find(b"[", c_start + 1)
    tries.append(("common_section_only", raw[c_start:c_end]))

    # 6) Variant rstrip + newline
    tries.append(("up_to_Signature_header_stripnewline", raw[:i].rstrip(b"\r\n")))
    tries.append(("sans_MC_up_to_Signature_stripnewline", without_mc[:i2].rstrip(b"\r\n")))

    # 7) Whole file minus [Signature]..EOF
    tries.append(("file_minus_sig_section", raw[:i].rstrip(b"\r\n ")))

    # 8) Whole file minus [Signature] and MC
    tries.append(("file_minus_MC_minus_sig", without_mc[:i2].rstrip(b"\r\n ")))

    # Also try CRLF-normalized
    raw_lf = raw.replace(b"\r\n", b"\n")
    i_lf = raw_lf.find(b"[Signature]")
    tries.append(("LF_normalized_up_to_sig", raw_lf[:i_lf]))

    # 9) With trailing \n or without
    tries.append(("up_to_Signature_minus_one_newline",
                  raw[:i].rstrip(b"\r\n") + b"\n" if raw[:i].endswith(b"\n") else raw[:i]))

    hits = []
    for name, data in tries:
        h = hashlib.sha1(data).hexdigest()
        tag = "MATCH" if h == target_hash_hex else "-"
        print(f"  {tag:5s}  sha1({name:50s}, {len(data):6d}B) = {h}")
        if h == target_hash_hex:
            hits.append((name, data))
    return hits


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    pub = open(os.path.join(root, "extracted", "swapkeys", "tsd", "etc",
                            "swap_keys", "tmp", "Metainfo_key_public_signed.bin"), "rb").read()
    modulus = pub[:128]
    print(f"modulus bits: {int.from_bytes(modulus,'big').bit_length()}")

    stock = os.path.join(root, "extracted", "toolbox", "metainfo2.txt")
    sig, text = load_sig(stock)
    decoded = rsa_decode(sig, modulus)
    print(f"\n[decoded 128 bytes]:")
    for i in range(0, 128, 16):
        print(f"  {i:03d}: {decoded[i:i+16].hex()}")
    di_hex, h_hex, hash_off, tail_len = parse_pkcs_hash(decoded)
    print(f"\n  digestInfo: {di_hex}  (SHA-1 oid expected: {SHA1_DI.hex()})")
    print(f"  signed hash: {h_hex}")
    print(f"  hash offset in decoded: {hash_off+15}  tail garbage bytes: {tail_len}")
    assert tail_len == 0, f"stock sig NOT tight (unexpected garbage tail {tail_len})"
    print(f"  => stock sig has ZERO tail garbage. Full-128 memcmp holds up for stock.")

    print(f"\n[trying slice definitions to find which SHA-1 slice = {h_hex}]:")
    hits = try_slices(text, h_hex)
    if hits:
        for name, data in hits:
            print(f"\n[MATCH] {name}  len={len(data)}")
    else:
        print(f"\n[!] NONE of the attempted slices match the signed hash.")
        print(f"    The signer used a slice I haven't modeled. Need more hunting.")


if __name__ == "__main__":
    main()
