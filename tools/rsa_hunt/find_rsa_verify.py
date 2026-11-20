#!/usr/bin/env python3
"""
Anchor-find the RSA padding-check in the SWAP ARM ELF.

Approach:
  1. Parse the ELF (via simple PT_LOAD scan — no pyelftools dep required).
  2. Locate the file-offset of rodata strings "RSA calculation failed",
     ".../ext.cryptolib/lib/src/rsa.c", "EscRsaFe_FromLongFe",
     "signature is invalid", "signature is valid".
  3. Scan .text for ARM-literal references (PC-relative LDRs) to those VAs,
     printing nearby code.
  4. Capstone-disasm 128 bytes around each hit so we can read the branch.

This is the cheapest way to answer: does RSA verify do a byte-compare against
a fixed PKCS layout, or does it scan for the ASN.1 header after 0x00?
"""
import struct, sys, os, capstone

ELF = os.path.join(os.path.dirname(__file__), "..", "..",
                   "extracted", "swap", "tsd", "bin", "swap",
                   "tsd.mibstd2.system.swap")
ELF = os.path.abspath(ELF)

ANCHORS = [
    b"RSA calculation failed",
    b"ext.cryptolib/lib/src/rsa.c",
    b"EscRsaFe_FromLongFe",
    b"EscSha1_ApplyPadding",
    b"signature is invalid",
    b"signature is valid",
    b"checking signature of FEC, using",
    b"no signature section found in elf file",
    b"checking elf signature using SHA-1 hash algorithm not supported by now",
    b"skip_signature_check_flag",
    b"Skip signature check: ",
]


def parse_elf(buf):
    """Return (base_va_of_text, text_file_off, text_size, segments[(va,off,size)])."""
    assert buf[:4] == b"\x7fELF"
    ei_class = buf[4]  # 1=32,2=64
    ei_data  = buf[5]
    endian = "<" if ei_data == 1 else ">"
    assert ei_class == 1, "expected 32-bit"
    e_phoff   = struct.unpack_from(endian+"I", buf, 0x1c)[0]
    e_phentsz = struct.unpack_from(endian+"H", buf, 0x2a)[0]
    e_phnum   = struct.unpack_from(endian+"H", buf, 0x2c)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i*e_phentsz
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from(endian+"IIIIIIII", buf, off)
        if p_type == 1:  # PT_LOAD
            segs.append((p_vaddr, p_offset, p_filesz, p_flags))
    return segs


def va_to_fo(segs, va):
    for v, o, s, _ in segs:
        if v <= va < v + s:
            return o + (va - v)
    return None


def fo_to_va(segs, fo):
    for v, o, s, _ in segs:
        if o <= fo < o + s:
            return v + (fo - o)
    return None


def find_all(buf, needle):
    out = []
    i = 0
    while True:
        j = buf.find(needle, i)
        if j < 0: break
        out.append(j)
        i = j + 1
    return out


def scan_text_for_va_ref(buf, segs, target_va):
    """Find 32-bit LE occurrences of target_va in executable segs."""
    pattern = struct.pack("<I", target_va)
    hits = []
    for v, o, s, flags in segs:
        if not (flags & 1):  # PF_X
            continue
        seg = buf[o:o+s]
        i = 0
        while True:
            j = seg.find(pattern, i)
            if j < 0: break
            hits.append((v + j, o + j))
            i = j + 1
    return hits


def disasm_around(buf, segs, va, window=96):
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    fo = va_to_fo(segs, va)
    if fo is None:
        return []
    start = max(fo - window, 0)
    data = buf[start:start + window*2]
    start_va = fo_to_va(segs, start)
    out = []
    for insn in md.disasm(data, start_va):
        out.append(f"  {insn.address:08x}: {insn.bytes.hex():<8}  {insn.mnemonic} {insn.op_str}")
    return out


def main():
    buf = open(ELF, "rb").read()
    segs = parse_elf(buf)
    print(f"[+] {ELF}")
    print(f"[+] {len(segs)} PT_LOAD segments")
    for v, o, s, f in segs:
        print(f"    VA=0x{v:08x}  FO=0x{o:08x}  SZ=0x{s:x}  FL={f:#x}")
    print()

    for needle in ANCHORS:
        offs = find_all(buf, needle)
        if not offs:
            print(f"[-] not found: {needle!r}")
            continue
        for fo in offs:
            va = fo_to_va(segs, fo)
            if va is None:
                continue
            print(f"[+] string FO=0x{fo:x} VA=0x{va:08x}  {needle!r}")
            hits = scan_text_for_va_ref(buf, segs, va)
            if not hits:
                # Try pointer-table reference too (the string VA might be referenced
                # via a .data.rel.ro pointer table).
                print(f"    (no direct 32-bit xref; may be via indirect pointer table)")
                continue
            for xva, xfo in hits[:4]:
                # xva is the location of the 32-bit immediate. Back up to the
                # instruction that loads it (usually the preceding LDR literal).
                # Just dump a window around the ref site.
                print(f"    xref @ VA 0x{xva:08x}  (FO 0x{xfo:x})")
                for line in disasm_around(buf, segs, xva - 64, window=32):
                    print(line)
                print()


if __name__ == "__main__":
    main()
