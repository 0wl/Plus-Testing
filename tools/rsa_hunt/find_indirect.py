#!/usr/bin/env python3
"""
QNX ARM binary uses base+offset addressing. Strings in rodata are NOT referenced
by direct 32-bit absolute LDR literals — they are referenced via a pointer
table (usually .data.rel.ro / .got).

Pipeline:
  1. Find target string VAs.
  2. Scan the FULL binary (not just .text) for 32-bit LE occurrences — those
     are the pointer-table entries.
  3. For each pointer-table entry, the entry's VA is itself what .text loads
     via a GOT-offset pattern. Scan .text for 32-bit LE occurrences of that
     pointer-table VA. If zero hits, the compiler may be loading the pointer
     table via a PIC base register — then dump the surrounding table and the
     offset of our entry inside it.
"""
import struct, os, capstone

ELF = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
      "extracted", "swap", "tsd", "bin", "swap", "tsd.mibstd2.system.swap"))

TARGETS = [
    (0x0017c044, "RSA calculation failed"),
    (0x0017a88f, "signature is invalid"),
    (0x0017a8a4, "signature is valid"),
    (0x0017c2be, "no signature section found in elf file"),
    (0x0017c361, "checking elf signature using SHA-1 hash algorithm not supported by now"),
    (0x001099f1, "skip_signature_check_flag"),
    (0x0017e5b1, "Skip signature check: "),
    (0x0017a84e, "checking signature of FEC, using"),
]


def parse_elf(buf):
    assert buf[:4] == b"\x7fELF"
    e_phoff = struct.unpack_from("<I", buf, 0x1c)[0]
    e_phentsz = struct.unpack_from("<H", buf, 0x2a)[0]
    e_phnum = struct.unpack_from("<H", buf, 0x2c)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i*e_phentsz
        p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags, _ = \
            struct.unpack_from("<IIIIIIII", buf, off)
        if p_type == 1:
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


def find_all_u32(buf, value):
    needle = struct.pack("<I", value)
    out = []
    i = 0
    while True:
        j = buf.find(needle, i)
        if j < 0: break
        out.append(j)
        i = j + 1
    return out


def main():
    buf = open(ELF, "rb").read()
    segs = parse_elf(buf)

    # Build a set of executable VA ranges
    exec_ranges = [(v, o, s) for v, o, s, f in segs if f & 1]

    for str_va, label in TARGETS:
        print(f"\n### {label}  (VA 0x{str_va:08x})")
        hits = find_all_u32(buf, str_va)
        if not hits:
            print("  no 32-bit occurrences at all — maybe loaded by arithmetic")
            continue
        for fo in hits:
            ref_va = fo_to_va(segs, fo)
            if ref_va is None:
                print(f"  FO 0x{fo:x}: outside any segment")
                continue
            # Is this inside .text (executable) or data?
            in_exec = any(v <= ref_va < v+s for v, _, s in exec_ranges)
            tag = "TEXT" if in_exec else "DATA"
            print(f"  FO 0x{fo:x}  VA 0x{ref_va:08x} [{tag}]")
            # If data, then ref_va is a pointer-table slot; find who loads it.
            if not in_exec:
                # Scan .text for 32-bit LE occurrences of ref_va
                table_hits = find_all_u32(buf, ref_va)
                for thfo in table_hits:
                    thva = fo_to_va(segs, thfo)
                    if thva is None: continue
                    tag2 = "TEXT" if any(v <= thva < v+s for v, _, s in exec_ranges) else "DATA"
                    print(f"      <-- pointer-slot VA 0x{ref_va:08x} is referenced @ VA 0x{thva:08x} [{tag2}] FO 0x{thfo:x}")


if __name__ == "__main__":
    main()
