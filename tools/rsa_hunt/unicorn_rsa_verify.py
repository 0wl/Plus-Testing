#!/usr/bin/env python3
"""
Unicorn ARM harness that runs the REAL swap binary's RSA modpow function
(FUN_0017b438 @ VA 0x0017b438 in the Ghidra-loaded cpu.system.swap build)
and verifies its output matches Python's integer pow(sig, 3, N).

Then it runs the SAME real function on our Bleichenbacher '06 forged
signature, pipes the result through the SAME expected-PKCS layout the
caller (FUN_0016e194 + FUN_0016e760) builds, and does the full-128 memcmp
that FUN_0016e760 does. Reports ACCEPT/REJECT for each.

This is end-to-end empirical proof — real ARM bytecode, not an abstract
model — of whether the production verifier accepts the forge.

Bytes come from the Ghidra memory dump of FUN_0017b438 (+ helpers
FUN_0017b3bc and FUN_0017b08c), mapped at their original VAs. The
__aeabi_uidiv thunk is replaced by an in-harness hook (uc.reg_read + Python
division + ret).

Requires: unicorn >= 2.0
Usage:    python unicorn_rsa_verify.py
"""
import hashlib, os, re, struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR,
)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GHIDRA_DUMP = os.path.join(ROOT, "tools", "rsa_hunt", "fun_0017b438.bin")

# VAs in the Ghidra-loaded cpu.system.swap
FUN_RSAEXP  = 0x0017b438   # modpow entry point
FUN_HELPER1 = 0x0017b3bc   # byteswap-copy
FUN_HELPER2 = 0x0017b08c   # subtract-reduce
RANGE_LO    = 0x0017b000
RANGE_HI    = 0x0017c000   # 4KB covers 0x17b000..0x17b8bf

# PLT thunk for __aeabi_uidiv — any BL here is replaced by our Python hook
AEABI_UIDIV = 0x0010fd44

# Memory map for Unicorn
CODE_BASE = 0x0017b000
CODE_SIZE = 0x1000         # 4KB — holds our RSA function + helpers
PLT_BASE  = 0x0010f000
PLT_SIZE  = 0x1000
DATA_BASE = 0x40000000
DATA_SIZE = 0x4000         # buffers + stack
STACK_TOP = DATA_BASE + DATA_SIZE - 0x100
SENTINEL  = 0xdeadbeef

SHA1_DI = bytes.fromhex("3021300906052b0e03021a05000414")


def dump_ghidra_bytes():
    """Load the 4KB Ghidra memory dump of the RSA code region from disk."""
    data = open(GHIDRA_DUMP, "rb").read()
    assert len(data) == 0x1000, f"expected 4KB, got {len(data)}"
    return data


def load_sig_from_metainfo(path):
    txt = open(path, "rb").read().decode("latin1")
    sig_hex = ""
    for i in range(1, 9):
        m = re.search(rf'^signature{i}\s*=\s*"([0-9a-fA-F]+)"', txt, flags=re.MULTILINE)
        sig_hex += m.group(1)
    return bytes.fromhex(sig_hex)


def signed_slice_sha1(path):
    """Match the toolbox's canonical slice: raw bytes up to [Signature]."""
    raw = open(path, "rb").read()
    i = raw.find(b"[Signature]")
    return hashlib.sha1(raw[:i]).digest()


def build_expected_pkcs(digest, k=128):
    """What FUN_0016e194 builds in C++: 00 01 FF*(k-35-3) 00 digestInfo || digest."""
    em_prefix = SHA1_DI + digest
    pad = k - len(em_prefix) - 3
    assert pad >= 8
    return bytes([0, 1]) + b"\xff" * pad + bytes([0]) + em_prefix


def run_modpow(code_bytes, sig, modulus, exp_bytes_be128):
    """Run FUN_0017b438 in Unicorn: returns the 128-byte decoded output."""
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(CODE_BASE, CODE_SIZE)
    uc.mem_map(PLT_BASE,  PLT_SIZE)
    uc.mem_map(DATA_BASE, DATA_SIZE)
    uc.mem_write(CODE_BASE, code_bytes)
    # Write a placeholder BX LR into the PLT thunk so even if we miss the
    # hook the emulator won't crash on fetch.
    bx_lr = struct.pack("<I", 0xe12fff1e)
    for off in range(0, PLT_SIZE, 4):
        uc.mem_write(PLT_BASE + off, bx_lr)

    sig_addr = DATA_BASE + 0x0000
    mod_addr = DATA_BASE + 0x0100
    exp_addr = DATA_BASE + 0x0200
    out_addr = DATA_BASE + 0x0300
    assert len(sig) == 128 and len(modulus) == 128 and len(exp_bytes_be128) == 128
    uc.mem_write(sig_addr, sig)
    uc.mem_write(mod_addr, modulus)
    uc.mem_write(exp_addr, exp_bytes_be128)
    uc.mem_write(out_addr, b"\x00" * 128)

    # ARM calling convention: r0..r3 = first 4 args
    uc.reg_write(UC_ARM_REG_R0, sig_addr)
    uc.reg_write(UC_ARM_REG_R1, mod_addr)
    uc.reg_write(UC_ARM_REG_R2, exp_addr)
    uc.reg_write(UC_ARM_REG_R3, out_addr)
    # CPSR must be written BEFORE SP — mode switch banks SP per-mode.
    uc.reg_write(UC_ARM_REG_CPSR, 0x10)   # user mode, ARM state
    uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM_REG_LR, SENTINEL)

    # __aeabi_uidiv hook: r0 = r0 / r1
    def uidiv_hook(uc, address, size, user_data):
        if address == AEABI_UIDIV:
            a = uc.reg_read(UC_ARM_REG_R0) & 0xffffffff
            b = uc.reg_read(UC_ARM_REG_R1) & 0xffffffff
            q = (a // b) & 0xffffffff if b != 0 else 0
            uc.reg_write(UC_ARM_REG_R0, q)
            lr = uc.reg_read(UC_ARM_REG_LR)
            uc.reg_write(UC_ARM_REG_PC, lr)

    def bad_mem(uc, access, addr, size, value, user):
        print(f"[!] unmapped mem access @ 0x{addr:x} size={size} pc=0x{uc.reg_read(UC_ARM_REG_PC):x}")
        return False

    uc.hook_add(UC_HOOK_CODE, uidiv_hook, begin=AEABI_UIDIV, end=AEABI_UIDIV+3)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, bad_mem)

    try:
        uc.emu_start(FUN_RSAEXP, SENTINEL, timeout=30_000_000, count=50_000_000)
    except Exception as e:
        pc = uc.reg_read(UC_ARM_REG_PC)
        # BX LR masks bit 0 for ARM state → sentinel-1 is expected halt
        if pc not in (SENTINEL, SENTINEL - 1, SENTINEL & ~1):
            print(f"[!] emu halted unexpectedly: {e}  pc=0x{pc:x}")
            return None, None

    retval = uc.reg_read(UC_ARM_REG_R0) & 0xffffffff
    out = bytes(uc.mem_read(out_addr, 128))
    return retval, out


def main():
    # Write the Ghidra dump the first time (bytes baked in below)
    code = dump_ghidra_bytes()

    # Load pubkey
    pub = open(os.path.join(ROOT, "extracted", "swapkeys", "tsd", "etc",
               "swap_keys", "tmp", "Metainfo_key_public_signed.bin"), "rb").read()
    modulus = pub[:128]
    exp_be128 = b"\x00" * 124 + struct.pack(">I", 3)

    def run_one(label, metainfo_path, sig_override=None):
        sig = sig_override or load_sig_from_metainfo(metainfo_path)
        digest = signed_slice_sha1(metainfo_path)
        ret, out = run_modpow(code, sig, modulus, exp_be128)
        expected = build_expected_pkcs(digest)
        pyout = pow(int.from_bytes(sig, "big"), 3,
                    int.from_bytes(modulus, "big")).to_bytes(128, "big")
        print(f"\n### {label}")
        print(f"  sig[:16]       : {sig[:16].hex()}")
        print(f"  digest         : {digest.hex()}")
        print(f"  unicorn ret    : {ret}  (0 = ok)")
        print(f"  unicorn out[:16]: {out[:16].hex() if out else 'N/A'}")
        print(f"  python  out[:16]: {pyout[:16].hex()}")
        print(f"  match python   : {out == pyout}")
        print(f"  expected[:16]  : {expected[:16].hex()}")
        print(f"  expected[-16:] : {expected[-16:].hex()}")
        print(f"  decoded[-16:]  : {out[-16:].hex() if out else 'N/A'}")
        if out is not None:
            accept = (out == expected)
            print(f"  FULL-128 MEMCMP VERDICT: {'ACCEPT' if accept else 'REJECT'}")
            if not accept:
                for i, (a, b) in enumerate(zip(expected, out)):
                    if a != b:
                        print(f"    first diff @ offset {i} (0x{i:x}): expected {a:02x}, got {b:02x}")
                        break

    # 1) Stock signed toolbox metainfo (should ACCEPT)
    stock_path = os.path.join(ROOT, "extracted", "toolbox", "metainfo2.txt")
    run_one("STOCK — signed by TechniSat", stock_path)

    # 2) Bleichenbacher '06 forged metainfo (should REJECT under tight verifier)
    forge_path = os.path.join(ROOT, "tools", "rsa_hunt", "fixtures", "forge_test.txt")
    if os.path.exists(forge_path):
        run_one("FORGE — Bleichenbacher '06 e=3", forge_path)
    else:
        print(f"[!] no forge fixture at {forge_path} — run forge_custom_metainfo.py first")


# ---------- bytes from Ghidra read_memory @ 0x17b000 len=0x1000 ----------
GHIDRA_DUMP_HEX = """
"""

if __name__ == "__main__":
    main()
