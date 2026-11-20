# Crypto + Trust chain — map

## Chain summary (signed)
```
TI J5 OTP SRK hash
   └─ Boot Public Root Key (BPRK) blob — verified by hash match → trusted
         └─ SWaP Public Root Key (SPRK) — verified by BPRK
         └─ One-Shot Public Root Key (OSPRK) — verified by BPRK
         └─ FEC_key_public_signed.bin (RSA-1024 pub) — verified by root key chain
         └─ Metainfo_key_public_signed.bin == Data_key_public_signed.bin (RSA-1024 pub)

Metainfo_key signs:
   - metainfo2.txt (RSA-1024 sig, 128 B = 8 × 16-byte chunks in `[Signature]` section)
   - hashes.txt entries (checksums)
   - module archives (via hashes.txt tying SHA-1 Checksum, multi-Checksum1..18 chunked SHA-1)

FEC_key signs:
   - each FEC blob (SWaP code)
   - MH* / LH* / BB* class SWaP codes

Data_key (== Metainfo_key) signs:
   - /tsd/etc/slist/signed_exception_list.txt  (the FAZIT-scoped FSID grant list)
```

## Primitives
- RSA-1024 everywhere (verified by signature sizes).
- SHA-1 hashing (`ext.cryptolib/lib/src/sha_1.c`) — `checking elf signature using SHA-1 hash algorithm not supported by now` string indicates SHA-1 is DEPRECATED in this build's verify path for ELFs. Interesting divergence (binaries still use SHA-1 in `.tsdsignature` section but verify may skip it).
- No EC. No PKCS#11.

## ELF binary signature (`.tsdsignature` section)
Both SWDL, SWAP, trustedservices, testinterface ELFs have the `.tsdsignature` section. Strings:
- `: Correct signature in ELF file "…"`
- `: Correct signature in …`
- `: Signature missing in …`
- `no signature section found in elf file`
- `checking elf signature using SHA-1 hash algorithm not supported by now`
- `.gnu_debuglink`

Observation: the `.tsdsignature` is a DT_NOTE-style appended section containing a single RSA-signed hash of the ELF image. Verified at launch (by startup / mount_ifs chain). Modifying an ELF without re-signing fails.

## trustedservices binary — the root-key guardian
Binary: `extracted/trusted/tsd/bin/trustedservices/tsd.mibstd2.system.trustedservices`
- Serves `BPRK_REQUEST` / `SPRK_REQUEST` / `OSPRK_REQUEST` events, returns the respective root keys.
- Verifies root-key authenticity by hashing and comparing to OTP (`root key read hash: …`, `root key calced hash: …`).
- `authenticity check of root key failed` / `successful`.
- Exposes RSA_verify entry point.
- Issuer string in cert data: `"CCC Root CA1"` — ConnectedCar Consortium / vehicle root CA.
- `qnx:root` — runs as root:root under QNX.

## Where keys could come from (threat model)
- **Firmware tree** — public keys shipped in `swapkeys_sec_vw` partition. PRIVATE counterparts never shipped.
- **Leaked signing keys** — if private keys were ever leaked publicly, that would enable forgery. Not assumed available here.
- **Weak-RNG derivation** — RSA-1024 is weak vs. modern. 1024-bit factoring is not feasible on commodity HW (>>$1M + months). Not practical.

## Where the chain IS brittle
1. **Flag paths** — `skip_signature_check_flag` + `Signature is skipped.` + `Skip signature check:` strings indicate explicit skip branches reachable under certain conditions. If the condition is a config file read from writable storage, we have a hole.
2. **Service mode** — dealer / engineering sessions get relaxed checks (`Customer updates are not allowed in service mode!` is the inverse: in service mode the SWDL customer gate is off, so dealer updates CAN run).
3. **Pre-sig parser bugs** — the INI parser for metainfo2.txt and the TAR extractor for module archives are large attack surfaces for a corrupt input that triggers code execution BEFORE the signature is checked.
4. **Downgrade** — an older firmware with a weaker sig algorithm or a known bug; version-check of metainfo may allow downgrade.

## Hot leads
- Confirm the `skip_signature_check_flag` conditions (Ghidra).
- Dig for "engineeringMode" / "developerMode" booleans in testinterface and trustedservices (UDS SA-controlled).
- Inspect the INI/TAR parsers for pre-verify side effects.
