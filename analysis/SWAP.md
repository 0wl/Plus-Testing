# SWAP + FEC — map

Source binary: `extracted/swap/tsd/bin/swap/tsd.mibstd2.system.swap`
QNX ARM ELF, 619 KB, stripped.

## What SWAP is
TechniSat's **SWaP (Software-Pack)** subsystem. It owns:
- **FEC manager** — Feature Enable Codes. A FEC is a signed blob that grants a vehicle unit permission to run a set of FSIDs (Feature Set IDs).
- **FSID store** — the current granted-permissions snapshot, stored persistently (RPMB-backed on eMMC).
- **Exception list consumer** — `/tsd/etc/slist/signed_exception_list.txt` can grant permission for FSIDs without a real FEC, when the list is signed and the unit's FAZIT is listed.
- **Code swaps** — swap codes change which FSIDs are granted (dealer-level adjustments).

## FSID vocabulary (sampled from swap strings)
4-char codes `[0-9][0-9][A-Z][A-Z]` appear as FSID tokens:
`10FE 10SF 10VI 11BP 11DS 11FE 11IC 11NP 11OC 11SF 11SP 11VC 11VI 12BP 12DS 12EX 12FE 12IF 12ML 12OC 12OS 12SP 12VC 13EX 13ML 13OS …`
These are compact IDs. The 2-letter suffix likely encodes a category — `SP`=standard+, `OS`=online services, `ML`=mirrorlink, `IC`=iconnect, `VI`=video, `NP`=navigation+, etc. (inference, needs confirmation by cross-referencing metainfo module names.)

## Keys trusted by SWAP (binary paths)
Found in `/tsd/etc/swap_keys/`:
- `FEC_key_public_signed.bin` (288 B) — RSA-1024 public key for verifying FEC signatures. Unique.
- `Metainfo_key_public_signed.bin` (288 B) — RSA-1024 public key for metainfo2.txt signatures. **Byte-identical to `Data_key_public_signed.bin`** in this firmware.
- `Data_key_public_signed.bin` (288 B) — RSA-1024 public key for signed data blobs (incl. exception list signature). Identical to Metainfo key.
- `/tsd/etc/swap/Unknown_key_public_signed.bin` — referenced in strings, present at runtime (not shipped in `swapkeys_sec_vw` partition).

Each 288-byte file layout (inferred from size): 128-byte RSA-1024 modulus + 4-byte public exponent + 128-byte signature-over-modulus-by-root-key + 28 bytes header/metadata. Verified authenticity by `trustedservices`:
- `BPRK_RESPONSE` / `SPRK_RESPONSE` / `OSPRK_RESPONSE` → Boot/SWaP/One-Shot Public Root Key — root key is hashed and compared against OTP-fused hash on the SoC (TI J5 secure boot).
- String `authenticity check of root key successful/failed`.

## Exception list — THE primary bypass path
Strings:
- `parsed exception list successfully`
- `is part of exception list, passing exception list to FEC manager`
- `is stated on exception list and therefor permission is granted`
- `as per exception list permission for all FSIDs is granted`
- `FSID is not covered by exception list`
- `Exception list covers FAZIT string, consider exception list.`
- `Exception list does not cover FAZIT string, ignore exception list.`
- `signature of exception list is valid/invalid`
- `FAZIT string is empty, ignore exception list.`
- `retention period is over, FEC manager is not ready and no signed exception list is available: `

Mechanics (inference):
1. On boot, SWAP looks for `/tsd/etc/slist/signed_exception_list.txt`.
2. Verifies the list's signature with one of the trusted keys (likely `Data_key` since Metainfo_key = Data_key — same family).
3. Checks whether the unit's FAZIT string (unique production ID, factory-burned) is covered by the list's FAZIT selector.
4. If it is, the listed FSIDs are granted without needing a real FEC.
5. Fallback: a retention period of grace exists where FEC manager can be non-ready if a signed list is present.

→ If a valid signed exception list that covers any FAZIT (wildcard) and grants the app-connect FSIDs existed, we'd be done. Without the private `Data_key` signing key, we can't forge one.

## FEC storage
- `FECStoreRPMB` class present → FEC is stored in the eMMC's **RPMB** (Replay Protected Memory Block) partition, authenticated by an eMMC key the SoC holds. SD cannot touch RPMB.
- `ALIVE_MESSAGE_FEC_ENABLING` / `DISABLING`, `FEC_ENABLE_RESPONSE`, `FEC_DISABLE_RESPONSE`, `FEC_READ_RESPONSE`, `FEC_STORAGE_RESPONSE`, `FSID_STATUS_RESPONSE` — UDS/DSI event namespace.
- `FEC version %#04x is not supported` — FEC blobs have a version field.

## Signature-check skip
- `Skip signature check: …` — literal present. Maps to the same family as SWDL's `Signature is skipped.`
- `skip_signature_check_flag` — named flag variable inside SWAP. Needs Ghidra follow-up to find how it gets set (dev-build only vs field-togglable).

## Why MH2p sign attempts failed
Given the FEC key is unique and OTP-anchored, forging an MH2p-class SWaP code (an FEC) is infeasible from outside. The failure is not a bug — it's the designed root of trust. The only forgery-free surfaces are:
- A signed exception list (needs leaked Data_key private).
- The sig-skip flag path (if reachable without root compromise).
- A dealer-mode UDS routine that writes to RPMB on behalf of an authenticated session (requires VW's SA 27 keys).

## Next steps (Ghidra)
- Resolve `skip_signature_check_flag` setter chain in both SWDL and SWAP.
- Read `signed_exception_list.txt` parser to confirm key id and signature algorithm.
- Dump actual key bytes to check if Unknown_key is a public-devkey (would be interesting).
