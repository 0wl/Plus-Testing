# Progress Log — SD-Only App Connect Install

Running log of what the bench has done, what is on the rail, what is left. Updated on every phase step.

Legend: ✅ done · ⏳ in progress · ◻ pending · ✗ failed/blocked

## Phase 1 — Inventory & scaffolding
- ✅ Surveyed project root; identified firmware `MST2_EU_VW_ZR_P0254T/`, toolbox ISO `mib-std2-pq-zr-toolbox-master.iso`, prior OTG analysis.
- ✅ Created `Plus Testing/` with subdirs: `analysis/`, `extracted/`, `ghidra_projects/`, `sd_installer/`.
- ✅ Moved firmware into `Plus Testing/MST2_EU_VW_ZR_P0254T/`.
- ✅ Copied prior OTG analysis to `analysis/00-prior-OTG-analysis.md`.
- ✅ Copied toolbox ISO into `extracted/toolbox.iso`.

## Phase 2 — Extract & strings
- ✅ Extracted `mainstd/swdownload_sec/9/default/*.tar.gz` → `extracted/swdownload_sec/`.
  - Payload: `tsd/bin/swdownload/tsd.mibstd2.system.swdownload` (QNX ARM ELF, 1.54 MB, stripped).
  - `tsd/etc/swdownload/modules/swdownload.info` — RSA-1024 base64 `Signature`.
- ✅ Extracted `mainstd/swap/9/default/*.tar.gz` → `extracted/swap/`.
  - Payload: `tsd/bin/swap/tsd.mibstd2.system.swap` (QNX ARM ELF, 619 KB, stripped).
  - `tsd/etc/swdownload/modules/swap.info` — RSA-1024 base64 `Signature`.
- ✅ Strings dump done with Python (swdl, swap, trusted, testinterface, debugtool, emmcrefresh).
- ✅ Extracted swapkeys, trustedservices, debugtool_sec, config_EU_sec, testinterface, mainbspfs, emmcrefresh.
- ✅ Copied mainboot_sec/init_mibstd2radio_sec.dat, startup/startup.boot, carcom_m0 boot.signed for later Ghidra pass.

## Phase 3 — Map SWDL pipeline
- ✅ Strings → symbol candidates; UDS routines (Quellenwahl + SWDL_Start) identified.
- ✅ metainfo2.txt layout + [Signature] format (RSA-1024 split across 8 × 32-hex) decoded.
- ✅ Key paths mapped: /tsd/etc/swap_keys, /tsd/etc/slist/signed_exception_list.txt, SYSTEM_RUNMODE switch.
- ✅ `analysis/SWDL.md` written.
- ◻ Ghidra: find skip_signature_check_flag setter + Quellenwahl enum values.

## Phase 4 — Map SWAP engine
- ✅ FEC manager / exception list consumer / FECStoreRPMB identified.
- ✅ 3 public keys (FEC, Metainfo, Data) cataloged; Metainfo == Data byte-identical.
- ✅ FSID 4-char ID vocabulary partially sampled.
- ✅ `analysis/SWAP.md` written.
- ◻ Ghidra: resolve FSID→name table + skip flag chain.

## Phase 5 — Map FEC handler
- ✅ FEC class hierarchy enumerated (FunctionEnabling / KeyExchange / SecureCoding / Individualization specific parts).
- ✅ FEC storage in RPMB confirmed → SD cannot touch RPMB directly.
- ✅ Exception list bypass path mapped: FAZIT-scoped signed list grants FSIDs w/o FEC.
- ✅ `analysis/FEC.md` written.
- ◻ App-connect FSID codes (12ML, 13ML, etc.) need cross-ref confirmation.

## Phase 6 — Map boot/install
- ✅ Two-CPU boot chain recapped (J5 + iMX6).
- ✅ /tsd/bin/system/startup critical staging logic captured (tsd/tmp/hmi → /tsd/hmi atomic move).
- ✅ testinterface auto-activation path captured (/tsd/var/testinterface binary flips to factory config).
- ✅ SYSTEM_RUNMODE normal vs swdl recognized (radio.conf vs radio_swdl.conf).
- ✅ `analysis/BOOT.md` written.

## Phase 7 — Crypto chain
- ✅ Root chain documented: J5 OTP SRK → BPRK/SPRK/OSPRK → FEC/Metainfo/Data keys.
- ✅ Primitives: RSA-1024 + SHA-1 everywhere.
- ✅ .tsdsignature ELF section mechanism documented.
- ✅ `analysis/CRYPTO.md` written.
- ◻ Ghidra: find flag paths + ELF-sig enforcement site.

## Phase 8 — Metainfo graph
- ✅ Parser written (tools/parse_metainfo.py), graph dumped to analysis/metainfo_full.json + metainfo_summary.json.
- ✅ Confirmed device-name mismatch: toolbox targets `cpu` (NAV), STD PLUS uses `cpuplus`.

## Phase 9 — Toolbox audit
- ✅ ISO extracted to extracted/toolbox/.
- ✅ install.sh behavior captured; drop-in anchors enumerated.
- ✅ custom/fec, custom/swap, custom/swdl, custom/greenmenu drop-ins confirmed.
- ✅ Toolbox metainfo is RSA-1024 signed for 17222 (STD PLUS) — BB06 is NOT the blocker.
- ✅ `analysis/TOOLBOX.md` written.

## Phase 10 — SD-only install design
- ✅ Primary path CHOSEN: GEM-gated metainfo Skip* flags (SkipSignatureCheck, SkipCheckVariant, SkipMetaChecksum, SkipChecksum, SkipCheckRegion, SkipFileCopyChecksum).
- ✅ Gate: GEM on (via OBD adaptation of block 5F) → SwdlGem::receiveGEMRead → getUserDefinedAllowed returns true → Skip* honoured.
- ✅ Payload re-targeted at cpuplus\* instead of cpu\* so SWDL actually matches on STD PLUS.
- ✅ analysis/SD-ONLY.md written.

## Phase 11 — Build installer
- ✅ tools/build_sd_installer.py written — assembles metainfo + per-module archives.
- ✅ sd_installer/ tree built: cpuplus/{esd_sec, swap, swdownload_sec, testinterface_sec}/15/default/*.tar.gz + hashes.txt + module.ref.
- ✅ cpuplus_esd_sec_15_default.tar.gz = STOCK esd merged with TOOLBOX ESD defs + activate scripts (147 files).
- ✅ sd_installer/README.md written with step-by-step procedure.
- ◻ Replace stock swap + swdownload archives with patched binaries (not shipped in current toolbox ISO — drop-in slots left in tools/custom/swap, tools/custom/swdl for user to add).

## Phase 12 — Testing
- ✅ tools/validate_metainfo.py written — replays SWDL gate checks over the built SD.
- ✅ Dry-run PASSES: sig=skipped, variant=skipped, 4 payload archives present, zero device mismatches.
- ✅ analysis/TESTING.md written with offline checks and on-unit checklist.
- ◻ Live trial on a real STD PLUS unit — requires hardware (user).
- ◻ Ghidra confirm of SkipSignatureCheck ordering wrt checkSignature.

## Open questions / stalls
- BB06 metainfo signing "failed" → RESOLVED: metainfo IS validly signed for 17222 in stock toolbox; the real blocker on STD PLUS is probably the HMI Service Mode entry missing (no visible SW Update screen).
- MH2p swap-code signing failed → RESOLVED: FEC private key is OTP-root-anchored, forgery infeasible. Bypass sits elsewhere (exception list, dealer UDS routine, or skip-flag abuse).
- OPEN: exact Quellenwahl source enum value (CSD1 vs CSD2) and whether it is accepted on a 1-slot variant.
- OPEN: exact variants 47213–47216 are not in any shipped metainfo — adding them would need re-signing.
- OPEN: dealer UDS routine IDs for writing exception list / testinterface binary.

## Phase 13 — Deep RE + verifier flaw hunt (new, per Olivia's steer)
- ✅ RE finding: metainfo key strings (SkipSignatureCheck, Variant, FileName, Checksum, Link, MetafileChecksum, etc.) have ZERO 32-bit absolute-address references in the SWDL ELF. Parser uses base-anchor + per-key offset addressing (QNX-style PIC pattern).
- ✅ Implication: direct xref search for "where is SkipSignatureCheck honoured?" can't use a byte-pattern approach — need to find the anchor pointer first.
- ✅ analysis/PARSER-ATTACK.md written — 8 pre-sig-check attack surfaces mapped (INI parser quirks, hashes.txt, tar extraction symlink/path-traversal, ELF .tsdsignature unsupported-algo, FEC version branch, User-Defined SWDL side, [Signature] section parse flaws, length-truncation / SHA-1 renormalisation).
- ⏳ Open: locate the anchor + build a key-offset map so we can follow SkipSignatureCheck in code.
- ⏳ Open: Unicorn harness for SWDL metainfo-parse path (no QNX kernel needed for parse phase).
- ⏳ Open: fuzz metainfo / hashes.txt / tar extractor for pre-sig-check code exec.
- ⏳ Open (parallel): full QNX6 qemu stand-up using firmware's own IFS.

## Open questions / stalls (updated)
- Signature can be skipped only by (a) a flag set BEFORE the sig check, (b) an input that triggers code exec BEFORE the sig check, or (c) a path that bypasses SWDL entirely.
- The SkipSignatureCheck flag's effectiveness in production builds is now uncertain — RE suggests the log strings are present but no direct code xref was found yet. Must confirm via Unicorn harness or deeper disasm.
- Variant list editing unblockably invalidates the sig — confirmed. Any variant expansion path must go through sig skip (a) or input-side flaw (b).

## Phase 14 — RSA verifier reverse + Bleichenbacher '06 falsification (NEW)
- ✅ Ghidra MCP connected; cpu.system.swap auto-analyzed (761 functions).
- ✅ Located xrefs to RSA-related strings. Anchors: "RSA calculation failed" at FUN_0016bd44 (raw RSA); "signature is valid/invalid" at FUN_001454e0 (FEC sig wrapper); "signature of exception list is valid/invalid" at FUN_001212f0 (exception-list verifier); "signature of key file is valid/invalid" at FUN_0011f890 (key-chain verifier); "no signature section"/"SHA-1 hash algorithm not supported" at FUN_0016f0d0 (ELF .tsdsignature verifier).
- ✅ Decompiled FUN_001b16c8 (FEC crypto dispatcher) → calls FUN_0016e760 with (hash_algo=1 SHA-1, encoding=1 PKCS#1_v1.5, hash_len=0x14, key_payload+128, 0x80, msg, msg_len, sig, sig_len, 1).
- ✅ Decompiled FUN_0016e760 (verifier core): builds expected PKCS via FUN_0016e194, decodes sig via FUN_0016bd44 (raw RSA s^e mod N), then **memcmp of FULL 128-byte buffers** → return 1 iff equal else 0.
- ✅ Decompiled FUN_0016e194: expected buffer layout is `0x00 0x01 FF*(k - 3 - em_len) 0x00 digestInfo || hash`. For k=128, em_len=35, pad = **FF*90**. TIGHT PKCS#1 v1.5 — zero garbage tolerated.
- ✅ Decompiled FUN_0016bd44 (raw RSA) and FUN_0017b438 (big-int modpow): plain Montgomery-style s^e mod N over 128-byte big-endian buffers.
- ✅ **Bleichenbacher '06 forge CANNOT pass this verifier.** Forge produces decoded message `0x00 0x01 FF*6 0x00 digestInfo hash + 84B math-residue tail`. Memcmp fails at offset 8 (expected FF, got 00).
- ✅ Offline model (`tools/rsa_hunt/verify_forge_against_tight.py`) + cube-decode + slice-identify (`tools/rsa_hunt/extract_signed_hash.py`, `find_signed_slice.py`) → identified actual signed slice = raw bytes of metainfo2.txt up to `[Signature]` (CRLF preserved; latin1 text-mode read had been stripping \r and breaking prior hash computation).
- ✅ **Unicorn ARM harness (`tools/rsa_hunt/unicorn_rsa_verify.py`) runs the real ARM bytecode of FUN_0017b438.** 4 KB of code dumped from Ghidra, mapped at 0x17b000, __aeabi_uidiv hooked for Python division. Verified:
   - STOCK sig → unicorn ret=0, output matches Python pow(s,3,N), full-128 memcmp = **ACCEPT** (prefix+hash exact).
   - FORGED sig → unicorn ret=0, output matches Python pow(s,3,N), full-128 memcmp = **REJECT** at offset 0x8 (expected FF, got 00).
- ✅ End-to-end empirical proof that Bleichenbacher '06 is dead on this binary. Exception list uses same crypto → also dead. FEC key uses same crypto → also dead. **Sig forging is NOT a viable path.**

## Phase 15 — Pivot: SkipSignatureCheck flag and parser-attack re-prioritization
- Primary path confirmed: the SD-ONLY design (`analysis/SD-ONLY.md`) stands. Metainfo with `SkipSignatureCheck = "true"` is the only route, gated by GEM `getUserDefinedAllowed()`.
- Next anchor hunt: in swdl ELF, locate how `SkipSignatureCheck = "true"` string is read from metainfo, how `skip_signature_check_flag` member is set, and the branch that guards the call to `checkSignature`. Ghidra MCP ready — proceed with equivalent xref hunt against cpu.swdownload in next phase.
- Parallel: parser-attack surfaces in PARSER-ATTACK.md (pre-sig-check INI parsing bugs, tar extraction symlink/traversal, `.tsdsignature` unsupported-algo early-return, ELF sig algo-id confusion) remain the only route if GEM flag is NOT honored in production.

## Phase 16 — personalpoi metainfo signature bypass (NEW — primary path)
- ✅ Opened `cpu.swdownload` in Ghidra; auto-analysis complete (3900+ functions).
- ✅ Located `checkSignature` at FUN_001a97e4 and its "SkipSignatureCheck = \"true\", will not check..." string emitter. Reading the decompile: that log is emitted when the SIGNED EXCEPTION LIST contains a SkipSignatureCheck flag covering the FAZIT. Requires a signed exception list → requires Data_key private → DEAD per Phase 14 crypto findings.
- ✅ Located `parseCommonSection` at FUN_001aa4fc. The RSA metainfo verify is called ONLY WHEN its 4th parameter (`skip_flag`) is 0. If skip_flag is nonzero, the log prints "parseCommonSection  Signature is skipped." and the verify is skipped entirely.
- ✅ Traced skip_flag source via FUN_001b5194 (parseIniMap): skip_flag = `FUN_001a4178(state)` = `isSkippingSignature(state)`.
- ✅ Decompiled `isSkippingSignature` (FUN_001a4178): returns 1 (SKIP) iff:
   (a) metainfo contains a `[personalpoi]` section, AND
   (b) every other section name contains one of `{"common", "Common", "signature", "Signature", "personalpoi"}` as a substring.
- ✅ Impact: a metainfo whose non-signature/non-common sections are named like `[cpuplus\personalpoi\swdl\15\default\Application]` passes the test → sig verify entirely skipped. **NO FORGE REQUIRED.**
- ✅ Also confirmed per-field Skip flags in metainfo `[common]`:
   - `SkipFileCopyChecksum` → state[0xe5]
   - `SkipChecksum` → state[0xe4]
   - `SkipMetaChecksum` → gates FUN_00189b34(state, MetafileChecksum) call; if nonzero, no checksum compare.
   - `SkipSaveTrainName`, `EnableUserDefinedSWDLMode`, `MaxParallelDevices`, `ExclusiveUpdate`, `UseSubDirs` all read from metainfo.
- ✅ `analysis/PERSONALPOI-BYPASS.md` written.
- ⏳ Open: trace the device-walker that matches `[device\module\...]` sections on target unit. Needs decomp of module-matcher. Determines if we must use `[cpuplus\personalpoi\<module>\...]` naming OR if the dedicated personalpoi install handler is the ingestion point.
- ⏳ Open: Unicorn-emulate FUN_001a4178 with a crafted INI map to empirically confirm return value == 1 for the attack metainfo shape.
- ⏳ Open: rebuild `sd_installer_forge/metainfo2.txt` (or create new `sd_installer_personalpoi/`) in the bypass shape once device-walker constraints confirmed.
- ✅ Device-walker FUN_001b4914 (parseDeviceSections) decompiled. Iterates top-level ini-tree names as device-names, invokes the device's registered callback for each `N\M\<version>\default\` subtree found. On STD PLUS the registered device list includes `personalpoi` via `PersonalPoiImportDevice` (QNX strings: `/tsd/var/nav/personalpoi/`, `TSDEVENT_NAV_BASE_START_PPOI_IMPORT`).
- ✅ Constraint confirmed: attack metainfo cannot contain a top-level `[cpuplus\...]` section (would fail isSkippingSignature's keyword filter). All payload MUST be nested under `[personalpoi\M\V\default\Application]` style sections. The handler is the `PersonalPoiImportDevice` driver.
- ⏳ Open: decompile PersonalPoiImportDevice's install/copy method (vtable entry at offset 0x14). Determines (a) hard-coded `/tsd/var/nav/personalpoi/` extraction target or honors section `Destination=`, (b) extraction order vs the TSDEVENT_NAV_BASE_START_PPOI_IMPORT send (STD PLUS has no NAV subsystem, so the event path is a dead end — but if extraction runs first, we can still land files), (c) tar extraction safety against traversal/symlink.

## Next bench steps (ordered)
1. Decompile the PersonalPoiImportDevice.install() virtual method to confirm whether arbitrary payload lands on disk on a STD PLUS unit.
2. If YES: build `sd_installer_personalpoi/` tree with crafted metainfo + personalpoi-nested modules.
3. If destination hard-coded to /tsd/var/nav/personalpoi/: construct a tar entry with ../../../ traversal or symlink pointing at /tsd/etc/persistence/esd/scripts/ to drop the unlock payload.
4. Write Unicorn harness for FUN_001a4178 to confirm bypass return value against the crafted metainfo tree.
5. Package final SD installer with install script.
