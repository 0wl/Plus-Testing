# SWDL — Software Download — map

Source binary: `extracted/swdownload_sec/tsd/bin/swdownload/tsd.mibstd2.system.swdownload`
QNX ARM ELF, 1.54 MB, stripped, dynamically linked. ELF has a `.tsdsignature` section (embedded signature trailer).

## Files owned by SWDL (paths found in strings)
- `/tsd/bin/swdownload/tsd.mibstd2.system.swdownload` — the binary
- `/tsd/etc/eeprom.ini` — eeprom helper config
- `/tsd/etc/startanim/startup_` — start animation prefix
- `/tsd/etc/swap_keys/` — public-key store (shared with SWAP)
- `/tsd/etc/swap_keys/Metainfo_key_public_signed.bin` — RSA-1024 public key used to verify metainfo signature
- `/tsd/etc/swap_keys.tmp/`, `/tsd/etc/swap_keys/tmp/` — staging dirs for key updates
- `/tsd/etc/swdownload/modules/*.info` — per-module signature descriptor
- `/tsd/etc/slist/signed_exception_list.txt` — signed exception list (separate from SWDL; consumed by SWAP, delivery route unclear)
- `/tsd/hmi/HMI/swdlDeleteList` — list of files to delete before SWDL copy (from metainfo `DeleteFilesBeforeCopy`)
- `/tsd/var/swdownload/DeviceTable.txt` — device registry
- `/tsd/var/swdownload/cpumoduleregistry.conf` — cpu module registry
- `/tsd/var/swdownload/swdlhistory` — update history
- `/tsd/var/swdownload/swdljournal.tmp`, `swdlselection.tmp` — transaction scratch

## metainfo2.txt format
Plain INI-ish. Sections: `[common]`, `[device]`, `[device\module\index\default\<Type>]`.
- Types: `Application`, `Dir`, `File`, `bootloader`, etc.
- Keys: `FileName`, `FileSize`, `Checksum`, `Checksum1..N`, `Version`, `Variant`, `RequiredComponent`, `RequiredVersion`, `Link`, `DeleteFilesBeforeCopy`, `DangerousBoloUpdate`, `NoExclusiveBoloUpdate`, `ExclusiveUpdate`.
- `[common]` `MetafileChecksum` = SHA-1 over metainfo content.
- `[Signature]` = final section, `signature1..8 = <32 hex>` each. Concatenated → 128 bytes = **RSA-1024 signature** over metainfo2.txt (content up to the `[Signature]` section).
- Verified against `/tsd/etc/swap_keys/Metainfo_key_public_signed.bin`.

## Signature status / flags
Strings surfaced:
- `Signature is skipped.` — explicit skip path exists.
- `: Correct signature in ELF file "…"`, `: Correct signature in …`, `: Signature missing in …` — per-binary signature audit (embedded `.tsdsignature` section).
- `signature error`, `has no effect`, `unknown version or not present after SWDL!`
- `calling observers with pseudo list of one signature error, since public key empty or too short`
- `calling observers with pseudo list of one signature error, since we have no com client to get public key`

Observation: skip path is live; locating gate variable → Ghidra follow-up.

## Build/Source layout (pulled from PDB-like path strings)
Jenkins workspace: `STAGE1_release_eu_swdownload`. Key source files named in strings:
- `src/_sec/tsd.mibstd2.system.swdownload/src/tsd/mibstd2/system/swdownload/DownloadManager.cpp`
- `…/swdownload/PersistentDownloadSystem.cpp`
- `…/swdownload/checksum/CheckSumFileStream.cpp`
- `…/swdownload/metainfo/MultiRelease.cpp`
- `…/swdownload/metainfo/SequenceRelease.cpp`
- `…/swdownload/diagnosis/SwdlDiagnosis.cpp`
- `…/swdownload/diagnosis/AbtEEpromService.cpp`
- `…/swdownload/device/AbtCanEventReceiver.cpp`
- `…/swdownload/device/BluetoothDevice.cpp`
- `…/swdownload/device/DownloadDeviceAdapter.cpp`
- `ext.cryptolib/lib/src/rsa.c`, `ext.cryptolib/lib/src/sha_1.c`

## Diagnosis / UDS surface (critical for SD+OBD path)
Confirmed events (demangled):
- `TSDEVENT_CARCOM_DIAG_ROUTINE_SWDL_START`
- `T_RoutineControl_SWDL_Quellenwahl` — SOURCE SELECTION routine (German "Quellenwahl" = "source choice").
- `T_RoutineControl_SWDL_Start` — triggers SWDL run.
- `C_DiagRequest_AdaptionDataSwdl`, `C_DiagResponse_AdaptionDataSwdl`
- `C_DiagRequest_IdentificationDataSwdl`
- `UpdateStatusMedium`, `T_SwdlAbtEepromData`, `SoftwareModulesStatus`
- Methods observed: `SwdlDiagnosis::chooseMedium(T_RoutineControl_SWDL_Quellenwahl)`, `SwdlDiagnosis::startUpdateWithRelease(T_RoutineControl_SWDL_Start)`

Bottom line: a UDS Routine Control (SID 0x31) call pair exists —
1. Pick source (SD1 / SD2 / USB / NFS) via Quellenwahl.
2. Fire Start.

Executing both over OBD-II to CAN is the SD+OBD-only trigger surface.

## Mode gating
- String: `Customer updates are not allowed in service mode!` — Customer update path is BLOCKED while Service Mode is active.
- Implication: SWDL has two trigger paths — Customer (normal) and Service (dealer / developer). The OBD routine path is Service.
- `SYSTEM_RUNMODE` env var: `normal` for regular boot, `swdl` for SWDL boot (from `radio.conf` vs `radio_swdl.conf`).

## Missing pieces (resolve by Ghidra)
1. Exact enum values for the `Quellenwahl` source IDs — need to try to read a specific SD slot even on a 1-slot unit.
2. Where SWDL enforces the variant check during metainfo accept (so we know whether a toolbox metainfo that already lists 17222 actually works for a 17222 unit, and what else must match).
3. Where the "Signature is skipped" branch lives — any config flag at `/tsd/etc/system/*.conf` that toggles it.
4. Ordering: is the metainfo signature checked BEFORE variant filter, or AFTER? (Decides whether we can slip a modified metainfo for a specific variant without re-sig.)

## Hypothesis — primary SD+OBD path
On STD PLUS (1 SD slot), the HMI Service Mode may not expose a Software Update entry at all, or it points at SD2 which is absent. However the UDS `T_RoutineControl_SWDL_Quellenwahl` → `T_RoutineControl_SWDL_Start` pair is still reachable over CAN from the OBD-II port. Issue:
1. UDS 10 03 (extendedDiagnosticSession)
2. UDS 27 (SA) if needed
3. UDS 31 01 <RID Quellenwahl> <slot = SD1>
4. UDS 31 01 <RID SWDL_Start>
The unit should then read the toolbox metainfo from SD1 slot regardless of HMI behaviour.
