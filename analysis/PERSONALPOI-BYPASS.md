# personalpoi — metainfo signature bypass (confirmed by RE)

## TL;DR
TechniSat's SWDL binary (`tsd.mibstd2.system.swdownload`) contains a pre-signature-check path that **skips the metainfo RSA signature verification entirely** when the metainfo is detected as a "Personal POI" update. No forge, no key, no exception list. SD-only compatible. Uses signed existing primitives only.

Status: **primary SD-only install path**. Supersedes the exception-list / GEM-flag plan in SD-ONLY.md.

## Code trail (Ghidra on cpu.swdownload)

### Entry: `FUN_001b5194` (parseIniMap)
```
parseIniMap(state, ..., metainfo_path):
    uVar1 = FUN_001a4178(state);        // isSkippingSignature(state)
    FUN_001aa4fc(state, ..., metainfo_path, uVar1);  // parseCommonSection with skip flag
    ...
```

### `FUN_001a4178` — `isSkippingSignature()`
```
if metainfo does NOT contain a [personalpoi] section:
    return 0                            // sig check NOT skipped
for each section name S in metainfo:
    if S contains none of {"common", "Common", "signature", "Signature", "personalpoi"}:
        log "personalpoi is not the only update (conflict with <S>)"
        return 0                        // sig check NOT skipped
return 1                                 // SKIP SIG CHECK
```
Allowed section-name substring vocabulary (any one of the five):
- `common` / `Common`
- `signature` / `Signature`
- `personalpoi`

### `FUN_001aa4fc` — `parseCommonSection(state, ?, metainfo_path, skip_flag)`
```
... parses [common]: UseSubDirs, EnableUserDefinedSWDLMode, SkipSaveTrainName,
    SkipFileCopyChecksum, SkipChecksum, MaxParallelDevices, ExclusiveUpdate,
    SkipMetaChecksum ...
if MetafileChecksum present and SkipMetaChecksum = "false": verify checksum
if skip_flag == 0:
    verify metainfo RSA signature (FUN_001aa1ec / FUN_00189b74)
    throw "Parse error, invalid metainfo signature" on failure
else:
    log "parseCommonSection  Signature is skipped."
```

### `FUN_001a97e4` — `checkSignature()`
Note: this is a DIFFERENT skip path (the exception-list + FAZIT path we analyzed before). It is only reached via the normal SWDL flow and returns 1 when the exception list contains a `SkipSignatureCheck = "true"` entry covering the FAZIT. That path requires a validly TechniSat-signed exception list, which we don't have. The `[personalpoi]` bypass is simpler and does not touch `checkSignature`.

## Constraints on the crafted metainfo

1. **Must contain one `[personalpoi]` section header.** The exact section can be empty (just the header) since the body's content is consumed by a later personal-POI handler, which may or may not do anything if the installer logic processes other sections first.
2. **Every other `[...]` section name must contain at least one of `common`, `Common`, `signature`, `Signature`, `personalpoi` as a substring.**
3. Valid examples:
   - `[common]` (trivially matches)
   - `[Signature]` (trivially matches)
   - `[personalpoi]` (trivially matches)
   - `[cpuplus\personalpoi\swdownload_sec\15\default\Application]` — contains "personalpoi"
   - `[cpuplus\personalpoi\swap\15\default\Application]`
   - `[cpuplus\personalpoi\esd_sec\15\default\Application]`
   - `[cpuplus\personalpoi\<arbitrary>]` — any path with `personalpoi` as a component
4. Invalid examples (would fail — isSkippingSignature returns 0):
   - `[cpuplus\onlineservices\...]`
   - `[cpuplus\sal\...]`
   - Any section without `common`/`signature`/`personalpoi` substring.

## Device-walker (parseDeviceSections, FUN_001b4914)

Semantics confirmed:
- `parseIniMap` iterates every TOP-LEVEL section group in the metainfo tree (where `[a\b\c]` parses as tree[a][b][c]).
- For each top-level name N it calls `parseDeviceSections(state, N)`.
- `parseDeviceSections` does:
  1. Look up `state.device_list[N]` — if not registered, path effectively no-ops (nothing to install).
  2. For each registered module M on device N, construct `N\M\<version>\default\` and look it up in the metainfo tree. If found, invoke the device's callback (`vtable[0x14]`) with (state, N, subtree_path, module_descriptor).

Consequence: the attack metainfo cannot have a top-level `[cpuplus\...]` section (fails the keyword check in `isSkippingSignature`). All payload must live inside the `[personalpoi]` top-level — so the device driver that fires is `PersonalPoiImportDevice`.

Confirmed class via strings in cpu.swdownload:
- `tsd::mibstd2::system::swdownload::device::PersonalPoiImportDevice`
- Install directory: `/tsd/var/nav/personalpoi/`
- Event emission: `TSDEVENT_NAV_BASE_START_PPOI_IMPORT` (sent to NAV subsystem)

STD PLUS has NO navigation subsystem → the import event is sent into a void or returns an error. The file-level extraction may still happen before the event is sent (needs further RE of PersonalPoiImportDevice's `install()` / `copy()` method).

## Unknowns to resolve next
1. Does PersonalPoiImportDevice respect `Destination = "/"` in a `[personalpoi\M\V\default\Application]` section, or is the extraction target hard-coded to `/tsd/var/nav/personalpoi/`?
2. Does extraction run BEFORE the `TSDEVENT_NAV_BASE_START_PPOI_IMPORT` emission (so STD PLUS without NAV still executes the tar)?
3. If extraction target is hard-coded, is there a tarball traversal / symlink path that escapes it (PARSER-ATTACK.md item 3)?
4. What is the complete module list the handler enumerates? Could be just one module or arbitrary names.

## Attack metainfo skeleton

```ini
[common]
Release = "MIBStd2_PersonalPOI_SD"
MUVersion = "V432"
Vendor = "TechniSat"
TsdBuildNumber = "1"
Variant = "17201"
Variant2 = "17202"
...
Variant99 = "47216"
SkipSaveTrainName = "true"
SkipFileCopyChecksum = "true"
SkipChecksum = "true"
SkipMetaChecksum = "true"
EnableUserDefinedSWDLMode = "true"
MaxParallelDevices = "4"
MetafileChecksum = "0000000000000000000000000000000000000000"

[personalpoi]
Vendor = "TechniSat"
DeviceDescription = "personalpoi"

[cpuplus\personalpoi\swdownload_sec\15\default\Application]
FileName = "cpuplus_swdownload_sec_15_default.tar.gz"
FileSize = "<real>"
Destination = "/"
Version = "0001"
Checksum = "0000000000000000000000000000000000000000"

[cpuplus\personalpoi\swap\15\default\Application]
FileName = "cpuplus_swap_15_default.tar.gz"
FileSize = "<real>"
Destination = "/"
Version = "0001"
Checksum = "0000000000000000000000000000000000000000"

[cpuplus\personalpoi\esd_sec\15\default\Application]
FileName = "cpuplus_esd_sec_15_default.tar.gz"
FileSize = "<real>"
Destination = "/"
Version = "0001"
Checksum = "0000000000000000000000000000000000000000"

[Signature]
signature1 = "00000000000000000000000000000000"
signature2 = "00000000000000000000000000000000"
signature3 = "00000000000000000000000000000000"
signature4 = "00000000000000000000000000000000"
signature5 = "00000000000000000000000000000000"
signature6 = "00000000000000000000000000000000"
signature7 = "00000000000000000000000000000000"
signature8 = "00000000000000000000000000000000"
```

`[Signature]` is left all-zero; `isSkippingSignature()=1` → `parseCommonSection(..., 1)` → RSA verify never runs.

## Why this was missed earlier
- All prior analysis anchored on the symmetric path: `checkSignature` → `FUN_001a8ba4` → RSA. The `parseCommonSection(..., skip_flag)` fourth parameter was never traced to its caller.
- The flag's source `isSkippingSignature()` was never named by strings except for a diagnostic log; the dispatcher logic is a plain INI-section-name lookup, easily mistaken for diagnostic code.
- The `personalpoi` shim is a TechniSat-internal design artifact: user-authored POI databases are not signable, so the installer has a pre-signature path that activates when the whole update is only POI data. The unintended consequence is a generic metainfo-signature bypass.

## Next steps
1. Trace the device-section walker to confirm `[cpuplus\personalpoi\<module>\...]` is honored OR `[personalpoi\...]` is its own install path.
2. If honored under the normal device-match path: rebuild `sd_installer/metainfo2.txt` in this shape, swap module archive names, no further changes needed.
3. If a dedicated personalpoi handler exists: trace its tar-extraction / install-script logic and determine if arbitrary `.tar.gz` content gets extracted to arbitrary destinations.
4. Validate fully with the Unicorn harness pattern (run `parseCommonSection` emulated with crafted input, observe branch).
