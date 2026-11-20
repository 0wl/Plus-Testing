# Testing — offline + onboard

## What is testable offline (here)
- **Metainfo parse**: `tools/validate_metainfo.py <sd_root>` replays the subset of SWDL checks we can run without the unit. Verifies: INI parse, Skip* flags, MetafileChecksum computation, Variant match, Region match, per-module archive presence and FileSize match, device-vs-unit match.
- **Payload integrity**: the merged `cpuplus_esd_sec_15_default.tar.gz` can be listed with `tar -tzf …` to confirm layout:
    - `tsd/etc/persistence/esd/*.esd` — stock + toolbox GEM screens
    - `tsd/etc/persistence/esd/scripts/*.sh` — toolbox activate + copy scripts
    - `tsd/etc/swdownload/modules/esd.info` — preserved from stock
- **Sanity run**: `python tools/parse_metainfo.py <sd_root>/metainfo2.txt` reproduces the full `metainfo_full.json` for the crafted file.

Command run in CI-like fashion:
```
python tools/build_sd_installer.py          # (re)builds sd_installer/
python tools/validate_metainfo.py sd_installer --unit-device cpuplus --unit-variant 17222
```

Expected state as of 2026-11-19 after rebuild:
- `overall: sig=skipped (by SkipSignatureCheck=true) | variant=skipped | payload=4 archives present`
- All device sections `[OK]`.
- `devices seen in metainfo: ['cpuplus']`.

## What requires a real unit (not testable from here)
- Whether SWDL actually honours `SkipSignatureCheck=true` when `getUserDefinedAllowed() == true` (GEM enabled). This is the critical assumption; a Ghidra pass on `DownloadManager.cpp`'s metainfo parser and `checkSignature` path will confirm, but short of that the behavioural test is: enable GEM, insert SD, look at the SWDL progress screen / UDS response.
- Exact Quellenwahl / SWDL_Start RID numbers over UDS. Natural default `01` for SD1; watch the CAN trace during the first live try.
- Post-install: whether GEM's `copy_fec.sh` actually copies an unsigned exception list to `/tsd/etc/slist/signed_exception_list.txt` AND whether a patched swap binary (dropped into `custom/swap/`) silently bypasses the sig check.

## Rollback / safety
- Nothing in this SD payload writes to bootloaders or signed system images.
- The `cpuplus/esd_sec/15/default/…` module replace is reversible by reinstalling the original stock firmware (same path, stock archive).
- No RPMB writes are attempted. FECs in RPMB remain intact.
- `DangerousBoloUpdate = "false"` in [cpuplus] — not a brickable update.

## Checklist for the first live attempt
1. Full eMMC backup via the existing EMMC installer (`BagolyDiag-PLUS-EMMC-Installer.exe`) BEFORE trying this SD path, kept as recovery.
2. OBD session: capture CAN trace during GEM enable + SWDL trigger.
3. Record the exact `SwdlProgressListener.updateTriggerPanel(...)` string that fires on the console — proves which branch SWDL actually took.
4. If the install fails with `RELEASERESULT_ERROR_NO_RELEASES`, the device-filter rejected; re-check `SkipCheckVariant` passes.
5. If fails with `METAINFORESULT_ERROR_PARSE`, something malformed — run the local validator again.
6. If the install hangs at the signature stage with a progress stall, `SkipSignatureCheck=true` is NOT being honoured under GEM — fallback is to drop a patched swdownload binary via the module path and retry.
