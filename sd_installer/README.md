# SD-only STD PLUS Toolbox Installer

> Target: MIB STD2 PQ/ZR **STD PLUS** (1 SD slot, iMX6-present, non-nav) units running the `MST2_EU_VW_ZR_P0254T` family.
>
> Goal: install the toolbox (and unlock app connect follow-up steps) without opening the unit, with **only an SD card** (+ an OBD2 adapter for the pre-step that enables GEM).

## How it works (the short version)
`tsd.mibstd2.system.swdownload` honours a documented set of metainfo-level skip flags when the unit is in **GEM** (Green Engineering Menu / developer) mode. The relevant flags:

| Flag | Effect |
|---|---|
| `SkipSignatureCheck = "true"` | Skip RSA-1024 metainfo signature check |
| `SkipMetaChecksum = "true"` | Skip metafile SHA-1 checksum |
| `SkipChecksum = "true"` | Skip per-file SHA-1 checksums |
| `SkipFileCopyChecksum = "true"` | Skip post-copy checksum |
| `SkipCheckVariant = "true"` | Install even if the unit's variant isn't in the list |
| `SkipCheckRegion = "true"` | Install regardless of region |

The permission to honour them is granted when `SwdlGem` reports User-Defined SWDL is allowed, which is stored in the GEM persistence block. Flipping block 5F to the dealer/engineering value over OBD-II flips that.

Prior toolbox metainfos target the `cpu/` partition (NAV units only). STD PLUS units expose `cpuplus/` instead, so a normal toolbox install silently does nothing on STD PLUS. This SD retargets every payload at `cpuplus/`.

## What's on this SD
```
metainfo2.txt                           — crafted; Skip* flags; cpuplus targets
cpuplus/esd_sec/15/default/
    cpuplus_esd_sec_15_default.tar.gz   — merged: stock cpuplus ESD defs + toolbox GEM screens + activate scripts
    hashes.txt
    module.ref
cpuplus/swap/15/default/
    cpuplus_swap_15_default.tar.gz      — STOCK (drop a patched swap binary later to enable unsigned exception lists)
    hashes.txt
    module.ref
cpuplus/swdownload_sec/15/default/
    cpuplus_swdownload_sec_15_default.tar.gz  — STOCK (same reasoning)
    hashes.txt
    module.ref
cpuplus/testinterface_sec/15/default/
    cpuplus_testinterface_sec_15_default.tar.gz  — STOCK
    hashes.txt
    module.ref
```

## Procedure
1. **Enable GEM over OBD** (one-time per unit):
   - Plug an OBD2 adapter (any VAG-capable tool: VCDS, OBDeleven, VagTacho, OPS/ODIS clone). Use "Information Electronics 1" (addr 5F).
   - Write adaptation block 5F → developer / engineering value. (Users who already use the current toolbox already know this.)
2. **Format a FAT32 SD card** (≥ 1 GB recommended; less for this SD alone but bigger if you also drop custom patches).
3. **Copy the content of `sd_installer/` onto the SD card root**. Do not nest; `metainfo2.txt` must be at the SD root.
4. **Insert the SD card into SD1**, ignition ON.
5. **Trigger SWDL**. Two options:
   - **HMI path**: long-press MENU → Service Mode → Software Update → pick `MIBStd2_StdPlus_Enable`. If the entry does not appear on 1-slot units, use the OBD path.
   - **OBD path**: UDS Routine Control via OBD2:
     1. `10 03` — extended diagnostic session.
     2. `27 01` / `27 02` — Security Access seed/key handshake (GEM-level session).
     3. `31 01 <Quellenwahl RID> <source=01 SD1>` — pick medium.
     4. `31 01 <SWDL_Start RID>` — start download.
     5. Watch `UpdateStatusMedium` / `SoftwareModulesStatus` responses.
6. **Reboot the unit when prompted**. GEM menu becomes visible.
7. **Open GEM → scripts** → run `activate_telnet.sh` / `activate_qconn.sh` to get root shell access.

## Enabling app connect (the follow-up, not done by this SD alone)
This SD puts the toolbox in. App-connect FSIDs are gated by FEC / signed exception list. Two paths:

### Path A — signed exception list drop-in
If you have a `signed_exception_list.txt` that covers the unit's FAZIT and grants the app-connect FSIDs, drop it in `custom/fec/` on the SD before step 3 and run `copy_fec.sh` from GEM after install.

### Path B — patched swap binary
Drop your patched `tsd.mibstd2.system.swap` (one that skips the exception-list signature check) into `tools/custom/swap/` and rebuild the SD (`python tools/build_sd_installer.py`). The rebuilt SD replaces the live swap binary during install. Then any user-written exception list is accepted.

### Why not just forge the metainfo signature
RSA-1024 factoring is not practical and the Metainfo private key has not leaked; forging is off the table. `SkipSignatureCheck = "true"` under GEM is the supported path.

## Dry-run validation (offline)
Before putting the SD into a real unit, run:

```
python tools/validate_metainfo.py sd_installer --unit-device cpuplus --unit-variant 17222
```

Expected output: all gates `PASS` or `SKIP`, zero missing files, zero device mismatches.

## Known open items (not blockers for installation, confirm on a real unit)
- Exact `Quellenwahl` RID + source enum values — needs confirming by Ghidra or by sniffing a dealer tool. Natural default `01` = SD1.
- Whether the HMI's Service Mode exposes the Software Update entry at all on 1-slot units; OBD path is the robust answer.
- Whether `getUserDefinedAllowed()` requires the UDS extended session to still be live during SWDL, or merely GEM being enabled.
