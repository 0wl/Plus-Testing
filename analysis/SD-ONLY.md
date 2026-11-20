# SD-only Install Path for STD PLUS — Design

## The real blocker (resolved)
Prior attempts tried to **re-sign** `metainfo2.txt` under the BB06 class and the **MH2p** swap code and both failed. That was never the right lock to pick.

Reversing SWDL (`tsd.mibstd2.system.swdownload`) showed that TechniSat left a **documented set of metainfo-level skip flags**:
- `SkipSignatureCheck = "true"` — SWDL will not verify the metainfo signature. Log string proves the branch: `"SkipSignatureCheck = \"true\", will not check signature of metainfo2.txt file."`
- `SkipCheckVariant = "true"` — SWDL will not filter releases by the unit's variant.
- `SkipCheckRegion = "true"` — SWDL will not filter releases by region.
- `SkipChecksum = "true"` — SWDL will not verify per-file checksums listed in `hashes.txt`.
- `SkipMetaChecksum = "true"` — SWDL will not verify `MetafileChecksum` in `[common]`.
- `SkipFileCopyChecksum = "true"` — already used by the current toolbox.
- `SkipSaveTrainName = "true"` — keeps the real train name intact in persistence.

Internal flags set from these: `skip_signature_check_flag`, `isSkippingSignature`, `forceVariant`, `skip_all`, `skip_device`, `skip_module`.

## Gate on using these flags
SWDL also calls `getUserDefinedAllowed()` (DSI method, backed by `SwdlGem::receiveGEMRead`). That returns whether a **User-Defined SWDL** session is allowed. The permission is stored in **GEM** persistence (`tsd::mibstd2::persistence::common::IGEM`).

GEM (Green Engineering Menu) permission is enabled over OBD by writing block 5F adaptation to the dealer/engineering value. This is a widely known pre-step already in the toolbox README ("Green Engineering Menu (developer mode) enabled in adaptations of block 5F. Use any OBD2 adapter and software that can enable it.").

→ With GEM on, SWDL honours the Skip* flags. That's the whole lock.

## Secondary blocker (device name) — why the existing toolbox metainfo fails on STD PLUS
The shipped toolbox metainfo lists variant **17222** in `[common] Variant*`, but every payload section is under `[cpu\…]` (NAV device). STD PLUS units expose **`cpuplus\…`** instead of `cpu\…`. SWDL walks each `[device\module\version\default\Type]` section and requires a matching device on the unit; none match on STD PLUS, so `RELEASERESULT_ERROR_NO_RELEASES` fires and the install is silently a no-op. The README calls this "SD installation method is NOT possible on unit variant 17222"; the actual cause is the device-name mismatch, not the variant number.

## Attack surfaces (chosen vs rejected)
| # | Path | Verdict |
|---|---|---|
| 1 | Re-sign metainfo with Metainfo_key | **REJECTED** — private key not available, RSA-1024 factoring not feasible. |
| 2 | Forge a signed `signed_exception_list.txt` for appconnect FSIDs | REJECTED — needs Data_key private. |
| 3 | SHA-1 collision over module payloads | REJECTED — non-practical compute. |
| 4 | Dealer UDS routine writing to RPMB | REJECTED — needs SA27 seed/key pair. |
| 5 | **GEM-gated `SkipSignatureCheck=true` metainfo + cpuplus-targeted payload** | **SELECTED — this is the design.** |
| 6 | Pure OBD/UDS SWDL trigger (Quellenwahl + SWDL_Start) with same crafted metainfo on SD | Compatible with #5; usable if the HMI Service Mode entry is absent on STD PLUS. |

## End-to-end plan

### Preconditions
1. Unit is a MIB STD2 PQ or ZR Plus variant (1 SD slot, stdPlus media, iMX6 present).
2. Firmware train is `MST2_XX_XX_XX_X0XXXT` (same cpuplus binary layout).
3. Unit has **GEM activated** in block 5F adaptation via OBD-II. Any VW-capable OBD2 tool/adapter will do.
4. A FAT32-formatted SD card.

### SD card layout
```
/metainfo2.txt                                      # crafted, with Skip* flags
/cpuplus/
   /onlineservices/15/default/
       cpuplus_onlineservices_15_default.tar.gz     # ESD screens + scripts (from toolbox cpu/onlineservices/1/default)
       hashes.txt                                   # placeholder (SkipChecksum active)
       module.ref                                   # placeholder (ditto)
   /esd_sec/15/default/
       cpuplus_esd_sec_15_default.tar.gz            # toolbox-provided ESD payload
       hashes.txt
       module.ref
   /swap/15/default/
       cpuplus_swap_15_default.tar.gz               # patched swap binary (bypasses exception-list sig)
       hashes.txt
       module.ref
   /swdownload_sec/15/default/
       cpuplus_swdownload_sec_15_default.tar.gz     # patched swdownload binary
       hashes.txt
       module.ref
   /testinterface_sec/15/default/
       cpuplus_testinterface_sec_15_default.tar.gz  # testinterface binary + hook into /tsd/var
       hashes.txt
       module.ref
```
All payload archives are assembled from the stock cpuplus partitions in this firmware tree PLUS toolbox-provided replacements in `custom/*`.

### Crafted metainfo2.txt — essential fields
```ini
[common]
Release = "MIBStd2_StdPlus_Enable"
MUVersion = "V432"
Vendor = "TechniSat"
TsdBuildNumber = "1"
Variant = "17201"
Variant2 = "17202"
Variant3 = "17203"
Variant4 = "17204"
Variant5 = "17205"
Variant6 = "17206"
Variant7 = "17207"
Variant8 = "17222"       # STD PLUS 5C0035684F
Variant9 = "47213"       # STD PLUS later-gen 5F003587*
Variant10 = "47214"
Variant11 = "47215"
Variant12 = "47216"
Region = "Europe"
Region2 = "RoW"
MaxParallelDevices = "4"
SkipSignatureCheck = "true"
SkipMetaChecksum = "true"
SkipChecksum = "true"
SkipFileCopyChecksum = "true"
SkipCheckVariant = "true"
SkipCheckRegion = "true"
SkipSaveTrainName = "true"
CheckAllUpdates = "true"
CheckIfNotEqual = "false"
MetafileChecksum = "0000000000000000000000000000000000000000"

[cpuplus]
VendorInfo = "TechniSat"
DeviceDescription = "cpuplus"
DeviceRelease = "1"
RequiredVersionOfDM = "0"
DangerousBoloUpdate = "false"
NoExclusiveBoloUpdate = "false"
MainUnitDevice = "true"

[cpuplus\onlineservices\15\default\Application]
FileName = "cpuplus_onlineservices_15_default.tar.gz"
FileSize = "<real size>"
Destination = "/"
Version = "0001"
… (per-module section with Checksum overridden to anything — `SkipChecksum = "true"` makes value non-load-bearing)

[cpuplus\esd_sec\15\default\Application]
…

[cpuplus\swap\15\default\Application]
…

[cpuplus\swdownload_sec\15\default\Application]
…

[cpuplus\testinterface_sec\15\default\Application]
…

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
The `[Signature]` section is required (SWDL expects it) but values are irrelevant with `SkipSignatureCheck = "true"`. Same for the `MetafileChecksum`, per-file `Checksum`, `hashes.txt` content.

### Trigger (2 options, pick either)
**Option A — HMI Service Mode (preferred if available):**
1. Insert SD into SD1 slot.
2. Hold MENU button to enter Service Mode.
3. Software Update → the crafted release `MIBStd2_StdPlus_Enable` should be visible.
4. Confirm install.

**Option B — OBD-II UDS trigger (works even if the Service Mode screen does not appear on STD PLUS):**
1. Insert SD into SD1 slot.
2. OBD-II adapter → CAN gateway → Radio/Information module (typ. address `0x05F`).
3. UDS `10 03` — extendedDiagnosticSession.
4. UDS `27 01` / `27 02` — SA seed/key exchange (dealer-level programming session; GEM activation grants this).
5. UDS `31 01 <RID Quellenwahl> <source=SD1>` — SwdlDiagnosis::chooseMedium. Source enum values TBC by Ghidra follow-up; `01` for SD1 is the natural default.
6. UDS `31 01 <RID SWDL_Start>` — SwdlDiagnosis::startUpdateWithRelease.
7. Monitor `UpdateStatusMedium` / `SoftwareModulesStatus` responses.

### Post-install activation
After reboot, the installed toolbox provides:
- `activate_telnet.sh` / `activate_qconn.sh` — persistent root access.
- `activate_perm_access.sh` — (what it actually does needs confirming; likely installs a signed exception list if provided, OR patches runtime).
- `copy_fec.sh` — copies a user-provided `signed_exception_list.txt` to `/tsd/etc/slist/`.
- Patched swap/swdl binaries if the SD provided them → runtime no longer requires signed exception list.

To enable app connect specifically:
- Confirm FSIDs for MirrorLink / CarPlay / AndroidAuto. (Known: `cpuplus/mirrorlink_EU`, `cpuplus/serviceapple_vw`, `cpuplus/exlap`, `cpuplus/sal`, `cpuplus/salconfig_sec_stdPlus_stdZR_vw` all already ship on this firmware — binaries are present, it's purely a FEC lock.)
- Install a drop-in `signed_exception_list.txt` covering those FSIDs for the unit's FAZIT.
- If no signed list exists, drop in the patched swap binary that skips the sig check on the exception list, then use an unsigned list.

## Open RE questions (to resolve against Ghidra when available)
1. Exact order in `DownloadManager`: is `SkipSignatureCheck` read before `checkSignature` call? (Log strings suggest yes; needs confirmation.)
2. Exact `Quellenwahl` enum values and whether any map to SD1 on a 1-slot variant.
3. Whether `getUserDefinedAllowed()` returns true merely with GEM on, or also requires a UDS extended session to be open.
4. Enumerate the FSIDs the stock firmware ships for mirrorlink/carplay/androidauto (expected from the FSID 4-char vocabulary gathered in `SWAP.md`).
