# Toolbox audit — `mib-std2-pq-zr-toolbox-master.iso`

ISO extracted to `extracted/toolbox/`.

## Top-level layout
```
README.md
install.sh                    # root install script
metainfo2.txt                 # signed metainfo (with [Signature] block of 8×32-hex = RSA-1024)
LICENSE
backup/                       # placeholder (filled on install)
cpu/                          # payload partitions mimicking SWDL layout
   InfoFile/1..18/default/File/
   onlineservices/1..36/default/Dir/
       hashes.txt
       tsd/etc/persistence/esd/{mibstd2-*.esd, scripts/*.sh}
custom/                       # user-dropped payload directories
   carplayicon/   fec/   greenmenu/   hmi/   java/   mapcfg/   mirrorlink/   navigation/
   onlineservices/ ringtones/ shadow/ sounds/ startanim/ stationdb/ swap/ swdl/ tts/
toolbox/
   devesd/                    # engineering ESD definitions (AndroidAuto.esd, CarPlay.esd, ...)
   gem/                       # Green Engineering Menu assets + GEM.jar
dump/
tools/                        # host-side helpers
```

## install.sh behaviour (summary)
- Hunts for toolbox volume across `/media/mp00*`, `/fs/*`, `/mnt/*`, `/tmp`, `/dev/sdcard`.
- Finds eMMC target at `/fs/<x>/tsd/etc/persistence/esd` (needs this already mounted rw-capable by caller).
- `mount -t qnx6 -o remount,rw /dev/hd0t177 /` — remount root partition rw.
- Clears old `mib2std-*.esd`, `mibstd2_yox.esd`, `TOOLBOX.esd`, `scripts/` dir.
- Copies ESD screens + scripts into `/tsd/etc/persistence/esd`.
- `chmod a+rwx` on all scripts.
- Replaces `/tsd/hmi/HMI/jar/GEM.jar` with v4.11 (from toolbox/gem/).
- Ends by returning the partition to ro.

## Toolbox metainfo2.txt — what makes NAV install work
- `Release = "MIBStd2_Online_Approval"` — appears as a selectable update in Service Mode's Software Update dialog.
- `MUVersion = "V432"` — fake-newer version that forces the unit to accept the update.
- `SkipSaveTrainName = "true"` — metainfo flag that prevents the swdownload from persisting the fake train name (so it doesn't survive uninstalls).
- Variants 17201–17223 + 37xxx + 47xxx listed. STD PLUS variant 17222 **is** in the variant list — so metainfo is signed-valid for 17222.
- `DangerousBoloUpdate = "false"` per `[cpu]` → not a bolo (brickable) update.
- Payload modules: `[cpu\InfoFile\1..18\default\File]`, `[cpu\onlineservices\1..36\default\Dir]` — all point at `cpu/onlineservices/1/default/` as the master, rest `Link=`.
- `[Signature]` 8 × 32-hex at end — valid RSA-1024 signature by someone with the Metainfo_key private key.

## Why README says STD PLUS can't install from SD
Despite 17222 being in the metainfo's variant list, README calls out:
- 17222 (5C0035684F) — **STD PLUS**, 1 SD slot
- 47213–47216 (5F003587* / 5QA035874*) — later STD PLUS variants, not in metainfo at all

For 17222 the metainfo IS valid. Blocker therefore isn't the signature — it's the HMI side. Working theory: on 1-SD-slot units, Service Mode's Software Update entry either (a) doesn't scan SD1, or (b) isn't shown at all, or (c) the cpu partition install of `MIBStd2_Online_Approval` needs the onlineservices partition that STD PLUS lacks (the toolbox targets the `cpu/` partition which only exists on NAV/Plus, not stdRadio — check).

## Custom drop-ins — what they say about the install ends
Each `custom/*/Place … here` folder is a drop-in point used by `install.sh` when present:
- `custom/fec/` ← **signed_exception_list.txt** (confirms that SWAP's exception list IS the gate the toolbox normally patches).
- `custom/mirrorlink/` ← mirrorlink.config.common (app-connect-adjacent).
- `custom/greenmenu/` ← GreenMenu .esd (the engineering menu that unlocks dealer screens).
- `custom/swdl/` ← **patched swdownload binary** (indicates toolbox ships a patched binary that skips signature checks — a replacement for the stock SWDL).
- `custom/swap/` ← **patched swap binary** (the same, for FEC/exception list verifier).
- `custom/shadow/` ← /etc/shadow override (root password mod).

Reading between the lines:
- The toolbox's full capability set — app connect enablement, persistent telnet, root shell — relies on dropping **patched swdl + swap binaries** into the running system via `install.sh` and relying on the `.tsdsignature` section being ignored at mount time OR on ELF-signature checks being advisory only.
- `signed_exception_list.txt` is a drop-in point for a FAZIT-matching list — these must be obtained externally (none ship with the toolbox). This is the reason BB06 (metainfo sig) never needed forging for the full toolbox flow: metainfo is TechniSat-signed already; the real binaries get swapped post-install by `install.sh` running as root.

## Implications for SD-only path
- The **existing toolbox metainfo is ALREADY valid for 17222**. So BB06 is not the physical blocker.
- The real blocker for 17222 (STD PLUS) SD install is likely: **the HMI Service Mode "Software Update" entry does not appear on 1-SD-slot units**, so the user can't trigger SWDL from the UI. UDS over OBD is the natural bypass — same SWDL binary, same metainfo check, no UI dependency.
- 47213+ variants must also be added to a new metainfo — but that requires re-signing (blocked without Metainfo_key private).

## Next
- Verify the hypothesis above by locating in Ghidra: (a) HMI Service Mode entry condition, (b) whether SWDL UDS routine path is gated by 1-slot vs 2-slot variant.
- If 17222 is confirmed reachable via UDS, build the OBD trigger sequence.
- For 47213+, also inspect the metainfo variant-check ordering to see whether the list can be pruned instead of extended (removing variants shouldn't change signed hash — BUT the `[Signature]` is over the WHOLE file, so pruning breaks it).
