# Boot + install path — map

## Two CPUs, two chains
From prior OTG analysis (verified):
- **J5 (TI Jacinto 5)** — system controller. Owns CAN, watchdog, iMX6 reset line. Boots TechniSat IPL from `mainstd/mainboot_sec/9/default/init_mibstd2radio_sec.dat`.
- **iMX6 (NXP)** — multimedia/HMI/eMMC owner. Boots `cpuplus/cpuboot_sec/*/init_mibstd2plus_cpu.dat` (TechniBoot IPL) then IFS from `/dev/hd0`.

STD-radio-only (`mainstd/`) units have NO iMX6, so no toolbox target exists. STD PLUS has iMX6.

## Boot sequence (summary)
1. SoC BootROM → TechniBoot IPL (HAB-signed).
2. IPL → QNX startup.boot (from `mainstd/startup/9/default/startup.boot`, extracted to `extracted/startup.boot`).
3. startup.boot mounts system IFS (`/tsd/bin/ifs/system.ifs`) at `/`, runs `/tsd/bin/system/startup`.
4. `/tsd/bin/system/startup` orchestrates service start and the key install-staging move.

## Critical install-staging logic in `/tsd/bin/system/startup`
```sh
if [ -d /tsd/tmp/hmi -o -d /tsd/tmp/j9 ] ; then
   mount -t qnx6 -o remount,rw /dev/hd0t177 /
   if [ -d /tsd/tmp/hmi ] ; then
      rm -rf /tsd/hmi
      mv /tsd/tmp/hmi /tsd/hmi
   fi
   if [ -d /tsd/tmp/j9 ] ; then
      rm -rf /j9
      mv /tsd/tmp/j9 /j9
   fi
   mount -t qnx6 -o remount,ro /dev/hd0t177 /
fi
```
Implication: anything dropped as a **directory** at `/tsd/tmp/hmi` or `/tsd/tmp/j9` is atomically moved to `/tsd/hmi` or `/j9` on next boot, with the root partition briefly remounted rw and the old dirs removed. If an attacker can write to `/tsd/tmp/` (which lives on the writable `/tsd/var` partition, not the signed system partition), they own the HMI tree next boot. This is the legitimate update-staging mechanism SWDL uses.

## Testinterface auto-activation (another install anchor)
```sh
if [ -x /tsd/var/testinterface/tsd.mibstd2.system.testinterface ] ; then
    cp /tsd/var/testinterface/tsd.mibstd2.system.testinterface /tmp
    CFG=/tsd/etc/system/factory/radio.conf
    RCFG=$CFG
else
    CFG=/tsd/etc/system/radio.conf
    RCFG=/tsd/etc/system/lsmradio/radio.conf
fi
```
Implication: if a file named `tsd.mibstd2.system.testinterface` is executable at `/tsd/var/testinterface/`, the FACTORY config (`factory/radio.conf`) is used and the testinterface binary is copied into `/tmp`. This switches the whole boot to engineering/factory config — potentially exposing dealer features and relaxed permissions.

## System image partitions
`systemimage_hwr0_sec_stdZR` partition contains the signed root FS image(s). Each `systemimage` is HAB-signed and mounted RO. Any live changes land on `/tsd/var` (persistent writable), `/tsd/hmi` (overlay), `/tsd/tmp/` (overlay staging), `/j9` (java apps).

## Config/conf partitions
`config_EU_sec` carries the active boot configs (`radio.conf`, `radio_swdl.conf`, `tsd.*.conf`). `config_EU_sec_vw` (cpu) is the iMX6 side.

## Mode switches
- `SYSTEM_RUNMODE=normal` → `radio.conf` is used, HMI is normal radio UI, boots services incl. swdownload normally.
- `SYSTEM_RUNMODE=swdl` → `radio_swdl.conf` is used, HMI runs in SWDL mode (progress screen). Triggered by long-press MENU or by UDS session request.
- Service mode / factory mode → testinterface auto-start when the file exists in `/tsd/var/testinterface/`.

## SD card handling
HMI (java j9 app + hmizr native) picks SD slot. From README of toolbox: `/media/mp000` = SD1, `/media/mp001` = SD2. Service Mode on NAV units shows SW Update when toolbox metainfo detected on EITHER slot. STD PLUS has mp000 only; whether Service Mode scans mp000 at all on STD PLUS is the open question (hypothesis: HMI service-mode screen is absent or empty on 1-slot units).

## Install footprint of the toolbox today (from `extracted/toolbox/install.sh`)
- Finds the SD root at `/media/mp00*`, `/fs/*`, `/mnt/*`, `/tmp` or `/dev/sdcard`.
- Writes to `/fs/<target>/tsd/etc/persistence/esd/` on the eMMC's writable subtree.
- `mount -t qnx6 -o remount,rw /dev/hd0t177 /` — **remounts the system partition rw**. Only possible with root. This is why today's install needs an already-established root shell.
- Copies ESD screens, scripts; `chmod a+rwx` on scripts; updates GEM.jar.

## Attack surface summary for SD-only
| Surface | Writable from SD stock? | Writable from SD via UDS? | Blocker |
|---|---|---|---|
| `/dev/hd0t177` (system partition) | no (RO, signed) | no | sig + HAB |
| `/tsd/var/testinterface/` | no | maybe (dealer routine?) | need routine ID + SA key |
| `/tsd/tmp/hmi`, `/tsd/tmp/j9` | yes via SWDL customer path | yes via SWDL UDS | metainfo sig check |
| `/tsd/etc/slist/signed_exception_list.txt` | yes if list signed | yes if list signed | need Data_key private |
| RPMB (FEC storage) | no | only via SA-locked FEC routine | SA27 key |
| `/tsd/etc/swap_keys/*` | yes via SWDL (replace keys partition) | yes via SWDL UDS | metainfo sig check on partition's hashes |
