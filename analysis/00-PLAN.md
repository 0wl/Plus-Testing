# MST2 EU — SD-Only App Connect Install — Master Plan

## Target
MST2_EU_VW_ZR_P0254T (MIB STD2 PQ/ZR). Goal: install the Plus-Testing toolbox / app-connect patches on **STD PLUS** units (1 SD slot, no NAV) using **only an SD card** (or at most an OBD trigger), without opening the unit, without EMMC/USB-OTG access.

Known-failed prior attempts:
- Signing modified `metainfo2.txt` under `BB06` scheme — rejected (sig chain fails).
- Signing swap codes under `MH2p` — rejected (second-stage verifier).

## Rails
Everything lives in `Plus Testing/`:
- `MST2_EU_VW_ZR_P0254T/`      – firmware (moved)
- `extracted/`                 – unpacked tarballs, ISO contents
- `analysis/`                  – one md per subsystem + strings + ghidra notes
- `ghidra_projects/`           – Ghidra project files
- `sd_installer/`              – built SD-only payload + install.sh

## Phases
1. **Inventory & move** — firmware into Plus Testing, scaffold dirs. ✅
2. **Extract & strings** — pull tarballs for swdownload, swap, swapkeys, mainboot, startup, trustedservices, cryptolib, config, carcom. Run strings + file.
3. **Map SWDL** — signature path, metainfo parser, hashes.txt consumer, SD mount point, variant gate.
4. **Map SWAP** — FEC codes (MH2p, LH2p, BB06, et al), swap.info format, swapkey public keys, where 2nd-stage verify runs.
5. **Map FEC** — where app connect FEC check happens, what persistence it lives in, what writes it.
6. **Map boot/install** — mainboot_sec, startup rc, emergency mode trigger, SD-card role.
7. **Map crypto** — trustedservices + cryptolib pubkeys, cert chain, HAB posture, which keys the loader trusts vs which it rejects.
8. **Metainfo parse** — build full package graph JSON.
9. **Toolbox audit** — what the existing EMMC installer does. Reconstruct the primitives.
10. **Design SD-only path** — options:
    - A. Replay a legitimate signed partial-update that drops a shell / writable path.
    - B. Abuse a `RequiredComponent` / `swap`-restore flow that runs attacker-writable scripts.
    - C. Find a signed module whose install script is parsed as `ksh` and is attacker-influenced (metainfo injection).
    - D. Downgrade: a signed older image with a known writable config, chain-load toolbox from SD.
    - E. Dealer-mode / engineering channel on SD (greenmenu / 2DUpdate).
11. **Build installer** — SD root with payload + any OBD hook.
12. **Test** — replay verifier in Python against the built SD image; Ghidra confirm the code path.

## Deliverables (everything into Plus Testing/)
- `analysis/SWDL.md`, `SWAP.md`, `FEC.md`, `BOOT.md`, `CRYPTO.md`, `TOOLBOX.md`, `TESTING.md`
- `analysis/metainfo.json`
- `sd_installer/<layout>`
- `progress.md` – running log
