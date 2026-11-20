# FEC — Feature Enable Codes — map

See also `SWAP.md` for the owning subsystem.

## What a FEC grants
A FEC = signed capsule that unlocks a set of FSIDs (feature-set IDs). TechniSat models each hardware feature (app connect, nav, hi-audio, etc.) as one or more FSIDs. The FEC maps FSID → grant for a given unit (or unit range, scoped by FAZIT / VCRN / VIN).

## Blob classes referenced (demangled C++ types in binary)
- `swap::data::FEC` — root
- `swap::data::FEC::FunctionEnablingSpecificPart` — the grant body (FSID set + validity conditions)
- `swap::data::FEC::KeyExchangeSpecificPart` — key handoff (per-FEC session key?)
- `swap::data::FEC::SecureCodingSpecificPart` — tamper-proof coding changes
- `swap::data::FEC::IndividualizationAttribute` — per-unit binding (FAZIT/VCRN/VIN)
- `swap::data::FEC::ITypeSpecificPart` — polymorphic type part
- `swap::data::FEC::FunctionEnablingSpecificPart::ValidityConditionType{Map}` — expiry / preconditions
- `swap::data::FSID::TypeMap`
- `swap::data::VIN`, `swap::data::VCRN`, `swap::data::FSID`

## Lifecycle
Strings surfaced:
- `notifying observers that FEC manager is ready to do signature check`
- `checking signature of FEC, using …`
- `notifying observers that all FEC signatures were checked successfully`
- `notifying observers that at least one FEC signature check failed`
- `notifying observers that signature of FEC covering FSID … (passed/failed)`
- `FEC description:` (prints into log on apply)
- `FEC key was changed successfully, checking all known FECs again`
- `FEC manager is not ready, abort handling of FEC`
- `FEC manager is not ready, abort handling of PDC` (Personal Data Code)
- `FEC manager says permission for FSID … (granted/denied)`

## Interplay with exception list
- Exception list bypasses FEC entirely for listed FSIDs when its own sig is valid and FAZIT is covered.
- String: `no exception list to consider, evaluating FECs` — fallback order.
- `retention period is over, FEC manager is not ready and no signed exception list is available:` — if FEC store is uninitialized AND no signed exception list exists, system enters not-ready state after a grace period.

## App-connect FSIDs
Not yet enumerated by raw code. Need to cross-check with GEM scripts and known toolbox config. Likely candidates (from mirrorlink.testinterface.MirrorLinkTestConfig reference): `12ML`, `13ML` (mirrorlink), possibly `12OC` / `11OC` (online), `12IF` (interface), plus related CarPlay / AndroidAuto FSIDs.

TODO (Ghidra): find constant table that maps FSID → human string inside swap binary.

## Storage — why the EMMC path exists today
FECs live in **RPMB** on eMMC (`FECStoreRPMB` class). RPMB requires an eMMC-level key the SoC's secure element holds, so SD can't rewrite FEC storage. That's why the current "working" method needs physical eMMC access.

## SD-only angles
1. Exception list drop-in (needs valid signature → blocked without leaked key).
2. UDS dealer routine to WRITE FEC via OBD (needs SA27 key for 0x5F adaptation).
3. Exploit ordering bug in FEC verifier (needs Ghidra follow-up).
4. Downgrade to firmware version where sig-check had a weakness (needs older firmware + the loader's version gate check).
