# Signature binding — what the sig ACTUALLY covers

## Confirmed by direct hash computation (2026-11-19)

### Dir sections — `Checksum` = SHA-1 of `hashes.txt`
Stock firmware `[cpu\customerupdateinfos\12\default\Dir]`:
- `FileSize = "436"` (toolbox metainfo lists this in a diff section — 1210 — which was for an older customerupdateinfos version)
- `Checksum = "360f12eacbc7a90a96e240162103a90846f45c1f"`
- Matches SHA-1 of `cpuplus/customerupdateinfos/15/default/hashes.txt` **exactly**. Binding confirmed.

### Toolbox Dir — binding does NOT match
Toolbox `[cpu\onlineservices\1\default\Dir]`:
- Stated `FileSize = "11012"`, `Checksum = "04605628c2c1fd4ef65d0928ef4601b65b516c66"`.
- Actual `hashes.txt` ships at 18476 B with SHA-1 `b40f576e117f83cabb14406924a72940a80165cc`.
- **Mismatch**. Either: (a) the author used a different hashes.txt during signing (and `SkipFileCopyChecksum = "true"` in `[common]` makes SWDL skip the verify), (b) the Dir Checksum covers something else here.

### File sections — `Checksum` = SHA-1 of the Source file
- `[cpu\InfoFile\1\default\File]` Checksum `7a005a0b493b41a229a0f799cff797ce1bd61a47` matches `Update.txt` byte-for-byte.
- These are strictly bound.

### Application sections — `Checksum` = SHA-1 of the tarball
- Each tarball's hash is in the signed metainfo, plus per-chunk `Checksum1..N` for streaming.

## What this means
- The signed `[Signature]` section binds the metainfo content (key-value lines). Every `Checksum` field in the signed metainfo is therefore fixed.
- `SkipFileCopyChecksum = "true"` in `[common]` disables the Dir Checksum **enforcement** by SWDL at install time. The sig binds the VALUE of the Checksum field; it does NOT force SWDL to verify.
- So an already-signed metainfo that carries `SkipFileCopyChecksum = "true"` AND a Dir entry whose Checksum field is any value (matching or not) effectively means SWDL won't compare actual-vs-stated.
- The toolbox does exactly this — the Dir Checksum in its signed metainfo is stale (from a pre-shipping version of hashes.txt) but SWDL doesn't care because SkipFileCopyChecksum = "true".

## Direct consequence for attack planning
1. If a signed metainfo with `SkipFileCopyChecksum = "true"` AND an `[X\Y\N\default\Dir]` entry pointing at a user-writable location exists, and the unit's device filter accepts section device `X`, then an SD-shipped `<SD>/X/Y/N/default/hashes.txt` controls which files are copied where — because the sig doesn't bind the actual hashes.txt content.
2. hashes.txt can carry `FileName = "/abs/path"` entries with **absolute destination paths**. These are honored (confirmed by how customerupdateinfos maps absolute paths into the system tree).
3. So on any unit whose device filter matches the signed metainfo's device name, an SD with a crafted hashes.txt could place arbitrary files on arbitrary paths.
4. The signed toolbox metainfo targets device `cpu`. STD PLUS devices expose `cpuplus`. The open question: does SWDL match `cpu` on a `cpuplus` unit (prefix/alias) or does it strictly reject?

## Open questions (ordered by impact)
1. **Device filter: strict vs prefix?** If strict: STD PLUS rejects `[cpu\…]`. If prefix or if `cpu` is an alias for "LocalDevice" that applies to any iMX6 unit, STD PLUS accepts. Resolution needs Ghidra on `MetaInfoConfiguration::createMultiRelease` + `LocalDevice::installInto`.
2. **Variant filter: how does it check?** Variant 17222 IS in the toolbox list. The reason it's claimed to fail on STD PLUS is NOT variant missing (README is outdated). It may purely be the HMI Service Mode entry absence on 1-SD units.
3. **47213+ variants:** these are truly NOT in any shipped metainfo. The only clean path is to find a signed metainfo that lists them (maybe a newer TechniSat dealer image), or trigger pre-sig code exec.

## Action items
- A. **Try the existing signed toolbox AS-IS on SD1 of a 17222 STD PLUS via OBD-UDS SWDL_Start.** Don't rewrite the metainfo. If install succeeds, that's one variant done.
- B. **Dig the SWDL device filter** to confirm whether `cpu` ever matches a `cpuplus` unit.
- C. **Hunt a signed metainfo listing 47213+** across all MIB STD2 release trees we can find (not shipped here — would need to be gathered).
- D. **Parser-side attack track** (in `PARSER-ATTACK.md`) remains the "any means necessary" route.
