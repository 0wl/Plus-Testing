# Parser / verifier attack surface — hunt plan

## Olivia's constraint (confirmed by RE)
- Signing `metainfo2.txt` with a modified variant list fails because the RSA-1024 signature is over the file content (minus `[Signature]` section). Any byte change invalidates it.
- The RSA-1024 private key for the Metainfo_key is not held and cannot be practically recovered.
- Therefore every successful install path must be one of:
  - a. The signature check is **skipped** by a condition reachable from the SD or OBD side.
  - b. Code executes **before** the signature check, from attacker-controlled input (metainfo text, tarball layout, filenames, module manifest, hashes.txt format).
  - c. Something downstream of the sig-check path trusts attacker-controlled data (hash-only verified payload, or a flag the parser sets based on an unverified field).

## Dead-string finding (SWDL binary)
All metainfo key strings — `SkipSignatureCheck`, `SkipCheckVariant`, `SkipCheckRegion`, `SkipMetaChecksum`, `SkipChecksum`, `SkipFileCopyChecksum`, `SkipSaveTrainName`, `CheckAllUpdates`, `ExclusiveUpdate`, `MetafileChecksum`, `FileName`, `Checksum`, `Variant`, `Link`, `MUVersion` — have **zero** 32-bit absolute-address references anywhere in the ELF (`.text`, `.data.rel.ro`, `.got`, `.rel.dyn`). Parser must use a base+offset or a string-table index pattern. This complicates xref hunting but does NOT mean the parse is dead. The 'SkipSignatureCheck = "true"' LOG FORMAT strings DO appear adjacent to the key strings in rodata.

## Attack surfaces worth hunting

### 1. INI parser — pre-signature side effects
SWDL log strings reveal the parse pipeline:
- `Parse error, invalid metainfo checksum`
- `Parse error, invalid metainfo signature`
- `Parse error, no common section inside metafile`
- `Parse error, metafile is corrupt`
- `Parse error, metafile is corrupt - invalid link`
- `Parse error, metafile is corrupt - invalid section name`

Target the *order*: the INI parser lays out an in-memory tree BEFORE the checksum/signature is validated (it needs a parsed `[common]` to even find the `MetafileChecksum`). That means every IniKeyValue parse call runs on attacker input ahead of the sig check.

Flaw candidates:
- **Section name length overflow** — `metafile is corrupt - invalid section name` means a length check exists; find its limit and over-/underflow it. Classic off-by-one on strncpy of a `[very\long\section\name]` to a bounded buffer.
- **`Link = "[other-section]"` resolver** — "invalid link" error is dedicated. If the resolver follows a link chain without cycle detection, a crafted cyclic link graph may stack-overflow or heap-corrupt.
- **Variant list arithmetic** — `Variant`, `Variant2`, …, `VariantNNNNN` keys. If the parser builds an array indexed by the trailing number without a cap, a `Variant999999 = "17222"` key could trigger out-of-bounds allocation.
- **Duplicate sections** — many sections with the same `[device\module\version\default\Type]` key; parser may free previously allocated nodes on insert and leave dangling pointers.
- **Trailing-equals quirks** — `Key = "value with embedded \0 bytes"`. Pure-ASCII field readers that null-terminate early cause length vs content mismatch, useful for the subsequent SHA-1 comparison.

### 2. hashes.txt parser (CheckSumFileStream.cpp)
Strings surfaced:
- `Not a valid metainfo2.txt file - missing values.` (template reused)
- Per-module `Checksum`, `Checksum1..N` chunk arrangement (SHA-1 per chunk).

Each chunk's SHA-1 is 40 hex chars. The parser reads `Checksum` + up to N enumerated `Checksum1..ChecksumNNN`. If there's no cap on N, or N is a signed int that wraps, you can push past the hash array.

### 3. Tar extraction (file factory / FileFactory.cpp)
QNX `pax`/`tar` code is a known source of symlink/path-traversal bugs. Our tar entries include `tsd/etc/persistence/esd/scripts/*.sh`. If the extractor follows `..`/symlinks in archive entries, a tarball placed in a module path could drop a file outside the module's install sub-tree (e.g., into `/tsd/bin/swdownload/tsd.mibstd2.system.swdownload` — replacing the live SWDL binary during install). The signature check is on the metainfo; tar payload is only hash-checked; `SkipChecksum = "true"` would gate that off anyway.

Specific tar flaws to probe:
- Absolute paths (`/tsd/bin/...`) inside the archive — some QNX tar libraries strip the leading `/` silently, others don't.
- Symlink inside archive — `tsd/bin/swap/tsd.mibstd2.system.swap -> /dev/stdin` style.
- Hardlink inside archive.
- Long filenames (Posix PAX extended header) — length mismatch bugs.
- Device files — if extractor honors char/block device type bytes, mknod attempts may escalate.

### 4. ELF signature section (`.tsdsignature`)
`checking elf signature using SHA-1 hash algorithm not supported by now` — a path exists where SHA-1 ELF signatures are declared unsupported. If a module archive carries an ELF whose `.tsdsignature` section claims a non-SHA-1 algo, the verifier may skip the check or default-accept. Craft an ELF with a stub signature section using an algo ID that triggers the "not supported" branch.

### 5. ARM EABI version check
`FEC version %#04x is not supported` — SWAP side. Same pattern: unsupported-version branch may early-return without a hard fail. If handling of such a FEC calls a default observer that grants permission (unlikely but possible), there's leverage.

### 6. User-defined SWDL mode
`getUserDefinedAllowed` + `SwdlGem` paths. Even if `SkipSignatureCheck=true` only works under GEM, the User-Defined SWDL path itself may accept a **less strict** metainfo by design (dealer tooling flow). If the enable gate is a field in GEM persistence, the OBD enable step may already flip it. Live trial via UDS session (extended / SA) with a crafted metainfo on SD1 will show.

### 7. `[Signature]` section parser itself
`signature1..8` are each parsed as 32 hex chars = 16 bytes = concatenated to 128 bytes. Flaws to probe:
- Fewer than 8 `signatureN` entries — does the parser default-zero the missing slots (then the RSA verify runs against all-zero bytes which never matches anything, triggering FAIL and halting)?
- More than 8 `signatureN` entries — buffer overflow candidate.
- Non-hex chars in a signature slot — parser might error out early (failing closed) OR might accept and log a warning.
- Mixed-case hex — case sensitivity differences.

### 8. Field length truncation + second-pass mismatch
If the parser truncates long values on read but later recomputes the SHA-1 of the full file, truncation inside the signed region would mismatch. But if the SHA-1 is computed over the IN-MEMORY normalized form (trimmed values, quoted-string unescaped), a crafted file whose on-disk and in-memory forms SHA-1-collide the same gives the attacker leeway to encode the same content in different ways — then one of those ways could carry extra interpreted fields (e.g., an added Variant number), while the SHA-1 stays unchanged. Unlikely in practice, worth a 10-minute test.

## Order of attack (cheapest first)
1. Build a QNX6 Unicorn harness that runs the SWDL binary's metainfo loader on a crafted file, watch where it crashes or branches. No QNX kernel needed — just enough of the libc for the I/O helpers.
2. Fuzz the INI parser with American-fuzzy-lop style mutations on `metainfo2.txt`.
3. Fuzz the hashes.txt parser similarly.
4. Build a malformed tar probe (symlink / path-traversal / long-name) and extract it with QNX's own `tar` to confirm tooling behaviour.
5. Confirm the RE-derived "dead-strings" theory by finding the base-pointer anchor and the offset table for the metainfo key pool; this unblocks a full Ghidra-equivalent xref map in Python.

## Secondary track — QNX6 emulation
Full QNX6 emulation (qemu-system-arm with a QNX 6.5 BSP) is heavy and not strictly necessary for the parse/verify question. Keep it as a parallel track; progress on it if the Unicorn harness turns out insufficient.
