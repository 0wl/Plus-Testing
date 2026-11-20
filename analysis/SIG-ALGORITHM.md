# metainfo2.txt signature — exact algorithm (cracked)

## MetafileChecksum computation (confirmed by matching the toolbox's shipped value)
`MetafileChecksum` = **SHA-1 of a specific slice of the file**:
1. Load the raw file bytes.
2. Remove the entire `MetafileChecksum = "<hex>"` line from `[common]`.
3. Keep every other byte UP TO (exclusive of) the `[Signature]` section header.
4. SHA-1 that byte slice.

The hash result = the value of `MetafileChecksum` in `[common]`.

Verified against the shipped toolbox metainfo:
- Stated `MetafileChecksum = "c7ecf8e46fb5915962f2d831a9460974a3f5f8a0"`.
- Computed (MetafileChecksum line REMOVED, up to `[Signature]`): `c7ecf8e46fb5915962f2d831a9460974a3f5f8a0`. Exact match.

## RSA signature (`[Signature]` section)
8 × 32-hex entries concatenate to 128 bytes = RSA-1024 signature (PKCS#1 v1.5 most likely).

Key used to verify: `/tsd/etc/swap_keys/Metainfo_key_public_signed.bin` (RSA-1024 pub + root-chain attestation).

The signature is over `MetafileChecksum` (equivalently: over the same slice SHA-1 is computed from). PKCS#1 v1.5 means it wraps as `00 01 FF..FF 00 [ASN.1 digestInfo for SHA-1] [20-byte digest]`.

## What is INSIDE the signed slice
- All of `[common]` EXCEPT the `MetafileChecksum = "<hex>"` line.
- All device sections (`[device\module\version\default\Type]`) in file order.
- Every value within those sections (FileSize, FileName, Checksum, Variant, Link, Destination, Version, …).

## What is OUTSIDE the signed slice
- The `MetafileChecksum = "<hex>"` line itself (it hashes its own-exclusive content, so it can be rewritten to any valid SHA-1 of the current content without new signing).
- Everything from `[Signature]` to EOF (the sig values themselves).

## Direct consequences
1. **Adding, removing, or modifying ANY character in the signed slice invalidates both the SHA-1 and the RSA signature.**
2. The `MetafileChecksum` line itself is not inside the hash, so you could delete it or change its value without changing the hash — but SWDL would reject the file with `Parse error, invalid metainfo checksum`.
3. The `[Signature]` section can be rewritten freely without changing the SHA-1 (it's outside the slice). But any new sig would still need to decrypt to the same SHA-1 under the trusted public key — i.e., you'd need to produce a valid RSA-1024 signature, which requires the private key.
4. Re-signing requires factoring RSA-1024 or having the private key. Factoring RSA-1024 is not practical for an individual (~$1M+, months). Private key not publicly leaked for this key.

## The collision angle (theoretical, expensive)
SHA-1 **chosen-prefix collisions** are feasible (SHAttered at ~$110K in 2017, now ~$45K-ish with GPU scale). The attack:
1. Craft a "message B" (our target metainfo with variants we want) whose SHA-1 equals the SHA-1 of "message A" (a signed metainfo).
2. The RSA signature over A's SHA-1 also verifies against B.

Caveat: chosen-prefix collisions require two custom prefixes carefully constructed; retrofitting a collision onto an arbitrary existing message is harder. But in principle, if we accept a specific prefix shape AND we have compute budget, this is the only known practical sig-forgery route for RSA-SHA1 without the private key.

Realistic recommendation: don't rely on it. Treat the signature as effectively unforgable.

## What this says for the install path
- Metainfo surgery (add variants, retarget devices, new sections) is OFF the table without a private key.
- The only in-tree working paths remain:
  - Leverage flags ALREADY INSIDE signed metainfos (`SkipFileCopyChecksum`, etc.) to loosen content binding on the shipping tree without needing new sig.
  - Trigger the signed metainfo via the correct medium / UDS routine so SWDL processes it on STD PLUS.
  - Exploit a parser bug reachable BEFORE the sig check runs.

## Open sub-question
Confirm the sig covers EXACTLY the slice `MetafileChecksum` covers. Test:
- Decrypt the 128-byte RSA sig with the pub key.
- The result (after PKCS#1 v1.5 unwrap) should equal the SHA-1 computed above.
- If match → algorithm fully confirmed.
- If mismatch → the sig covers a slightly different slice; recompute.
