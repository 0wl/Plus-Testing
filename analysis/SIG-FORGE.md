# RSA-1024 e=3 signature forgery — Bleichenbacher '06 angle

## The setup
All three public keys in `/tsd/etc/swap_keys/` have:
- modulus: 128 bytes big-endian (RSA-1024)
- exponent: value `0x03`, stored as 32 bytes big-endian at offset 128..160 of the key file
- trailing 128 bytes: signature-over-this-key by the root key (not used for verifying signed content, only for key-chain attestation)

```
Metainfo_key_public_signed.bin   e=3   (verifies metainfo signatures + Data-scope payloads)
Data_key_public_signed.bin       e=3   (byte-identical to Metainfo key here; verifies signed_exception_list.txt and other data blobs)
FEC_key_public_signed.bin        e=3   (verifies FEC blobs / SWaP codes)
```

The **signature-verify algorithm** is RSA-1024 e=3 wrapped in PKCS#1 v1.5 digestInfo for SHA-1. Confirmed by cubing the toolbox's shipped `[Signature]` concatenation under the Metainfo pubkey: the result is `0x00 0x01 0xFF… 0x00 [digestInfo-SHA1] [hash]` where `[hash] = eabf0ec5…` matches the SHA-1 computed over the metainfo's signed slice.

## Why this is a historic crack-able configuration (Bleichenbacher '06 / Finney)
When `e = 3` and the verifier is lazy about PKCS#1 v1.5 padding (doesn't offset-lock the ASN.1 digestInfo position, doesn't count FF bytes, doesn't bounds-check the trailing-garbage region), the attacker can:
1. Choose any target SHA-1 hash H.
2. Build a short PKCS structure `00 01 FF*k 00 digestInfo H` leaving many garbage bytes at the end.
3. Compute the integer cube root of that structure padded-with-zeros-or-fill.
4. Submit that cube-root as the signature.
5. The verifier cubes it, gets a 128-byte message whose high-order bytes match the PKCS structure. Loose verify reads the high bytes and ACCEPTS.

This bug killed OpenSSL, NSS, Mozilla, GnuTLS, and many embedded crypto libraries around 2006-2008. TechniSat's `ext.cryptolib/lib/src/rsa.c` is in-house, not OpenSSL. The chance it's vulnerable is non-trivial.

## What's proved so far (offline)
`tools/bleichenbacher06_forge.py` and `tools/forge_custom_metainfo.py` produce a forged `[Signature]` section that:
- Cubes under the Metainfo pubkey to a byte string beginning `00 01 FF*k 00 digestInfo <any chosen SHA-1>` with k >= 5 FF bytes followed by digestInfo + hash + 84 bytes of garbage.
- Does NOT match the RFC-8017 §9.2 reference (too few FF, trailing garbage).
- Does MATCH what a strstr-style or "find the digestInfo anywhere after the zero byte" verifier sees.

```
$ python tools/forge_custom_metainfo.py extracted/toolbox/metainfo2.txt \
       extracted/swapkeys/tsd/etc/swap_keys/tmp/Metainfo_key_public_signed.bin \
       sd_installer_forge/metainfo2.txt \
       --add-variant 47213 47214 47215 47216
...
  recomputed MetafileChecksum  : 070660bad34a037050faed61df77ce4eb68316e2  OK
  recomputed signed-slice SHA1 : 2ea09087ae0a84fc3e6fc2e9bbd6b0aab0657c14  OK
  RSA cube verify (loose PKCS) : OK
     prefix exact 44 bytes, garbage tail 84 bytes
```

## What's unproved (needs a real unit or Ghidra)
Whether TechniSat's RSA verify is loose enough to accept the forge. Two outcomes:
- **LOOSE**: this crack is end-to-end. We can make SWDL (and SWAP, and FEC manager) accept arbitrary attacker-authored content, including a metainfo with any variant list AND any target device path AND arbitrary payload. App-connect unlock becomes trivial via a forged `signed_exception_list.txt` that grants the right FSIDs.
- **TIGHT**: verify code bounds-checks the FF count OR offset-locks the digestInfo. Forged sig rejected, crack doesn't work.

Determination plan:
1. Disassemble the RSA verify function (look in SWAP binary first — smaller, easier). Anchor via the "RSA calculation failed" / "cwords[RSA_SIZE_WORDS]" strings' nearest code.
2. Specifically look for the padding check: does it (a) `memcmp` against a fixed layout of the expected bytes, or (b) scan for 0x00 0x01, scan for the 0x00 separator, parse ASN.1 from there?
3. (b) is the Bleichenbacher '06 pattern — verify is loose, crack works.

## The exception list / FSID angle
`signed_exception_list.txt` is verified under `Data_key` (same crypto as Metainfo_key, same vulnerability profile). The exception list grants FSIDs per FAZIT. Forging it enables:
- App connect (mirrorlink, CarPlay, AndroidAuto FSIDs — modules are already shipped on cpuplus).
- Nav features even on STD PLUS (nav modules aren't in cpuplus — can't unlock).
- Anything else gated by FEC.

So forging the exception list is the DIRECT PATH to app-connect enablement on STD PLUS without any firmware mod. Even bigger: it works regardless of SWDL's behaviour, because it hits SWAP's verifier, which uses the same cryptolib.

## FEC forging
FEC blobs are verified under `FEC_key` (also e=3). Forging FEC blobs is strictly more work (binary structure, FSID encoding, individualization attributes) but same crypto outcome. If the exception list route works it's simpler.

## Next moves
- A. **Try the forged metainfo on a GEM-enabled STD PLUS unit via SD1 + OBD-UDS SWDL trigger**. Primary falsification test.
- B. **Reverse the ARM RSA verify function** to check loose/tight before touching a unit. If strict, pivot to parser-bug angle (`PARSER-ATTACK.md`). If loose, scale to exception-list forging.
- C. **Build a signed_exception_list forger** (`tools/forge_exception_list.py`) once the exception-list serialization format is known (need to find a leaked example OR reverse the SWAP parser).
