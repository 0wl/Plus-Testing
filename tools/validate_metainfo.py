#!/usr/bin/env python3
"""
Dry-run validator that replays what tsd.mibstd2.system.swdownload is believed
to do for the metainfo2.txt + per-module layout on an SD. It:

  1. Parses metainfo2.txt (INI-ish).
  2. Computes `MetafileChecksum` (SHA-1 over content from start up to the
     '[Signature]' header, exclusive — same slice SWDL uses on a stock file).
  3. Reads Skip* flags.
  4. Walks every `[device\\module\\version\\default\\Type]` section and checks
     the referenced file exists at `<SD_root>/<device>/<module>/<version>/<default>/<FileName>`.
  5. Reports which gates PASS and which are SKIPPED due to flags.
  6. Flags device entries that don't match the runtime unit (`--unit-device cpuplus`).

Usage:
   python validate_metainfo.py <sd_root> [--unit-device cpuplus] [--unit-variant 17222]
"""
import argparse
import hashlib
import os
import re
import sys
import tarfile


SEP = "\\"


def parse(path):
    txt = open(path, encoding="latin1").read()
    sections = {}
    current = None
    for raw in txt.splitlines():
        line = raw.rstrip()
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            current = m.group(1)
            sections[current] = {}
            continue
        if not line or line.startswith("#"):
            continue
        if current is None:
            continue
        m = re.match(r'^(\w+)\s*=\s*"?(.*?)"?\s*$', line)
        if m:
            sections[current][m.group(1)] = m.group(2)
    return sections, txt


def metafile_checksum(txt):
    idx = txt.find("[Signature]")
    if idx < 0:
        payload = txt
    else:
        payload = txt[:idx]
    return hashlib.sha1(payload.encode("latin1")).hexdigest()


def section_variants(kv):
    out = []
    for k, v in kv.items():
        if re.fullmatch(r"Variant\d*", k):
            out.append(v)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sd_root")
    ap.add_argument("--unit-device", default="cpuplus",
                    help="Device the target unit exposes (cpu | cpuplus | mainstd | mainplus | main)")
    ap.add_argument("--unit-variant", default="17222",
                    help="VW variant number of target unit")
    args = ap.parse_args()

    sd_root = os.path.abspath(args.sd_root)
    meta_path = os.path.join(sd_root, "metainfo2.txt")
    if not os.path.isfile(meta_path):
        print(f"FAIL: no metainfo2.txt at {meta_path}")
        sys.exit(2)

    sections, raw = parse(meta_path)
    common = sections.get("common") or sections.get("Common") or {}
    sig = sections.get("Signature", {})

    skip_sig = common.get("SkipSignatureCheck", "false").lower() == "true"
    skip_meta = common.get("SkipMetaChecksum", "false").lower() == "true"
    skip_cks = common.get("SkipChecksum", "false").lower() == "true"
    skip_cks_cp = common.get("SkipFileCopyChecksum", "false").lower() == "true"
    skip_var = common.get("SkipCheckVariant", "false").lower() == "true"
    skip_reg = common.get("SkipCheckRegion", "false").lower() == "true"

    print("=== [common] ===")
    print(f"  Release                : {common.get('Release')}")
    print(f"  MUVersion              : {common.get('MUVersion')}")
    print(f"  Vendor                 : {common.get('Vendor')}")
    print(f"  Region / Region2       : {common.get('Region')} / {common.get('Region2')}")
    print(f"  MetafileChecksum (stated): {common.get('MetafileChecksum')}")
    actual = metafile_checksum(raw)
    print(f"  MetafileChecksum (actual): {actual}")
    print()
    print("=== Skip flags ===")
    for k in ("SkipSignatureCheck","SkipMetaChecksum","SkipChecksum",
              "SkipFileCopyChecksum","SkipCheckVariant","SkipCheckRegion",
              "SkipSaveTrainName","CheckAllUpdates"):
        print(f"  {k:<22s}: {common.get(k, '<unset>')}")
    print()
    print("=== Gates ===")
    def gate(name, ok, skipped, extra=""):
        if ok:
            tag = "PASS"
        elif skipped:
            tag = "SKIP"
        else:
            tag = "FAIL"
        print(f"  [{tag}] {name}{(' — '+extra) if extra else ''}")

    gate("metafile_checksum",
         ok = (common.get("MetafileChecksum","").lower() == actual.lower()),
         skipped = skip_meta,
         extra = f"actual={actual}")

    gate("metafile_signature",
         ok = False,  # we never have a valid sig without the private key
         skipped = skip_sig,
         extra = "RSA-1024 over content up to [Signature], can only PASS by SkipSignatureCheck=true")

    variants_common = section_variants(common)
    gate("variant_covers_unit",
         ok = args.unit_variant in variants_common,
         skipped = skip_var,
         extra = f"unit={args.unit_variant} listed={variants_common}")

    regions = {common.get("Region"), common.get("Region2")}
    gate("region_covers",
         ok = ("Europe" in regions or "RoW" in regions),
         skipped = skip_reg,
         extra = f"regions={sorted(regions)}")

    print()
    # Walk device sections
    print("=== Device/module sections ===")
    ok_count = 0
    miss_count = 0
    mismatch_count = 0
    seen_devices = set()
    for sec, kv in sections.items():
        if sec in ("common","Common","Signature"):
            continue
        parts = sec.split(SEP)
        device = parts[0]
        seen_devices.add(device)
        if len(parts) < 5:
            continue
        module, version, chan, typ = parts[1], parts[2], parts[3], parts[4]
        filename = kv.get("FileName")
        if not filename:
            continue
        path = os.path.join(sd_root, device, module, version, chan, filename)
        exists = os.path.isfile(path)
        size_ok = True
        if exists and "FileSize" in kv:
            try:
                stated = int(kv["FileSize"])
                actual_sz = os.path.getsize(path)
                size_ok = stated == actual_sz
            except ValueError:
                size_ok = False
        msg = []
        if not exists:
            msg.append("missing-file")
        elif not size_ok:
            msg.append(f"size-mismatch:{kv.get('FileSize')}->{os.path.getsize(path)}")
        if device != args.unit_device and not skip_var:
            msg.append(f"device-mismatch:{device}!={args.unit_device}")
            mismatch_count += 1
        tag = "OK" if exists and size_ok and not msg else "MISS"
        if not exists:
            miss_count += 1
        elif size_ok and not msg:
            ok_count += 1
        extra = " ".join(msg)
        print(f"  [{tag}] {device}\\{module}\\{version}\\{chan}\\{typ}   file={filename}   {extra}")

    print()
    print("=== Summary ===")
    print(f"  device sections OK      : {ok_count}")
    print(f"  missing files           : {miss_count}")
    print(f"  device mismatches       : {mismatch_count}")
    print(f"  devices seen in metainfo: {sorted(seen_devices)}")
    print()
    overall = []
    # Pass criteria (sig side):
    if skip_sig:
        overall.append("sig=skipped (by SkipSignatureCheck=true)")
    elif common.get("MetafileChecksum","").lower() == actual.lower() and sig:
        overall.append("sig=need key-verify step (not emulated)")
    else:
        overall.append("sig=FAIL (bad checksum or missing)")
    if skip_var:
        overall.append("variant=skipped")
    elif args.unit_variant in variants_common:
        overall.append(f"variant={args.unit_variant} present")
    else:
        overall.append(f"variant=FAIL (unit variant {args.unit_variant} not listed)")
    if miss_count == 0 and ok_count > 0:
        overall.append(f"payload={ok_count} archives present")
    else:
        overall.append(f"payload=issues (miss={miss_count})")
    print("overall:", " | ".join(overall))


if __name__ == "__main__":
    main()
