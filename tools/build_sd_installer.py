#!/usr/bin/env python3
"""
Build the SD-only installer tree for STD PLUS app-connect enablement.

Layout created under Plus Testing/sd_installer/:
  metainfo2.txt                      (crafted; Skip* flags; cpuplus sections)
  cpuplus/<module>/<version>/default/
      cpuplus_<module>_<version>_default.tar.gz
      hashes.txt                      (placeholder)
      module.ref                      (placeholder)

Modules packaged:
  - onlineservices   (ESD screens + scripts from toolbox)
  - esd_sec          (replacement ESD defs)
  - swap             (patched swap binary, if available in toolbox/custom/swap/)
  - swdownload_sec   (patched swdl binary, if available in toolbox/custom/swdl/)
  - testinterface_sec (testinterface binary + autostart hook)

If a custom patched binary is not present, a copy of the stock firmware's
same module archive is reused (so the SD stays installable, binary still stock).
"""
import os, sys, tarfile, hashlib, shutil, pathlib, io

ROOT = pathlib.Path(__file__).resolve().parents[1]
FW = ROOT / "MST2_EU_VW_ZR_P0254T"
TOOLBOX = ROOT / "extracted" / "toolbox"
OUT = ROOT / "sd_installer"

MODULES = [
    # (module_name, version_dir, source_strategy)
    ("esd_sec",           "15", "merge_toolbox_esd"),   # STOCK esd + TOOLBOX ESD files/scripts merged — primary toolbox payload path
    ("swap",              "15", "custom_or_stock"),     # patched swap if provided, else stock
    ("swdownload_sec",    "15", "custom_or_stock"),     # patched swdl if provided, else stock
    ("testinterface_sec", "15", "stock_cpuplus"),       # stock testinterface
]

VARIANTS = ["17201","17202","17203","17204","17205","17206","17207","17222",
            "47213","47214","47215","47216"]

HEADER = """\
#
[common]
Release = "MIBStd2_StdPlus_Enable"
MUVersion = "V432"
SkipSaveTrainName = "true"
SkipSignatureCheck = "true"
SkipMetaChecksum = "true"
SkipChecksum = "true"
SkipFileCopyChecksum = "true"
SkipCheckVariant = "true"
SkipCheckRegion = "true"
CheckAllUpdates = "true"
CheckIfNotEqual = "false"
Vendor = "TechniSat"
TsdBuildNumber = "1"
MaxParallelDevices = "4"
Region = "Europe"
Region2 = "RoW"
DelMmeBackups = "false"
"""

def write_variants(f):
    for i, v in enumerate(VARIANTS, start=1):
        if i == 1:
            f.write(f'Variant = "{v}"\n')
        else:
            f.write(f'Variant{i} = "{v}"\n')
    f.write('MetafileChecksum = "0000000000000000000000000000000000000000"\n\n')

def cpuplus_header(f):
    f.write('[cpuplus]\n')
    f.write('VendorInfo = "TechniSat"\n')
    f.write('DeviceDescription = "cpuplus"\n')
    f.write('DeviceRelease = "1"\n')
    f.write('RequiredVersionOfDM = "0"\n')
    f.write('DangerousBoloUpdate = "false"\n')
    f.write('NoExclusiveBoloUpdate = "true"\n')
    f.write('MainUnitDevice = "true"\n\n')

def write_module_section(f, module, version, filename, filesize):
    section = f"[cpuplus\\{module}\\{version}\\default\\Application]"
    f.write(section + "\n")
    f.write(f'FileName = "{filename}"\n')
    f.write(f'FileSize = "{filesize}"\n')
    f.write(f'Destination = "/"\n')
    f.write(f'Version = "0{version}0"\n')
    f.write('Checksum = "0000000000000000000000000000000000000000"\n')
    for v in VARIANTS:
        pass
    # Variant restrictions: duplicate variant list so SWDL device-filter accepts
    for i, v in enumerate(VARIANTS, start=1):
        if i == 1:
            f.write(f'Variant = "{v}"\n')
        else:
            f.write(f'Variant{i} = "{v}"\n')
    f.write('RequiredComponent = "/tsd/bin/swdownload/tsd.mibstd2.system.swdownload"\n')
    f.write('RequiredVersion = "2101.231"\n\n')

def write_signature(f):
    f.write('[Signature]\n')
    zero = "0" * 32
    for i in range(1, 9):
        f.write(f'signature{i} = "{zero}"\n')

def pick_source_archive(module, version):
    """Return (src_tarball_path | None, source_description)."""
    # 1) toolbox custom override (patched binary)?
    cust_dir = TOOLBOX / "custom" / ("swap" if module == "swap"
                                     else "swdl" if module == "swdownload_sec"
                                     else None if module not in ("swap","swdownload_sec") else module)
    if module == "swap":
        cust = TOOLBOX / "custom" / "swap"
        if cust.is_dir() and any(cust.iterdir()):
            return (None, "custom-patched-swap"), cust
    if module == "swdownload_sec":
        cust = TOOLBOX / "custom" / "swdl"
        if cust.is_dir() and any(cust.iterdir()):
            return (None, "custom-patched-swdl"), cust
    # 2) stock cpuplus module archive
    stock_dir = FW / "cpuplus" / module
    if stock_dir.is_dir():
        for v in sorted(os.listdir(stock_dir)):
            d = stock_dir / v / "default"
            if d.is_dir():
                for fn in os.listdir(d):
                    if fn.endswith(".tar.gz"):
                        return ((d / fn, "stock-cpuplus"), None)
    return (None, None)

def build_merged_esd_archive(dest_tar):
    """Pack an esd_sec archive carrying BOTH stock cpuplus ESD defs AND the toolbox ESD + scripts.

    Target layout (inside archive):
       tsd/etc/persistence/esd/<existing stock esd>.esd   (preserved)
       tsd/etc/persistence/esd/mibstd2-*.esd              (toolbox GEM screens)
       tsd/etc/persistence/esd/scripts/*.sh               (toolbox activate scripts)
       tsd/etc/swdownload/modules/esd.info                (preserved)
    """
    tmp = OUT / "_esd_merge"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    # 1) Unpack stock cpuplus esd_sec archive
    stock = FW / "cpuplus" / "esd_sec" / "15" / "default" / "cpuplus_esd_sec_15_default.tar.gz"
    with tarfile.open(stock, "r:gz") as tf:
        tf.extractall(tmp)
    # 2) Overlay toolbox esd + scripts dir
    tb_src = TOOLBOX / "cpu" / "onlineservices" / "1" / "default" / "tsd" / "etc" / "persistence" / "esd"
    dst_esd_dir = tmp / "tsd" / "etc" / "persistence" / "esd"
    dst_esd_dir.mkdir(parents=True, exist_ok=True)
    for p in tb_src.rglob("*"):
        if p.is_file():
            rel = p.relative_to(tb_src)
            target = dst_esd_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
    # 3) Re-tar (preserve permissions for shell scripts)
    with tarfile.open(dest_tar, "w:gz") as tf:
        for p in sorted(tmp.rglob("*")):
            if p.is_file():
                arcname = str(p.relative_to(tmp)).replace("\\", "/")
                info = tf.gettarinfo(str(p), arcname=arcname)
                # Make shell scripts executable
                if arcname.endswith(".sh"):
                    info.mode = 0o755
                else:
                    info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                with open(p, "rb") as f:
                    tf.addfile(info, f)
    shutil.rmtree(tmp)

def write_placeholders(target_dir, archive_name, archive_size):
    hashes = target_dir / "hashes.txt"
    hashes.write_text(
        f'FileName = "/tsd/{archive_name}"\n'
        f'FileSize = "{archive_size}"\n'
        f'Checksum = "0000000000000000000000000000000000000000"\n'
    )
    (target_dir / "module.ref").write_text(
        "# placeholder — SkipChecksum active in metainfo; content ignored\n"
    )

def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    # Open metainfo
    meta = OUT / "metainfo2.txt"
    with open(meta, "w", encoding="utf-8", newline="\n") as f:
        f.write(HEADER)
        write_variants(f)
        cpuplus_header(f)
        for module, version, _ in MODULES:
            target = OUT / "cpuplus" / module / version / "default"
            target.mkdir(parents=True, exist_ok=True)
            archive_name = f"cpuplus_{module}_{version}_default.tar.gz"
            archive_path = target / archive_name
            size = 0
            if module == "esd_sec":
                build_merged_esd_archive(archive_path)
                size = archive_path.stat().st_size
                source = "merged-stock-esd+toolbox-esd"
            else:
                # Prefer custom-patched, else stock cpuplus archive
                custom_dir = None
                if module == "swap":
                    cust = TOOLBOX / "custom" / "swap"
                    if cust.is_dir() and any(f for f in cust.iterdir() if f.is_file() and not f.name.lower().startswith("place")):
                        # copy first non-placeholder file
                        for file in cust.iterdir():
                            if file.is_file() and not file.name.lower().startswith("place"):
                                # wrap as tar.gz with tsd/bin/swap/tsd.mibstd2.system.swap
                                with tarfile.open(archive_path, "w:gz") as tf:
                                    info = tarfile.TarInfo(name="tsd/bin/swap/tsd.mibstd2.system.swap")
                                    data = file.read_bytes()
                                    info.size = len(data)
                                    info.mode = 0o755
                                    tf.addfile(info, io.BytesIO(data))
                                size = archive_path.stat().st_size
                                source = f"patched-swap:{file.name}"
                                break
                        else:
                            source = None
                    else:
                        source = None
                elif module == "swdownload_sec":
                    cust = TOOLBOX / "custom" / "swdl"
                    if cust.is_dir() and any(f for f in cust.iterdir() if f.is_file() and not f.name.lower().startswith("place")):
                        for file in cust.iterdir():
                            if file.is_file() and not file.name.lower().startswith("place"):
                                with tarfile.open(archive_path, "w:gz") as tf:
                                    info = tarfile.TarInfo(name="tsd/bin/swdownload/tsd.mibstd2.system.swdownload")
                                    data = file.read_bytes()
                                    info.size = len(data)
                                    info.mode = 0o755
                                    tf.addfile(info, io.BytesIO(data))
                                size = archive_path.stat().st_size
                                source = f"patched-swdl:{file.name}"
                                break
                        else:
                            source = None
                    else:
                        source = None
                else:
                    source = None
                if size == 0:
                    # Fallback: copy stock cpuplus archive
                    stock_dir = FW / "cpuplus" / module
                    chosen = None
                    for v in sorted(os.listdir(stock_dir)) if stock_dir.is_dir() else []:
                        d = stock_dir / v / "default"
                        if d.is_dir():
                            for fn in os.listdir(d):
                                if fn.endswith(".tar.gz"):
                                    chosen = d / fn
                                    break
                        if chosen:
                            break
                    if chosen:
                        shutil.copy(chosen, archive_path)
                        size = archive_path.stat().st_size
                        source = f"stock-cpuplus:{chosen.name}"
                    else:
                        archive_path.write_bytes(b"")
                        source = "empty"
                        size = 0
            write_placeholders(target, archive_name, size)
            write_module_section(f, module, version, archive_name, size)
            print(f"  packed {module} v{version}: {size} B  <-  {source}")
        write_signature(f)
    print(f"\nSD installer tree written to: {OUT}")

if __name__ == "__main__":
    main()
