# MIB STD2 PQ/ZR – USB OTG ("solderless") method: analysis

Source article: <https://www.drive2.ru/b/646562041351386364/>
("Installing Toolbox on almost any MIB STD2 PQ/ZR without soldering or going to 'specialists'"; method by **Malec**)
Package analysed: `Solderless_MIBSTD2_PQ_ZR_ToolboxInstaller.7z`, SHA-256 `d33d96a14ef8d162ce92cab03d4f520c35c909d3e72412371dea24ead827833d` (matches the hash published by Yandex Disk).
Firmware analysed: `MST2_EU_VW_ZR_P0254T` (this folder).

Everything marked **verified** was checked directly in the binaries, the source code or the screenshots. Everything marked **inference** follows from the evidence but has not been tested on a unit.

---

## 1. What the method does (article, translated and condensed)

The MIB STD2 PQ/ZR units with navigation or "Plus" media have **two processors**:

| CPU | Role | Firmware in this folder |
|---|---|---|
| **J5** (TI Jacinto 5) | System controller. Owns power, watchdog, CAN, and the iMX6 reset line | `main/`, `mainplus/` (`init_mibstd2*_main_sec.dat` = J5 IPL "TechniBoot"/X-Loader) |
| **iMX6** (NXP i.MX6) | Multimedia/HMI. Owns the eMMC with the QNX6 partitions where the toolbox goes | `cpu/`, `cpuplus/` (`init_mibstd2*_cpu.dat` = iMX6 IPL "TechniBoot", `mibstd2*_cpu.boot` = QNX IFS) |

Single-processor `mainstd` radios (5Q0035819*, 5Q0035824*) have no iMX6, so the method cannot work on them.

Procedure:

1. Open the unit. Fit a jumper on the **J5 boot-mode** pins and one on the **iMX6 recovery** pins (pinouts in `docs/Pinout_PQ.jpg`, `Pinout_ZR_v1.jpg`, `Pinout_ZR_v2.jpg` of the package).
2. Connect two USB-TTL adapters (FT232/PL2303/CH340/CP2102): one to the J5 UART and one to the iMX6 UART. Both are on the quadlock on ZR units. On PQ units the iMX6 UART is only on the motherboard, and on many units the iMX6 RX pin is not routed to the quadlock at all.
3. Build a **USB2HSD cable** (USB-A to the yellow HSD/"Fakra" socket on the back of the unit) and connect it to the laptop.
4. Power the quadlock from **exactly 12 V, at least 3 A**. The author warns that a 12.8 V supply skews the TTL levels and CH340 adapters stop working.
5. The J5 emergency menu appears on the J5 console:
   ```
   1 - continue boot
   2 - Emergency Update
   3 - Unlock JTAG
   4 - reset Emergency Counter
   5 - disable Watchdog
   6 - enable Watchdog
   7 - enable imx6 USB and release imx6 from reset
   ```
   Press **5**, which stops the J5 watchdog from power-cycling the iMX6, then **7**, which hands the USB/HSD port to the iMX6 and releases its reset.
6. Because of its recovery jumper, the iMX6 boot ROM enters USB serial-download mode. Windows plays the "device connected" sound.
7. Run `PLUS1.bat` (1 SD slot) or `NAV1.bat` (2 SD slots). These run `imx_usb.exe std_stage1.bin` or `nav_stage1.bin`.
8. Run `PLUS2.bat` or `NAV2.bat`. These run `imx_usb.exe custom_plus.ifs` or `custom_nav.ifs` (QNX image).
9. QNX boots and a root shell `#` appears on the iMX6 console. The toolbox is then installed from an SD card in slot 1:
   ```
   /technisat/scripts/mount_emmc.sh
   /technisat/scripts/enable_sd.sh
   mount -t dos /dev/sd10t11 /dev/sdcard      (or sd10t12 – see `ls /dev/sd*`)
   ksh /dev/sdcard/install.sh
   ```

The author's own note: on some units (Bolero 5Q0035840B H30 **2017**, 3Q0035842B H30, 5QA035842, 5QA035824A, 5K7035200D) the console only boots after **20–30 attempts**. The 2016 Bolero 5Q0035840B works fine.

---

## 2. Screenshots, one by one

| # | Shows | What it tells us |
|---|---|---|
| 1 | Back of the unit and the USB2HSD cable | Only **D+ and D−** are wired from the USB plug to the HSD socket. **No GND, no VBUS, no shield.** |
| 2 | Wiring diagram | Same cable: D+/D− only. The only ground link between PC and unit runs through the TTL adapters' GND wires and the 12 V supply. J5 TX/RX are on the quadlock. iMX6 TX/RX are on the quadlock (ZR) or the PCB (PQ). |
| 3 | J5 console | The emergency menu, as listed above. |
| 4 | iMX6 console after PLUS1 | `U-Boot SPL 2019.10-rc1-dirty (Sep 14 2019)`, `Trying to boot from USB SDP`, `SDP: handle requests...`. **Stage 1 for Plus units is a U-Boot SPL**, not Technisat code. |
| 5, 6 | Successful boot | Dual-core iMX6 (CPU1 present) at 996 MHz, `Welcome to QNX Neutrino 6.5.0 on the i.mx6 (malec edition)`, eMMC `MMC08G` found. |
| 7 | Failing 2017 Bolero | `Enabling only 1 CPU` (i.MX6 **Solo**), 792 MHz, DDR 396 MHz. Download, decompression and kernel start all work. Then **every** process (`devc-sermx1`, `slogger`, `pipe`, `devb-sdmmc-mx6q_mibstd2`, `devc-pty`, `ksh`) dies with `SIGSEGV code=1 fltno=11` at the **same** address `ip=0106e360` (shared libc). |
| 8 | Failing transfer | `Downloading file of size 4233228 to 0x107ff8e8... done`, then `Invalid state: 0` / `done` **9 times**, then `Jumping to 0x10800000` and silence. |
| 9 | Failing 3Q0035842B / 5QA035842 / 5QA035824A / 5K7035200D | Solo/DualLite clocks (DDR 396 MHz). Hangs right after `cpu_startnext: cpu0 -> fe0531ec`, i.e. at kernel start. |

### Image 7 in detail (verified numbers, interpretation is inference)
The faulting data addresses (`ref=`) of consecutive processes are `0x36a8bf06 → 0x36f50a41 → 0x3732133d → 0x375fd9fa → 0x37ac2535`. The steps are 5,000,000 − 5, 4,000,000 − 4, 3,000,000 − 3 and 5,000,000 − 5. Those are nanosecond timestamps at 1 ms tick resolution, not pointers. Each process loads a "pointer" whose memory cell holds a running clock value. One libc instruction fails in every process because of what it reads from memory, not because of a driver bug. That is the signature of **corrupted RAM contents**, which points at the DDR configuration (section 4).

### Image 8 in detail (verified against the U-Boot v2019.10 source of `drivers/usb/gadget/f_sdp.c`; rc1 is identical apart from one `#include`)
`sdp_rx_data_complete()` prints `done` and then `Invalid state: N` in the same call. It does this only when the byte counter reaches zero while the state is no longer "receiving file". Here **all 9** `done` lines, including the first one, are followed by `Invalid state: 0` (IDLE). So the gadget had already dropped back to IDLE **before** the image was complete. The only silent way to IDLE during a receive is `sdp_set_alt()`, which runs on a USB SET_CONFIGURATION/SET_INTERFACE, i.e. after a bus reset/re-enumeration. Any other path would print `Wrong State`. From that point on, every data report was counted but **not written to RAM**. Eight more reports then arrived after the counter was already zero, which fits the host's retry behaviour (section 3.2). Finally `imx_usb` still sent JUMP into the half-written image.
**Inference:** the USB link dropped or was reset mid-transfer, and nothing in the tool chain noticed.

---

## 3. Package contents and defects

| File | What it really is (verified) |
|---|---|
| `std_stage1.bin` (103,068 B) | **U-Boot SPL 2019.10-rc1-dirty built for the *Wandboard*.** The only board names inside are `imx6q-wandboard-revb1`, `imx6qp-wandboard-revd1` and `imx6dl-wandboard-revb1`. USB gadget is "Toradex" `1b67:4fff`. IVT: entry `0x00908000`, self `0x009078E8`, declares `0xD000` bytes. From offset `0xB000` the file carries a **stale second copy of an older debug SPL build**: the new build was written over an old file without truncating it. |
| `nav_stage1.bin` (225,024 B) | **The genuine factory iMX6 TechniBoot, SVN 650378, 30 May 2018**, still HAB-signed (SRK/CSF/IMG certificates dated 2018‑05‑30). Only the DCD pointer is zeroed. The IVT declares `0xA000` bytes from `0x00909000`. A 184 KB tail follows that is not covered by the IVT. |
| `custom_plus.ifs`, `custom_nav.ifs` (4,233,228 B each) | Technisat's own **emergency-update iMX6 QNX image** (`STAGE2_emergencyupdate_cpuimage_secure/.../mibstd2plus_cpu/hwi_imx6q_ddr3.c`) with a modified image filesystem (shell, `/technisat/scripts`). The startup code is **byte-identical** to `cpuplus/emergency/15/default/mibstd2plus_cpu.boot` and `cpu/emergency/12/default/mibstd2_cpu.boot` in this firmware: only 8 bytes differ (image sizes and checksum). Each file is prefixed with an IVT (self `0x107FF8E8`, entry `0x10800000`). That IVT declares **2,060 bytes less than the file**. |
| `imx_usb.exe` | A **Debug build** of boundarydevices `imx_usb_loader` (`D:\work\nxp_mfgtools\imx_usb_loader-master\msvc\imx_usb\Debug\imx_usb.pdb`). It ships with the debug CRTs `ucrtbased.dll`/`vcruntime140d.dll` and talks HID through `libusb-1.0.dll`. |
| `mx6_usb_work.conf` | The stock upstream i.MX6Q SABRE config (`mx6_qsb`, 256 KB OCRAM). |

### 3.1 Why "PLUS" units are the unstable ones: the Wandboard SPL programs the wrong DDR (verified)
U-Boot's Wandboard SPL (`board/wandboard/spl.c`, v2019.10) configures **Wandboard memory**:

| CPU | Wandboard config |
|---|---|
| i.MX6 Solo | 32-bit, 512 MB, Hynix H5TQ2G63DFR timings, Wandboard-Solo calibration |
| i.MX6 DualLite | **64-bit**, 1 GB, Wandboard-DL calibration |
| i.MX6 Quad | 64-bit, 2 GB, H5T04G63AFR (DDR3-1600) |
| i.MX6 **Dual** | **not handled at all** (`is_cpu_type(MXC_CPU_MX6Q)` only), so no DDR init |

The factory iMX6 IPL (`cpuplus/cpuboot_sec/15/default/init_mibstd2plus_cpu.dat`, TechniBoot SVN 490068, 18 Jun 2015) works quite differently. I ran it in an ARM emulator (Unicorn) with the i.MX6 peripherals it polls modelled, and recorded every MMDC/IOMUX write:

* It **waits for a hardware-revision word from the J5** on the ESAI link (`ESAI RX2 0x020240A8`). Bits [4:0] are the hardware index and the upper bits select PQ vs ZR.
* It reads fuse **OCOTP `0x430` bits [21:20]**. A value of 1 means **stdPlus** (1 SD slot, **32-bit DDR bus**); anything else means stdNav (64-bit).
* It prints `Variant: <PQ|ZR> <stdNav|stdPlus> <512MB|1GB|2GB> <DDR3|LPDDR3>`.
* Older "DDR3" boards are reported as **"WARNING: deprecated hardware! Falling back to online calibration..."** and get calibrated at every boot. Newer boards (TechniBoot labels them "LPDDR3"; the controller still runs in DDR3 mode, so they are probably low-voltage DDR3-class parts) get **stored, per-PCB calibration constants** and no online calibration.

Factory variant table (2015 IPL from this firmware, emulated):

| Fuse | HW index | Variant | MDCTL |
|---|---|---|---|
| stdNav | 1–3 | PQ stdNav 1 GB DDR3 (online cal.) | `0x831A0000` |
| stdNav | 4–7 | PQ stdNav 1 GB LPDDR3 | `0x831A0000` |
| stdNav | 8–15 | PQ stdNav 2 GB LPDDR3 | `0x841A0000` |
| stdPlus | 1–3 | PQ stdPlus **512 MB DDR3** (online cal.) | `0x83190000` (32-bit) |
| stdPlus | 4+ | PQ stdPlus **512 MB LPDDR3** | `0x83190000` (32-bit) |
| stdPlus | ZR, high index | ZR stdPlus **1 GB LPDDR3** | `0x84190000` (32-bit) |

The 2018 TechniBoot inside `nav_stage1.bin` has **more** per-revision calibration tables. For example, PQ stdPlus hardware index 0x0C is "1 GB LPDDR3" there but "512 MB" in the 2015 IPL, and index 0x14 has its own constants. So newer boards exist that even this 2015 firmware does not know about.

MMDC registers, Wandboard SPL on an i.MX6 Solo vs the factory stdPlus 512 MB configs (emulated, verified):

| Register | Wandboard SPL (Solo) | Factory 512 MB DDR3 | Factory 512 MB "LPDDR3" |
|---|---|---|---|
| MDCTL | `0x83190000` | `0x83190000` | `0x83190000` |
| MDCFG0 | `0x3F435333` | `0x3F4378F3` | `0x3F4378F3` |
| MDCFG1 | `0xB66E8B63` | `0xDB138F63` | `0xDB138F63` |
| MDMISC | `0x00001740` | `0x00081740` | `0x00081740` |
| MDPDC | `0x000255ED` | `0x00020026` | `0x00020036` |
| MDREF | `0x00005800` | `0x00007800` (`0xC000` only during online cal.) | `0x00007800` |
| MAPSR | `0x00001006` (auto power-save **on**) | `0x00000001` (auto power-save **off**) | – |
| MPZQHWCTRL | `0xA1390003` | `0xA1380000` | `0xA1390003` |
| MPWLDECTRL0/1 | `0x0040003C` / `0x0032003E` | `0x003E0048` / `0x0033003C` | `0x003E0048` / `0x0033003C` |
| MPDGCTRL0/1 | `0x42350231` / `0x021A0218` | `0x0248024C` / `0x02340238` | `0x0248024C` / `0x02340238` |
| MPRDDLCTL | `0x4B4B4E49` | `0x4A4A4C4C` | `0x4A4A4C4C` |
| MPWRDLCTL | `0x3F3F3035` | `0x3A363234` | `0x3A363234` |

The factory DDR3 column's calibration values are the seeds written before online calibration. The "LPDDR3" column's values are the final stored constants.

What the differences mean:
* **Timing (MDCFG1):** Wandboard runs the RAM faster than Technisat does: tRCD/tRP 6 vs 7 clocks, tRAS 15 vs 20, tRC 20 vs 25, tWR 6 vs 8 (MDCFG0: tXP 3 vs 4, tXPDLL 10 vs 13). Violating a chip's timing corrupts data depending on pattern and temperature, which matches "works on the 20th–30th try".
* **Calibration:** every write-levelling, DQS-gating and read/write-delay value comes from a Wandboard PCB, not the MIB2 board.
* **Refresh:** Wandboard issues 4 refreshes per 32 kHz cycle (~7.6 µs). Technisat issues 8 (~3.8 µs, extended-temperature rate).
* **Power saving:** Wandboard enables automatic power-down/self-refresh; Technisat disables it.
* **DualLite:** an i.MX6 DualLite stdPlus board would be programmed as 64-bit, but the stdPlus PCB is wired 32-bit (inference: such a unit cannot work at all with this SPL).

The QNX startup (unchanged factory code, function at `0x10803590`) **sizes RAM from the MMDC registers** (rows/cols/bus width/banks). So QNX inherits whatever the SPL programmed.

**Conclusion (strong inference, matches all screenshots and the article's 2016-OK / 2017-H30-fails observation):** on stdPlus units the only stage 1 available is a Wandboard SPL. It drives the MIB2 DRAM with foreign timing and calibration. Older "deprecated DDR3" boards tolerate it. Newer boards that rely on Technisat's stored calibration get marginal, random RAM, which produces image 7 (all processes crash on corrupted memory) and image 9 (kernel hangs). NAV units use the real TechniBoot (`nav_stage1.bin`) and get the correct factory DDR setup from the J5's hardware word, which is why they behave better.

**Why Malec probably needed a separate SPL for Plus units (inference):** the full `nav_stage1.bin` (225 KB) only fits the 256 KB OCRAM of an i.MX6 Dual/Quad. A Solo/DualLite has 128 KB, so a small standalone SPL was used instead. The **TechniBoot part alone (40 KB, as declared by its IVT) does fit a Solo/DualLite**, and the 2018 TechniBoot supports every stdPlus variant (verified by emulation). Whether the J5 sends its hardware word on Plus units after option 7 still needs to be tested on a unit.

### 3.2 Host-side defects that turn a USB hiccup into silent corruption (verified in the `imx_usb_loader` source)
1. **Retry shifts the image.** On a failed data transfer, `do_data_transfer()` halves the chunk to 512 bytes and retries. But `transfer_hid()` always sends a full 1024-byte report 2. The device counts and writes 1024 bytes while the host advances only 512, so **every retry shifts the rest of the image by 512 bytes in RAM.**
2. **WRITE_FILE errors are ignored.** `load_file()` does not check the result of the WRITE_FILE command and streams the data anyway.
3. **Jump after a failed load.** `do_download()` calls `jump()` **even when `load_file_from_desc()` failed** (exactly image 8).
4. **No verification.** `imx_usb` has `-v/--verify`, but the .bat files never use it.
5. **Length handling depends on the version.** The SPL log proves the bundled `imx_usb.exe` sent the **whole** IFS (4,233,228 B). Current upstream clamps to the IVT-declared length, which for these IFS files is **2,060 bytes short** and would truncate the image. For stage 1 the opposite is dangerous: sending the whole `std_stage1.bin` (103,068 B from `0x009078E8`) runs past the end of a Solo/DualLite's OCRAM (`0x0091FFFF`).
6. The **U-Boot SDP gadget** counts `req->length` (bytes requested) instead of `req->actual` (bytes received). It has no checksum, and a bus reset silently resets its state (`sdp_set_alt()`), as in image 8.

### 3.3 Electrical layer ("hard to connect")
* **No ground in the USB2HSD cable** (images 1 and 2, verified). USB 2.0 High-Speed signalling needs a shared ground with only a few hundred millivolts of common-mode tolerance. Here the return current runs through the TTL adapters' thin GND wires, a second laptop USB port and the bench supply. Ground offset and switching noise from the 12 V supply then cause failed HS chirp/enumeration, CRC errors, retries and bus resets. The author's own "12.8 V breaks the TTL levels" observation is a symptom of the same floating-ground problem (inference).
* Untwisted, unshielded splice between an old USB cable and an HSD pigtail: impedance discontinuities at 480 Mbit/s.
* Under-sized supply: the README requires at least 3 A. Brown-outs reset the unit mid-transfer.

---

## 4. How to make it stable

### Hardware and setup (cheap, do these first)
1. **Add GND to the USB2HSD cable.** D+/D− sit on one diagonal of the HSD socket. With the unit unpowered, find the HSD pin that has continuity to quadlock GND (Kl. 31) and wire it to USB GND, and the shield to the shell. **Leave VBUS unconnected**: the unit provides its own after option 7, which is why Windows hears the device.
2. Keep D+/D− **twisted**, the cable **short** (< 50 cm), and the splice minimal. A ready-made HSD-to-USB adapter cable is better than a home splice.
3. Put a **USB 2.0 hub** (powered) between the laptop and the unit. Better still, force **Full Speed** with a USB 1.1 hub or an **ADuM3160-type USB isolator**. Full Speed is far more tolerant of a poor cable, and the isolator also removes the ground loop. SDP works at Full Speed; the 4 MB image just takes longer.
4. **Single ground point:** bench-supply negative, quadlock GND, both TTL adapters' GND and the USB GND all meet at one point. Run the laptop on battery.
5. Exactly **12.0 V, at least 3 A** supply. Use **3.3 V** TTL adapters (FT232/CP2102 set to 3.3 V).
6. Press **5 before 7**, and power-cycle the unit between attempts. The iMX6 ROM and SPL do not recover from a half-done transfer.

### Software (recommendations for a replacement for `imx_usb.exe`; not implemented)
1. Quick win with the existing tool: run `imx_usb.exe -v <file>` (verify), and check its output before trusting the boot. It still has the retry and jump-after-failure bugs, though.
2. A robust SDP loader would:
   * Write in **64 KB chunks**, each with its own WRITE_FILE and status check. A retry re-sends the whole chunk to the same address, which is idempotent, so nothing ever shifts.
   * Send every data report as a full, padded 1024 bytes.
   * **Read back and verify** everything written (SDP READ_REGISTER).
   * **Never jump** into an image that did not verify.
   * Send only the IVT-declared part of stage 1 and check it against the OCRAM size of the detected CPU, but send the whole IFS.
   * Classify failures: transfer/link errors vs. bit errors in RAM (DDR instability).
3. Detect the CPU from the boot ROM's USB ID (`15a2:0054` Dual/Quad, `15a2:0061` Solo/DualLite) and read the HAB state. Where the ROM allows it, read `DIGPROG` and the stdPlus/stdNav fuse (OCOTP `0x430`[21:20]) the same way TechniBoot does.
4. Run a short **RAM test** over SDP after stage 1, before loading QNX. It would show within seconds whether the stage-1 DDR setup is usable on that unit, instead of 20–30 blind attempts.
5. Watch both consoles for the failure signatures above (`Invalid state`, repeated `SIGSEGV`, hang after `cpu_startnext`).

### Firmware-level fix (needs testing on a unit)
* **Plus units: try the factory TechniBoot as stage 1** (the first 40 KB of `nav_stage1.bin`). It fits Solo/DualLite OCRAM and contains every stdPlus DDR variant with Technisat's own calibration. This depends on the J5 sending the hardware word after option 7 on Plus units, and on TechniBoot accepting the following image load.
* Alternatively, build a stage 1 (U-Boot SPL or ROM DCD) from the **factory MMDC values per variant** listed above, instead of Wandboard's.

---

## 5. Open points (need a unit to confirm)
* Whether the J5 sends the hardware-revision word over ESAI after option 7 on stdPlus units (it decides whether TechniBoot can be stage 1 for Plus).
* How the NAV flow hands over from TechniBoot to the IFS download (ROM serial downloader again vs. the 184 KB tail of `nav_stage1.bin`).
* The exact HW-version ("H2x/H3x/…") to hardware-index mapping.
* The HSD pin numbering of GND/VBUS on each unit generation (measure, don't assume).
