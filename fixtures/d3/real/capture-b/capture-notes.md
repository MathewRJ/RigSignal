# D3 boot-journal capture — capture-b

**Capture timestamp (UTC):** 2026-07-21T17:40:48Z (system local time CEST = UTC+2)
**Box:** `USER-REDACTED@IP-REDACTED`, label `capture-b`
**Identity:** hostname `HOST-REDACTED-B`, current boot index `0`
**Kernel (current boot):** `6.16.12-drmexec7-valve24.5-1-neptune-616-drm-exec-gf253f5da553e`
**dGPU present:** `0000:09:00.0`, vendor `0x1002` device `0x7590` (Navi 44 / Radeon RX 9060 XT), class `0x030000` — this box is single-boot (no multi-boot caveat needed).

## journalctl --list-boots (boot IDs omitted for publication)

```
IDX FIRST ENTRY                  LAST ENTRY
 -9 Thu 2026-07-16 23:08:52 CEST Thu 2026-07-16 23:08:53 CEST
 -8 Fri 2026-07-17 09:06:49 CEST Fri 2026-07-17 18:19:19 CEST
 -7 Fri 2026-07-17 20:13:55 CEST Fri 2026-07-17 23:48:55 CEST
 -6 Sat 2026-07-18 08:04:35 CEST Mon 2026-07-20 10:01:48 CEST
 -5 Mon 2026-07-20 10:02:39 CEST Mon 2026-07-20 17:29:54 CEST
 -4 Mon 2026-07-20 17:30:10 CEST Mon 2026-07-20 19:41:23 CEST
 -3 Mon 2026-07-20 19:41:36 CEST Mon 2026-07-20 23:01:49 CEST
 -2 Tue 2026-07-21 08:49:10 CEST Tue 2026-07-21 10:56:57 CEST
 -1 Tue 2026-07-21 10:57:10 CEST Tue 2026-07-21 12:27:37 CEST
  0 Tue 2026-07-21 12:27:50 CEST Tue 2026-07-21 19:39:13 CEST (ongoing at capture time)
```

This box retains far more history (10 boots back to 2026-07-16) than capture-a (4 boots). Only boots -1, -2, -3 were captured per spec; boots -4 through -9 exist but were intentionally NOT captured (out of scope).

## journalctl --disk-usage

`Archived and active journals take up 49M in the file system.` (unchanged before/after capture).

## Exact commands used

Identical command set to capture-a (see that box's PROVENANCE.md), targeted at `USER-REDACTED@IP-REDACTED`, same flags (`--no-pager`, `-o short-iso-precise`, `-b {0,-1,-2,-3}`, `-k` for kernel-only, `| tail -n 2000` for full-tail). All read-only; nothing written on the remote box.

## File inventory (line counts)

| file | lines | notes |
|---|---|---|
| list-boots.txt | 11 | header + 10 boots |
| disk-usage.txt | 1 | |
| system-info.txt | 3 | boot_id + uname -a |
| journal-b0-kernel.log | 1202 | current boot, starts at `Linux version` |
| journal-b-1-kernel.log | 1232 | starts at `Linux version` — full boot captured |
| journal-b-1-full-tail.log | 2000 | last 2000 lines of boot -1 |
| journal-b-2-kernel.log | 1259 | starts at `Linux version` — full boot captured |
| journal-b-2-full-tail.log | 2000 | last 2000 lines of boot -2 |
| journal-b-3-kernel.log | 1212 | starts at `Linux version` — full boot captured |
| journal-b-3-full-tail.log | 2000 | last 2000 lines of boot -3 |
| pci-devices.txt | 42 | live sysfs PCI enumeration at capture time |
| lspci-nn.txt | 42 | `lspci -nn` at capture time |

All files non-empty. All four kernel logs (b0, b-1, b-2, b-3) are complete, un-truncated boot records.

## Anomalies

None. Unlike capture-a, this box shows no evidence of journal rotation loss, no RTC-jump events, and no missing boot-time kernel content in any of the four captured boots. This is likely because capture-b retains a much larger backlog (10 boots vs. 4) and/or does not trigger the same split-lock-detector spam / RTC-correction pattern seen on capture-a.

## Enumeration-present verdict per boot (dGPU `7590` / `amdgpu` / `09:00.0`)

| boot | verdict | detail |
|---|---|---|
| 0 (current) | **PRESENT** | Starts with `Linux version` at `12:27:50`; full early-boot PCI enumeration content present. |
| -1 | **PRESENT** | Starts with `Linux version` at `10:57:10`; full early-boot PCI enumeration content present. |
| -2 | **PRESENT** | Starts with `Linux version` at `08:49:10`; full early-boot PCI enumeration content present. |
| -3 | **PRESENT** | Starts with `Linux version` at `19:41:36` (2026-07-20); full early-boot PCI enumeration content present. |

(Verified via `head -1` on each kernel log showing the `Linux version 6.16.12-...` line as the very first entry in all four files — i.e. no truncation/rotation loss on this box for any of the captured boots.)

## Clean/unclean shutdown classification (from full-tail `Reached target.*Shutdown` / `shutdown` / `Journal stopped` markers)

| boot | classification | evidence |
|---|---|---|
| -1 | **clean** | 11 markers, terminal sequence `Starting Generate shutdown-ramfs` → `mkinitcpio-generate-shutdown-ramfs.service: Deactivated successfully` → `steam[2217]: Shutdown` → `systemd[1829]: Reached target Shutdown` at `12:27:36`. Note: one extra line logged AFTER `Reached target Shutdown` — `systemd[1]: Requested transaction contradicts existing jobs: Transaction for NetworkManager-dispatcher.service/start is destructive...` — a benign systemd transaction-ordering warning during shutdown, not indicative of a hang. |
| -2 | **clean** | 9 markers, same orderly pattern, `systemd[2401]: Reached target Shutdown` at `10:56:55`. |
| -3 | **clean** | 9 markers, same orderly pattern, `systemd[2096]: Reached target Shutdown` at `23:01:48`. |

All three prior boots ended in an orderly systemd shutdown. As with capture-a, this capture establishes a clean-boot baseline and does NOT contain a captured D3-positive (GPU-loss) event.

## SMU / GPU-reset precursor grep (`0xFFFFFFFF|GPU reset|ring.*timeout`, case-insensitive)

| boot kernel log | hits | assessment |
|---|---|---|
| b0 | 10 | **all false positives** — e820/BIOS memory-map and clocksource `mask:`/`max_cycles:` boilerplate. |
| b-1 | 10 | same — boilerplate false positives. |
| b-2 | 10 | same — boilerplate false positives. |
| b-3 | 10 | same — boilerplate false positives. |

**No genuine SMU/reset precursor evidence found.** No `amdgpu ... GPU reset`, no `ring ... timeout` messages, and (unlike capture-a's boot -2) no DP-link-training errors either — all four captured boots on this box are clean of GPU-related error messages entirely.
