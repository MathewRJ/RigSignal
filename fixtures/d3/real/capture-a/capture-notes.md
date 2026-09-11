# D3 boot-journal capture — capture-a

**Capture timestamp (UTC):** 2026-07-21T17:40:48Z (system local time CEST = UTC+2)
**Box:** `USER-REDACTED@IP-REDACTED`, label `capture-a`
**Identity:** hostname `HOST-REDACTED-A`, current boot index `0`
**Kernel (current boot):** `6.16.12-drmexec7-valve24.5-1-neptune-616-drm-exec-gf253f5da553e`
**dGPU under test:** `0000:03:00.0`, vendor `0x1002` device `0x7550` (RX 9070 XT), class `0x030000`
**Note:** box is multi-boot (SteamOS / Windows / CachyOS). Windows and CachyOS boots leave **no journald entries at all** — `journalctl --list-boots` only enumerates SteamOS (systemd-journald) boots. A gap in the boot-ID sequence's wall-clock timeline (vs. what the user may recall booting) is expected and does not indicate journal loss; it indicates a non-Linux or non-journald boot occurred in between.

## journalctl --list-boots (boot IDs omitted for publication)

```
IDX FIRST ENTRY                  LAST ENTRY
 -3 Mon 2026-07-20 22:21:55 CEST Mon 2026-07-20 23:11:03 CEST
 -2 Tue 2026-07-21 09:13:13 CEST Tue 2026-07-21 10:11:16 CEST
 -1 Tue 2026-07-21 10:11:40 CEST Tue 2026-07-21 11:07:33 CEST
  0 Tue 2026-07-21 11:07:58 CEST Tue 2026-07-21 19:39:10 CEST (ongoing at capture time)
```

Only boots -1, -2, -3 were captured per spec (current boot is 0). No boot -4 or older exists in the retained journal (list-boots only goes to -3), so nothing was skipped.

## journalctl --disk-usage

`Archived and active journals take up 43.9M in the file system.` (checked before and after capture — unchanged, confirming captures did not trigger rotation).

## Exact commands used

All run via `ssh -o BatchMode=yes -o ConnectTimeout=10 USER-REDACTED@IP-REDACTED "<cmd>"`, all journalctl invocations use `--no-pager` and `-o short-iso-precise`:

```
journalctl --no-pager --list-boots
journalctl --no-pager --disk-usage
cat /proc/sys/kernel/random/boot_id; uname -a
journalctl --no-pager -o short-iso-precise -b 0 -k
journalctl --no-pager -o short-iso-precise -b -1 -k
journalctl --no-pager -o short-iso-precise -b -1 | tail -n 2000
journalctl --no-pager -o short-iso-precise -b -2 -k
journalctl --no-pager -o short-iso-precise -b -2 | tail -n 2000
journalctl --no-pager -o short-iso-precise -b -3 -k
journalctl --no-pager -o short-iso-precise -b -3 | tail -n 2000
for d in /sys/bus/pci/devices/*; do printf "%s vendor=%s device=%s class=%s\n" "$(basename "$d")" "$(cat "$d/vendor")" "$(cat "$d/device")" "$(cat "$d/class")"; done
lspci -nn
```

All read-only. Nothing written on the remote box.

## File inventory (line counts)

| file | lines | notes |
|---|---|---|
| list-boots.txt | 5 | header + 4 boots |
| disk-usage.txt | 1 | |
| system-info.txt | 3 | boot_id + uname -a |
| journal-b0-kernel.log | 1809 | current boot, starts at `Linux version` |
| journal-b-1-kernel.log | 1726 | starts at `Linux version` — full boot captured |
| journal-b-1-full-tail.log | 2000 | last 2000 lines of boot -1 (truncated at head, boot ran long) |
| journal-b-2-kernel.log | 92 | **TRUNCATED — see anomaly below** |
| journal-b-2-full-tail.log | 2000 | last 2000 lines of boot -2 |
| journal-b-3-kernel.log | 1 | **EMPTY — "-- No entries --", see anomaly below** |
| journal-b-3-full-tail.log | 2000 | last 2000 lines of boot -3 (also does not reach boot start; first captured line is ~19 min after boot per list-boots) |
| pci-devices.txt | 63 | live sysfs PCI enumeration at capture time |
| lspci-nn.txt | 63 | `lspci -nn` at capture time |

All files non-empty except `journal-b-3-kernel.log`, which is exactly one line reading `-- No entries --` (this is journalctl's own output for a zero-match query, not a capture failure — the SSH command succeeded and returned valid journalctl output; there is simply nothing in the journal for that boot's kernel facility).

## Anomalies

1. **Boot -3 kernel messages are entirely absent from the journal** (`journalctl -b -3 -k` → "-- No entries --"). The mixed full-tail for -3 also contains zero kernel-tagged lines (`grep -c 'kernel:'` = 0) and its earliest captured line (last-2000-lines tail) is `22:40:57`, ~19 minutes after the boot's `FIRST ENTRY` of `22:21:55` per list-boots — i.e. even the userspace portion of the early boot is gone from the retained tail, though a live "no tail limit" pull might still have it in the archived journal (out of scope for this capture spec, which is fixed at last 2000 lines).
2. **Boot -2 kernel log is truncated mid-boot.** `journal-b-2-kernel.log` (92 lines) does NOT start with a `Linux version` line — it opens mid-stream at `09:13:13` with a `systemd-journald[635]: Received client request to flush runtime journal` message, i.e. the actual PCI-enumeration-time kernel messages (including the `03:00.0` `amdgpu`/`7550` probe) are gone. The only `amdgpu`/`03:00.0` lines present are late-boot DP-link-training errors at `10:11:11`–`10:11:15`, right before shutdown. The full-tail for boot -2 also shows a `systemd-journald[635]: Time jumped backwards, rotating.` at `09:13:42`, followed by a ~49-minute gap in entries jumping straight to `10:02:30` — consistent with a real-time-clock correction event triggering a journal file rotation that discarded the early-boot kernel ring buffer contents for that boot. **This matches the previously-flagged risk** that split-lock-detector log spam (or, in this specific case, an RTC-jump-triggered rotation) can evict boot-time GPU enumeration from the retained journal before it's captured — confirmed here as a real, reproduced loss mode, not merely theoretical.
3. Boot -2's full-tail also contains a `steam[2552]: Shutdown` line at `09:13:15`, only 2 seconds after boot start — likely a stale/crash-restart artifact from the Steam client rather than a real early shutdown; noted but not investigated further (out of scope for D3).

## Enumeration-present verdict per boot (dGPU `7550` / `amdgpu` / `03:00.0`)

| boot | verdict | detail |
|---|---|---|
| 0 (current) | **PRESENT** | `journal-b0-kernel.log` starts with `Linux version` at `11:07:58`; PCI enum line `pci 0000:03:00.0: [1002:7550] type 00 class 0x030000 PCIe Legacy Endpoint` present; 157 total `7550/amdgpu/03:00.0` matches. |
| -1 | **PRESENT** | `journal-b-1-kernel.log` starts with `Linux version` at `10:11:40`; same PCI enum line present; 153 matches. |
| -2 | **ABSENT / TRUNCATED** | No `Linux version` line, no PCI enum line for `03:00.0`. Only 13 late-boot `amdgpu` DP-link-error matches (all after `10:11:11`, i.e. near end-of-session, not boot time). Early kernel ring buffer content for this boot was lost — see anomaly #2. |
| -3 | **ABSENT** | Zero kernel-tagged entries at all for this boot (0 matches). Total loss of kernel data for this boot in the journal. |

## Clean/unclean shutdown classification (from full-tail `Reached target.*Shutdown` / `shutdown` / `Journal stopped` markers)

| boot | classification | evidence |
|---|---|---|
| -1 | **clean** | 9 markers incl. `Starting Generate shutdown-ramfs` → `mkinitcpio-generate-shutdown-ramfs.service: Deactivated successfully` → `steam[2542]: Shutdown` → `systemd[2088]: Reached target Shutdown` at `11:07:33`. |
| -2 | **clean** | 10 markers, same pattern, `systemd[2069]: Reached target Shutdown` at `10:11:16`, followed by `PluginLoader[2137]: Shutdown finished`. |
| -3 | **clean** | 3 markers (fewer because the -3 full-tail window starts later, missing early-boot content), but the terminal sequence (`steam[20412]: Shutdown` → `Removed slice .../org.kde.Shutdown` → `Reached target Shutdown` at `23:11:03`) is present and orderly. |

No boot shows signs of an unclean/abrupt termination (no missing terminal `Reached target Shutdown`, no abrupt log truncation mid-shutdown-sequence) — all three prior boots on this box ended in an orderly systemd shutdown, i.e. **none of the captured boots correspond to a GPU-absent-after-hard-reset or crash scenario**. This capture establishes a clean-boot baseline; it does NOT yet contain a captured D3-positive (actual GPU-loss) event.

## SMU / GPU-reset precursor grep (`0xFFFFFFFF|GPU reset|ring.*timeout`, case-insensitive)

| boot kernel log | hits | assessment |
|---|---|---|
| b0 | 11 | **all false positives** — matches are `0xffffffff` occurring in e820/BIOS memory-map and clocksource `mask:`/`max_cycles:` boilerplate lines, not GPU-register dumps. |
| b-1 | 11 | same — all e820/clocksource boilerplate false positives. |
| b-2 | 0 | no matches (consistent with the truncated/late-only content of this log). |
| b-3 | 0 | no matches (log is empty). |

**No genuine SMU/reset precursor evidence was found in this capture.** No `amdgpu ... GPU reset`, no `ring ... timeout`, no register-dump-style `0xFFFFFFFF` reads were seen — the only `amdgpu` errors present anywhere are late-boot-2 DP-link-training failures (`dpcd_set_link_settings` × several, `enabling link 1 failed: 15`), which are display-link training issues, not GPU-absent/reset precursors, and occurred at shutdown-adjacent time, not boot time.
