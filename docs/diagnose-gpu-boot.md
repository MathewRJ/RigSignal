# Diagnose GPU boot enumeration

`rigsignal-agent diagnose gpu-boot` (D3) diagnoses an explicitly selected GPU
slot that is absent or enumerates differently after boot. PCI sysfs is the
authoritative presence and identity source; journald adds bounded, best-effort
corroboration and AMD/amdgpu precursor context.

## Usage

Learn a healthy baseline first. Selection is intentionally explicit because a
machine may have both an iGPU and a dGPU:

```bash
rigsignal-agent diagnose gpu-boot --learn-baseline --slot 0000:03:00.0
rigsignal-agent diagnose gpu-boot
rigsignal-agent diagnose gpu-boot --reset-baseline
```

`--learn-baseline` never overwrites a baseline; reset it first. Add `--json`
for one JSON result and `--state-file PATH` to use a non-default state file.
The default is `$XDG_STATE_HOME/rigsignal/detectors/d3-gpu-boot.json` (or
`~/.local/state/...`).

Offline replay is deliberately explicit and never mixes fixtures with live
inputs. It requires `--offline`, `--pci-snapshot`, a non-default `--state-file`,
and either `--boot-list` or `--current-boot-id`; journal files are optional:

```bash
rigsignal-agent diagnose gpu-boot --offline \
  --pci-snapshot fixtures/d3/real/capture-a/pci-topology.txt \
  --boot-list fixtures/d3/real/capture-a/boot-inventory.txt \
  --journal-prior-tail fixtures/d3/real/capture-a/journal-previous-1-tail.log \
  --state-file /tmp/d3-state.json --slot 0000:03:00.0 --learn-baseline
```

For a black-screen symptom, run the command over SSH. Enabling `sshd` before a
failure is part of the setup; D3 cannot make a remote path appear after a GPU
has stopped presenting a local display.

## Verdict contract

| Verdict | Exit | Meaning |
| --- | ---: | --- |
| `baseline-required` | 0 | No explicit healthy slot baseline exists. |
| `hardware-changed` | 1 | Identity relocated, was replaced at the BDF, or is ambiguous. |
| `bus-absent` | 1 | Expected identity is absent and its BDF is empty or bridge-class. |
| `precursor-warning` | 1 | Paired prior boot meets the scoped AMD/amdgpu precursor rule. |
| `recovered` | 0 | A later healthy boot consumed one recorded bus-absence. |
| `history-unavailable` | 0 | GPU is present but no paired prior history is available. |
| `ok` | 0 | Baseline identity is present and no precursor matched. |
| incomplete/invalid invocation | 2 | Input/state/preflight error; details go to stderr. |

Every diagnosis includes confidence basis, evidence, falsifier, supported
scope, missing evidence, and nearest alternative. Findings say “most
consistent with”; they do not establish an absolute cause. A failed journal
query becomes missing evidence and cannot erase a sysfs finding.

## Collection caveats and privacy

D3 selects journal boots by explicit normalized boot ID, never a relative
`-b -1` offset: multi-boot systems can boot another OS between Linux boots.
It validates that an end-oriented tail reaches the boot’s last entry before
using absent shutdown markers; an early `steam: Shutdown` log line is not a
clean OS shutdown. Journal retention can still remove relevant history. The
2026-07-21 capture from the gaming host lacked boot-time enumeration after an RTC-jump
rotation even with persistent journald, so `history-unavailable` is an honest
result rather than a healthy claim.

Evidence is emitted as normalized facts. Any retained excerpt is redacted for
user names, non-target host names, MAC addresses, serials, UUID-bearing command
lines, and control characters. The included fixture captures are redacted too.
