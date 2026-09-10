# Diagnose Gamescope display modes

`rigsignal-agent diagnose display` is D6, the 0.3.0 wedge of RigSignal's
diagnostic evidence engine. It compares a Gamescope `modes.cfg` override with
the display state Gamescope is using, then reports evidence, confidence, a
falsifier, and a reversible next action. It is a CLI diagnosis; Kibana remains
the deep-dive surface.

D6 was motivated by a real docked Steam Deck incident: a Samsung 4K TV was
pinned to `1280x800@60` even though the pin was a valid advertised fallback
mode. The problem was not a nonexistent timing; it was a stale override asking
the display to drive a poor mode. D6 has two finding tiers:

| Verdict | Meaning |
|---|---|
| `mode-override-invalid` | The pinned resolution, or a reported active resolution, is absent from the selected connector's resolution-only sysfs `modes` list. |
| `mode-override-degraded` | The pin matches the internal panel's native resolution after orientation normalisation, or it is under half the preferred mode's area and materially differs in aspect ratio. |

Same-aspect performance downscales that remain valid resolve as `ok`. Sysfs
`modes` data does not contain recoverable Hz, and an absent `active_mode` is
normal: D6 simply skips the active-resolution comparison.

## Usage

Run live collection in an active Gamescope session:

```bash
rigsignal-agent diagnose display
```

Replay captured input by supplying both files together:

```bash
rigsignal-agent diagnose display \
  --modes-cfg fixtures/d6/deck-incident-bad/modes.cfg \
  --drm-state fixtures/d6/deck-incident-bad/drm-state.json
```

Add `--json` for one JSON document, or `--host NAME` to attach the host name to
a diagnosis:

```bash
rigsignal-agent diagnose display --json --host fixture-peer.example
```

In offline mode, `--modes-cfg` and `--drm-state` are a pair. Supplying only one
is incomplete; the command does not combine one supplied file with live state.

| Exit | Contract |
|---:|---|
| 0 | `ok` or typed `not-applicable` (for example, no usable connected external display or no Gamescope session). |
| 1 | A real `mode-override-invalid` or `mode-override-degraded` finding. |
| 2 | Incomplete or invalid invocation: one offline flag, unreadable/missing input, malformed data, an all-unparsable nonblank `modes.cfg`, collection failure, or ambiguous connector selection. Errors are written to stderr; `--json` does not turn them into success JSON. |

## Real replay example

This is the seeded degraded run from the verified live replay on the gaming host.
The configuration was restored afterwards and its SHA-256 matched the original.

```text
detector_id: D6
rule_version: d6.2
verdict: mode-override-degraded
confidence: 0.85
confidence_basis: One or more D6 degraded-mode branches matched the pinned mode against preferred and internal-panel evidence.
evidence: modes.cfg line 1: AOC AG352UCG6:1280x800@60
evidence: card0-DP-2: preferred resolution is 3440x1440 (first sysfs mode)
evidence: card0-DP-2: degraded branch: pinned area ratio 0.207 < 0.5 and aspect delta 0.789 > 0.05 versus preferred 3440x1440
evidence: gamescope_control.valid_refresh_rates=[120.0] diverges from pinned refresh 60
plain_language: Your display is being driven at 1280x800@60 while card0-DP-2 prefers 3440x1440. This driven-vs-native mismatch points to a stale gamescope mode override in modes.cfg. A reboot won't help because this is a home-dir config, not an EDID cache.
suggested_fix: Correct or delete the offending line in ~/.config/gamescope/modes.cfg.
suggested_fix: Run: systemctl --user restart gamescope-session.target
falsifier: The finding is falsified if a fresh DRM snapshot shows the pinned/active resolution valid and neither degraded branch matches.
supported_scope: Gamescope modes.cfg overrides mapped to connected external DRM connectors.
missing_evidence: []
nearest_alternative: A display-side issue unrelated to a Gamescope mode override.
```

The area/aspect line identifies the rule branch; the refresh line is supporting
Gamescope evidence, not a claim that sysfs modes contain Hz. Follow the two
suggested fixes, then run D6 again to verify the healthy state.

## Diagnosis fields

| Field | Purpose |
|---|---|
| `@timestamp`, `host` | When and, if supplied, where the result was produced. |
| `detector_id`, `rule_version` | The detector (`D6`) and exact rule pack (`d6.2`) used for the decision. |
| `verdict`, `confidence` | The outcome and its bounded numeric confidence. |
| `confidence_basis` | The evidence branch that justifies that confidence, rather than a restatement of the verdict. |
| `evidence` | One or more cited observations used by the rule. |
| `plain_language`, `suggested_fixes` | Operator summary and reversible remediation for findings. |
| `falsifier` | The observation that would overturn the result. Falsifiers keep the rule testable and distinguish a supported diagnosis from an assertion. |
| `supported_scope` | The hardware/configuration boundary the detector actually evaluated. |
| `missing_evidence` | Evidence that was unavailable; this is always an array and may be empty. |
| `nearest_alternative` | The closest distinct explanation that the reported evidence did not establish. |

`not-applicable` is intentionally a smaller outcome with an explanation and
evidence, not a fabricated diagnosis. It means D6 had no valid display state to
compare, not that the display was proven healthy.

## Scope and accepted risk

D6 runs with the invoking user's privileges and intentionally trusts that
user's `PATH` and `HOME`. A hostile inherited environment is outside the threat
model for this user-invoked diagnostic.

MangoHud, FrameView, and CapFrameX cannot see a `modes.cfg`/DRM-state mismatch:
they measure frame delivery inside the rendered pipeline. A stale Gamescope
mode override changes what the display is asked to drive, which is invisible to
frame-time instrumentation; detecting it requires comparing configuration with
hardware state.
