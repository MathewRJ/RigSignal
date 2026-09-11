# D6 fixture provenance

| Fixture | Provenance | Detection branch pinned |
|---|---|---|
| `deck-real/` | Good-state capture from the handheld. The selected external TV has `active_mode: 3840x2160@120`; DRM, EDID, and `gamescopectl` material are captured data. `modes.cfg.bak.1782922517` is the real pre-fix backup retained for context. | Healthy `ok`: the pin matches the preferred external mode. Also pins skipping the unrelated LG override because that display is not connected. |
| `real-254/` | Capture from the gaming host, including DRM, EDID, and `gamescopectl` material. Its DRM state has no `active_mode`. | Healthy `ok`: the AOC pin matches the preferred mode; absence of `active_mode` is normal and skips only the active-resolution check. |
| `deck-incident-bad/` | Real Deck base and real pre-fix `modes.cfg`; `drm-state.json` differs from the good Deck capture only by a synthetic `active_mode: 1280x800@60`. EDID files are real copies of the unchanged panel data. | `mode-override-degraded`: pins both the internal-panel-native and low-area/different-aspect branches, with active mode agreeing with the bad pin. |
| `legit-downscale-modes.cfg` | Fully synthetic discriminator, paired with `synthetic-4k-drm-state.json`. | `ok`: a valid same-aspect 1920x1080 performance downscale must not be called degraded. |
| `invalid-mode-modes.cfg` | Fully synthetic discriminator, paired with `synthetic-4k-drm-state.json`. | `mode-override-invalid`: pinned 2000x2000 is absent from the connector's modes list. |
| `synthetic-4k-drm-state.json` | Fully synthetic 4K DRM-state discriminator used by the two synthetic modes files above. | Supplies the preferred 3840x2160 mode, valid 1920x1080 downscale, and absent 2000x2000 comparison state. |

`/sys/class/drm/.../modes` exposes resolutions, not refresh rates: Hz is not
recoverable from that sysfs data. A missing `active_mode` is normal captured
state, not a failed collection; D6 treats it as unknown.
