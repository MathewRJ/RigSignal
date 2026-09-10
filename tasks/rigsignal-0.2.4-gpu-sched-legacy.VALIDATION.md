# gpu_sched legacy port — A9.2-R live validation evidence (2026-07-17, session 2026-07-17-024-kickoff)

Box: the gaming host deck@192.0.2.254, kernel 6.16.12-drmexec7-valve, HFW (appid 2420110)
running. Deployed pair: daemon `9e5f3bec…`, probes `ddf8199e…` (main `c7288e5`).
Attach log: `variant="legacy" key_field="id" key_offset=32 scope_field="entity"
scope_offset=8`, 9/9 probes, both boxes.

## Reference captures (root ftrace, `scripts/gpu-sched-ftrace-reference.sh`, 60s each)

Capture 1 (20:27Z, pre-TSDS-fix daemon — kernel ground truth only):
`count=61213  min/mean/max = 1.000/7.681/199.000 us`
`counts=0,168,31891,20329,3449,1766,3106,450,54,0…`

Capture 2 (window 21:00:16–21:01:16Z, final daemon live):
`count=61200  min/mean/max = 0.000/7.764/198.000 us`
`counts=2,163,32438,19628,3507,1863,3080,445,74,0…`

## Daemon, same window (61 one-second docs, `metrics-rigsignal.ebpf-default`)

total events **62220** (ref 61200; +1.67% = exactly the 61st boundary window),
weighted mean **7.828 us** (ref 7.764; +0.8%), max **198.0 us** (ref 198.0 — identical).

| bucket_us | daemon% | ref% | diff_pp |
|---|---|---|---|
| 1 | 0.03 | 0.00 | +0.02 |
| 2 | 1.37 | 0.27 | +1.11 |
| 4 | 65.12 | 53.00 | +12.11 |
| 8 | 19.41 | 32.07 | −12.66 |
| 16 | 5.37 | 5.73 | −0.36 |
| 32 | 2.82 | 3.04 | −0.22 |
| 64 | 5.03 | 5.03 | −0.00 |
| 128 | 0.73 | 0.73 | +0.00 |
| 256 | 0.12 | 0.12 | −0.01 |

The 4/8 adjacent-bucket smear is the expected artifact of ftrace's microsecond-quantized
text timestamps vs the BPF ns clock, with the population mode sitting on that boundary:
combined 4+8 mass is 84.5% (daemon) vs 85.1% (ref). All ≥16us buckets match ≤0.4pp.

**Verdict: PASS.** Density post-TSDS-fix: seven probes at exactly 60 docs/min over 4
clean minutes (gpu_sched/gpu_fence/gpu_submit/irq/vfs/schedlatency at 240/4min, futex
239, bio 84 — activity-gated); zero loss-counter warnings.

Raw captures (40 MB each) intentionally not committed; regenerate with the script.
New-name-variant live regression remains DEFERRED until a fleet kernel exposes the
renamed tracepoints (A9.2-R item 4).
