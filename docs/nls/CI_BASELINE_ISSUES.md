# Segment 1 CI Baseline Issues

## Reference revisions

| Repository | Baseline revision | Segment 1 final revision |
|---|---|---|
| NetOS | `46f69bbfa71bf3ea05e93622c89f2822d3dc96c8` | `d5d07e60ddb4f02d25a021c3214186af31fc7ae9` |
| NexOS Core | `not retrieved` | `4e58b0954994c54beed4ceab2421148b84e2c4bd` |

This register distinguishes verified workflow metadata and logs from evidence not retrieved. It does not infer results for jobs whose run records or logs were unavailable.

## NetOS sampled CI evidence retrieved

| Revision | Run | Job | Result | Verified failure signature |
|---|---:|---|---|---|
| Baseline `46f69bb` | 1343 | `six-node-nlh2-lab (ubuntu-22.04)` | failure | `NLS_DATA_MULTICAST_NOT_TUNNELED`; `NLS_HS_M1_REJECTED` at `D:M1`; traffic-path assertion failure |
| Baseline `46f69bb` | 1343 | `six-node-nlh2-lab (ubuntu-24.04)` | failure | `iperf3` UDP subprocess timeout; Router-CA rollback-mark bundle-expiry mismatch; `_log_drop` TypeError |
| Baseline `46f69bb` | 1343 | Other jobs | not retrieved in this register | Per-job conclusions/signatures not fully captured here |
| Final `d5d07e6` | 1375 | `six-node-nlh2-lab (ubuntu-22.04)` | failure | `iperf3` subprocess timeout; Router-CA rollback-mark bundle-expiry mismatch; `_log_drop` TypeError |
| Final `d5d07e6` | 1375 | `six-node-nlh2-lab (ubuntu-24.04)` | failure | `NLS_DATA_SESSION_INVALID` observed in logs; six-node job conclusion was failure |
| Final `d5d07e6` | 1375 | `ten-router-ipv6 (ubuntu-22.04)` | success | No failure signature in this job |
| Final `d5d07e6` | 1375 | `ten-router-ipv6 (ubuntu-24.04)` | success | No failure signature in this job |
| Final `d5d07e6` | 1375 | `package (ubuntu-22.04)` | success | Package, Python tests, security checks, and install lifecycle steps completed successfully |
| Final `d5d07e6` | 1375 | Other jobs | not retrieved in this register | Do not infer results |

The retrieved NetOS six-node jobs were not fully green at either sampled revision. The baseline and final-head logs share observed failure families including data-path failures, `iperf3` timeouts, the rollback-mark bundle-expiry mismatch, and the `_log_drop` TypeError. The exact full family-by-job comparison is **not retrieved**; therefore, the claim that every final-head family is a subset of baseline families is **not independently established by this register**.

## NexOS Core sampled CI evidence

- Runs #142–#146 and their reported success status: **not retrieved for independent verification** by the available run lookup.
- Latest run association with `4e58b09`: **not retrieved**.
- Core baseline run: **not retrieved**.
- Per-job conclusions and error signatures at the Core baseline and final revision: **not retrieved**.
- Whether any Core six-node job was fully green at either sampled revision: **not retrieved**.

No Core job result is inferred from NetOS results or from an unverified summary.

## Known failure families / defects to track

These families were identified in the sampled NLS CI investigation; per-repository and per-revision attribution is only asserted where shown in the evidence table above.

- `_log_drop` TypeError: unexpected keyword argument `stored_directory_seq`.
- Router-CA rollback-mark bundle-expiry mismatch.
- `NLS_CA_FRESHNESS_LOST`.
- `NLS_HS_TIMEOUT` at `M2_SENT`.
- `NLS_HS_M1_REJECTED` at baseline `D:M1` (verified in the retrieved NetOS baseline log).
- `iperf3` subprocess timeouts.
- `NLS_DATA_MULTICAST_NOT_TUNNELED`.
- `NLS_DATA_SESSION_INVALID`.

The complete per-job evidence for `NLS_CA_FRESHNESS_LOST` and `NLS_HS_TIMEOUT` is **not retrieved** in the records summarized here.

## Gating and acceptance policy

1. Unit and security checks are required gates.
2. The ten-router IPv6 test is a required gate.
3. Six-node results are compared against this register and the exact job history.
4. A known-family failure is recorded and does not by itself block acceptance. A rising frequency, or a known family appearing in a job that passed consistently at baseline (for example, ten-router), blocks acceptance and requires investigation.
5. A NEW error family requires investigation before acceptance.
6. A sampled pass does not prove an intermittent defect has been eliminated. Missing run records or logs remain **not retrieved**, not pass.

