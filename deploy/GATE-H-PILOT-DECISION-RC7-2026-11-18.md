# Gate H Small-Group Pilot Decision - rc.7

Status: **EXECUTED / PASSED on 2026-11-19**

Date: 2026-11-18 Asia/Shanghai

The approved single-participant, synthetic-only pilot was executed through the
loopback tunnel and passed. The temporary key was revoked, the tunnel is
closed, and the single administrator-team membership was retained as approved.

## Current prerequisites

| Control | Current state |
| --- | --- |
| Application source | `c8f683ab9785c6eefc5caa071b135ed1ac227af7` |
| Running image | `0.1.0-rc.7` / `sha256:3e2515b926e607152bcc9126c10f747cec023599e04e025be29cd3fbcd1946cb` |
| Rollback image | `0.1.0-rc.6` / `sha256:ada8b2bc3b876ed1bc64ee3d83d5bb464699bbd6197bc95e88bd8f1105139ea8` |
| Database | schema 9, 18 public tables |
| App/companion health | healthy / unchanged |
| Gate G | PASS: Pro non-streaming, Pro SSE, Flash tool, usage, three encrypted audits, content-free logs/metrics and cleanup |
| Recovery point | `metadata-20261118T150636Z-605733`, verified before deployment |
| Restore drill | V9 passed in 4,217 ms |
| Current ingress | operator-only SSH tunnel to loopback HTTPS |
| Employee ingress | closed |
| Pilot traffic | not started |

Fresh read-only readiness check at `2026-11-18T23:56:57+08:00` confirmed the
running rc.7 digest, healthy App/PostgreSQL, schema `9|false`, 18 public tables,
read-only root filesystem, all capabilities dropped, no published App port, and
proxy binding only to `127.0.0.1:18443`. Evidence:
`.codex/gate_h_readiness_preflight_20261118.result.json`, SHA-256
`c1704d4385eda1a6999ab6647d8151a6f8b2b5505f356153f35af15a05ca865d`.

The rc.7 image is immutable. Any source change after `c8f683a` requires a new
image and a new release verification; do not rebuild or mutate rc.7 in place.

## Proposed minimum pilot

These are proposed values, not yet approved:

| Field | Proposed value |
| --- | --- |
| Pilot owner | requesting user |
| Rollback owner | requesting user |
| Participants | one named internal participant: requesting user |
| Window | 2026-11-19 10:00-12:00 Asia/Shanghai |
| Observation | continuous during the two-hour window; close at 12:00 |
| Data class | synthetic prompts and responses only |
| Models | `deepseek-v4-pro` and allowed `deepseek-flash` |
| Downstream credential | one N-API-P personal key, displayed once to the participant |
| Upstream credential | existing server-side Token 5; never exposed |
| Ingress | existing internal HTTPS proxy and certificate |
| Ingress switch | proxy must remain independently closable by the rollback owner |

The two-hour window is deliberately shorter than Token 5's
`2026-11-20 18:31:37 Asia/Shanghai` expiry.

## Mandatory unresolved decision

An internal HTTPS route must be selected before ingress can open. The current
proxy binds only to loopback and is reached through an operator SSH tunnel.
Publishing `18443` directly on a public interface is not accepted by this
package.

Choose exactly one:

1. Existing private/VPN address with firewall allowlist and matching DNS/TLS.
2. SSH-tunnel-only evaluation for the one named user, with no browser-facing
   public listener.
3. A separately reviewed internal ingress change with explicit bind address,
   source ACL, TLS certificate and rollback switch.

## Required user confirmation

Before a Gate H execution package can be created, confirm:

- participant roster, maximum one participant for the first run;
- exact start and end time;
- private/VPN/tunnel ingress choice;
- monitoring owner and rollback owner;
- acknowledgment that the first run uses synthetic content only;
- whether the participant is the requesting user or another named person.

Do not place credentials, employee identifiers beyond the approved roster, or
request/response content in this repository.

## Pre-ingress checks

- [ ] Fresh read-only check confirms rc.7 image, health, schema 9 and ingress
  state.
- [ ] Recovery point is less than 24 hours old at ingress start.
- [ ] rc.6 rollback image remains present and its Compose rollback override is
  verified.
- [ ] Proxy can be closed independently of application health.
- [ ] The proxy listener and firewall admit only the approved ingress path.
- [ ] `/health/live`, `/health/ready` and operator-only `/metrics` are reachable
  through the operator path.
- [ ] Unauthenticated employee API calls return 401.
- [ ] The participant understands that only synthetic prompts are permitted.
- [ ] No synthetic or real key is written to Git, logs, metrics, screenshots or
  this document.

## Pilot checks

- request count and status/error rate;
- gateway-added p50/p95 latency;
- audit completeness for every completed request;
- usage linkage and content-retention state;
- readiness, audit gate and database health;
- CPU, memory, PID and log growth;
- no secret, prompt, response or unauthorized identity appears in logs/metrics.

## Stop and rollback

Immediately close ingress and stop new traffic on any of:

- missing or corrupt completed audit or usage record;
- authentication/authorization bypass or cross-user visibility;
- secret or raw-content leakage;
- readiness/audit gate blocked while ingress remains open;
- database or upstream fail-open behavior;
- error rate above 2x baseline or gateway-added p95 latency more than 50% above
  baseline;
- any request that exceeds the approved data, model or participant boundary.

Rollback order:

1. Close the proxy ingress.
2. Preserve content-free evidence.
3. Recreate only `app` with the exact rc.6 rollback digest if the fault is
   application-specific and rollback is approved.
4. Keep the database at schema 9; do not use a down migration.
5. Re-run health, unauthenticated rejection, audit and database checks.
6. Record the trigger, timestamps, stable error codes and final ingress state.

## Completion

At the end of the window:

1. close ingress unless a new approval extends it;
2. revoke the participant's pilot key if it is no longer needed;
3. retain usage/audit metadata and content-free results;
4. confirm no participant or external user can still reach the ingress;
5. record a `go`, `hold` or `rollback` outcome;
6. require a new decision before roster or window expansion.

Gate H remains **HOLD** until an explicit approval names every field above.
