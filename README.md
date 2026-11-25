# Omnislash

**Platform for controlled, verifiable HTTP desync research.**

Omnislash is an AppSec research platform, not a stealth scanner. It gives a
probe author a byte-exact, attributable socket: the proxy is pinned before the
handshake, the ClientHello is explicit, and every response is recorded as
evidence. The learning loop only reorders techniques an operator already
declared.

The core is stdlib Go plus refraction-utls; the research loop is stdlib Python.
There is no Docker, Node.js, npm or CDN dependency, and the learning loop never
calls the network. The rules are in [MANIFESTO.md](MANIFESTO.md); invariants and
negative tests are in [ARCHITECTURE.md](ARCHITECTURE.md).

## Safety Gates

Read this before running anything. These are enforced controls, not advice.

1. **Authorized targets only.** Use your own lab instances. Examples use
   `LAB-ID` placeholders — replace them with your lab ID, never with a public
   hostname. OSINT modules are intelligence-only; they never auto-attack what
   they find.
2. **Fail-closed egress.** `allow_direct: false` by default and forbidden in
   `trust_tier: strict`. A dead proxy fails the experiment; there is no silent
   direct fallback.
3. **Scope before dial.** An explicit scope file (`--scope-file`) or
   `scope.allow_hosts` is mandatory for unattended runs. Hosts are resolved
   locally, all addresses are checked, and a checked IP is pinned into CONNECT.
   Out-of-scope targets get `403` without a dial.
4. **The transport owns the socket.** A probe receives an already dialed
   `net.Conn`. No `net.Dial`, no `http.Client`, no `net/http` request writer
   inside `probe/`. One experiment uses one pinned session and one exit IP.
5. **Evidence before verdicts.** `unverified` is a quarantine label. Only
   cross-proxy-verified target responses can become executable strike jobs; two
   independent attributed exits are required. WAF pages and parser rejections
   are weak negative evidence; proxy failures do not train at all.
6. **No evasion claims.** TLS fingerprint rotation exists for protocol
   reproducibility across intermediaries, not anonymity. We do not build or
   document WAF/IDS evasion.
7. **Local-only control plane.** Gateway, stats, dashboard and the semantic
   skeleton service bind to loopback. Audit lines carry attribution and
   evidence, not credentials or secrets.

## Architecture

```text
 target scope file / LAB-ID allowlist
                 │
 proxy lists ──> scrape ──> admission (CONNECT + TLS + N-byte echo)
                 │                     │
                 └──────────────> verified pool ──> Dialer ──> Session (pinned)
                                                                  │
                                      utls handshake on the proxy-dialed conn
                                                                  │
                                raw net.Conn ──> probe/ (byte-exact writes)
                                                                  │
                                              JSONL audit ──> online loop
                                                                  │
                                          weights / hypotheses / candidates
                                                                  │
                                   two verified exits ──> strike job (optional)
```

The declared job is immutable: each attempt works on a copy. Learning may
reorder variants, mutations and declared framing lengths; it cannot invent a
probe, a payload or a finding.

## Quick start (no Docker)

```bash
cp config.example.json config.json            # then narrow scope to your LAB-ID
make build                                    # bin/omnislash
make daemon-build                             # bin/omnislashd
bash lab/e2e_smoke_test.sh                    # offline, loopback only
```

A daemon job for an authorized lab instance:

```json
{
  "name": "lab-clte-gpost",
  "target": {
    "addr": "LAB-ID.web-security-academy.net:443",
    "host": "LAB-ID.web-security-academy.net",
    "path": "/"
  },
  "tls": "h1",
  "probe": "smuggle-chain",
  "success_contains": "Unrecognized method GPOST",
  "attempts": 3
}
```

```bash
./bin/omnislashd -config examples/daemon/daemon.json -once
./bin/omnislash serve -config config.json -proxies proxies.txt
```

`serve` starts the loopback gateway (`127.0.0.1:3128`), the dashboard and stats
(`127.0.0.1:9090`), health/scrape loops and (by default) the online learning
worker. Without a verified proxy in the pool, a strict-config dial is refused;
it does not leak your real IP.

## Surfaces

| Surface | Use | Boundary |
|---|---|---|
| `Dialer` / `Session` | raw TCP/TLS from Go tools | session pins one proxy for its TTL; `ProxyOf(conn)` attributes the exit |
| `probe/` | smuggling, H2 desync, differential fuzz, raw replay | receives `net.Conn`; writes bytes itself |
| `omnislashd` | scheduled jobs, retries, JSONL audit | one attempt = one pinned session |
| `omnislash serve` | local CONNECT gateway + dashboard | loopback only; fail-closed scope |
| `research/online_loop.py` | stdlib streaming learner | tails audit from a persisted offset; no network |
| `playbooks/` | curated priors with explicit provenance | priors never presented as observations |

## Transport controls

| Config key | Meaning |
|---|---|
| `trust_tier` | `strict` (full admission, direct forbidden) or `trusted` (owned pool) |
| `allow_direct` | dangerous opt-in for a trusted pool; default `false` |
| `strategy` | `round_robin`, `random`, `least_used`, `sticky` |
| `scope.*` | fail-closed allowlist, private/metadata blocking, local DNS pinning |
| `health.*`, `cooldown.*`, `http.ban_statuses` | liveness, exponential backoff, proxy bans |
| `rate_limit.global_rps` | pool-wide cap so rotation cannot multiply request rate |
| `safety.*` | stop statuses in a sliding window, hard request budget, cooldown |
| `audit.path` | JSONL evidence log (query strings/userinfo stripped) |
| `scraper.*` | sources, strict validation mode, hot-swap with a minimum pool size |
| `gateway.listen`, `stats.listen` | loopback listeners; set to `""` to disable |

`403` in `ban_statuses` can be a WAF verdict on a specific path rather than a
proxy ban. Keep `[407, 429]` for quiet work and interpret `403` from the audit
evidence instead.

## TLS fingerprint rotation

`tls_fingerprints` rotates a coherent ClientHello per `Session`:

```json
"tls_fingerprints": ["chrome_133", "safari_ios", "okhttp"]
```

- Defaults are Chrome 133 / iOS Safari / Android OkHttp. Unknown names are a
  config error — there is no silent Chrome or Go fallback.
- The handshake uses refraction-utls **on the connection the proxy already
  dialed**. No utls dial, no direct egress; `ProxyOf(conn)` still reports the
  pinned proxy after the handshake.
- An explicit empty array disables fingerprinting and keeps `crypto/tls`.
- SNI, ALPN and certificate verification come from the caller's `tls.Config`,
  so a fingerprinted session has the same trust behavior as a stdlib one.
- This is a reproducibility control. It does not make traffic anonymous.

## Deception resistance

`omnislash` does not bypass tarpits. It detects and quarantines them.

```json
"safety": {
  "enabled": true,
  "stop_statuses": [403, 429, 503],
  "threshold": 5,
  "window": "60s",
  "cooldown": "10m",
  "deception": {
    "enabled": true,
    "semantic_service": true,
    "semantic_addr": "127.0.0.1:8000",
    "baseline_samples": 2,
    "ncd_tarpit": 0.25,
    "ncd_structural": 0.6,
    "repeat_status": 200,
    "repeat_threshold": 8,
    "repeat_window": "10s",
    "action": "mark"
  }
}
```

- A baseline is calibrated **before the first probe**. Without a baseline the
  filter does not guess.
- The loopback semantic service reduces sampled bodies to value-free canonical
  skeletons; NCD compares skeletons, not dynamic values. Identical bytes are
  guarded explicitly, and an unavailable service is reported, not faked.
- Repeated near-identical responses inside `repeat_window` trigger the action.
  `mark` bans the target for the session (`target_ban_ttl`); it does **not** trip
  the proxy circuit.
- `cooldown` and `disable` are the other actions. All three keep the raw
  exchange in the audit log so a human can review the verdict.

## Self-learning and hard quarantine

The daemon keeps an epsilon-greedy prior over declared variants, mutations and
lengths. Defaults: `epsilon=0.12`, `epsilon_min=0.02`, `epsilon_decay=0.995`.
Decay follows observed attempts, not wall clock. One roll is taken per attempt
and shared by all ranking stages, so exploration stays near 12% instead of
stacking to ~22%. Use `learning_enabled: false` to turn it off; learning never
invents a technique or a verdict.

Attempts are labelled `Proxy Failed`, `WAF Blocked`, `Target Rejected` and
`Target Response`:

| Class | Training effect |
|---|---|
| Proxy Failed | counted in its own class; **never** trains and never yields a candidate |
| WAF Blocked | weak negative signal (`strength=0.25`) |
| Target Rejected | weak negative signal (`strength=0.25`) |
| Target Response | full evidence only when attributed to a verified proxy |

The Python worker tails `audit.path` from a persisted byte offset, atomically
updates `state/learned_weights.json` and publishes `state/jobs_online.json`.
Holdout hosts are counted but never enter training cells. Unverified signals
may nudge weights and land only in `candidates`; a `jobs` (strike) entry needs a
confirmed queue shift, a real dial address and two independently attributed
proxy exits. One audit line contributes at most one identity, so noise cannot
confirm itself.

The dashboard card **Online Feedback Loop** shows state, processed episodes,
outcome counters and accuracy. `POST /api/learning/toggle` pauses/resumes the
worker; `POST /api/learning/feedback` applies explicit ±2.0 labels. Calibration
(`make calibrate`) is native: local simulations plus loopback proxy/backend
pairs, with train/validation split by host or lab ID.

## CLI and local API

```text
omnislash check|scrape|fetch|serve|healthcheck
omnislashd -config <daemon.json> [-once] [-job NAME]
```

`serve` and `omnislashd` expose loopback JSON surfaces: `/stats`, `/status`,
`/healthz`, `/readyz`, `/experience`, `/api/dashboard`, `/api/learning/status`,
`/api/learning/toggle`, `/api/learning/feedback`, `/api/run` and
`/api/caido/push`. `/api/run` is fail-closed: scope must be enabled and the
target must pass the same allowlist and local resolution checks as any other
dial. Missing action backends return `501`, never a fake success.

## Verification

```bash
go vet ./...
env -u HTTPS_PROXY -u HTTP_PROXY -u ALL_PROXY -u NO_PROXY -u no_proxy \
  go test -race ./... -count=1
python3 -m unittest discover -s research -p 'test_*.py'
python3 -m unittest discover -s osint -p 'test_*.py'
bash lab/e2e_smoke_test.sh
make release
git diff --check
```

The suite covers handshake rotation through one CONNECT proxy, exit attribution
after TLS, dead-proxy silence, strict fingerprint parsing, baseline-before-probe,
tarpit detection, epsilon roll sharing, outcome classification, proxy-failure
exclusion, weak-signal scaling and the two-exit strike gate. All lab fixtures
are loopback; no external network is needed for tests or calibration.

## Further reading

- [MANIFESTO.md](MANIFESTO.md) — what this project is and will not be.
- [ARCHITECTURE.md](ARCHITECTURE.md) — invariants mapped to code and tests.
- [lab/README.md](lab/README.md) — authorized local labs and smoke checks.

MIT licensed; see [LICENSE](LICENSE). Use only on systems you own or have
written authorization to test.
