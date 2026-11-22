# Local security-testing lab

This directory is a deliberately small, local-only lab for the safety controls in
`omnislash`:

- a global cap of **4 requests/second** across every upstream connection;
- a fail-closed target allowlist (scope);
- a circuit breaker that stops all traffic after repeated `403`, `429` or `503`
  responses;
- a JSONL audit log with no request or response bodies.

The lab is only for targets you own. It does not contain proxy rotation for
evasion, traffic obfuscation, or any target outside `127.0.0.1`. Do not point
Nuclei or Caido at third-party systems.

## Architecture

```text
Nuclei / curl / Caido
        |
        |  HTTP forward proxy or CONNECT
        v
omnislash gateway 127.0.0.1:3128
  scope -> global 4 rps -> circuit breaker -> audit
        |
        v
127.0.0.1:3000  Juice Shop (or fallback target)
127.0.0.1:8080  DVWA       (or fallback target)
```

Plain HTTP requests are forwarded one request at a time, so the gateway can see
the response status and feed the circuit breaker. HTTPS and raw TCP use CONNECT,
which is byte-transparent; the gateway cannot see HTTP status codes inside TLS.
For status-level safety, use the plain-HTTP lab URLs.

## Quick start

Requirements:

- Go 1.27+;
- Docker + Compose for the real Juice Shop/DVWA images, **or** nothing extra for
  the built-in fallback targets;
- Nuclei 3.x for the template run;
- Caido is optional and only for manual requests.

```bash
# Docker targets (Juice Shop + DVWA), then the gateway
lab/run-lab.sh

# No Docker: tiny local Go targets with stable lab markers
lab/run-lab.sh --fallback

# Stop Docker containers later
lab/run-lab.sh --down
```

The gateway listens on `127.0.0.1:3128`; stats are at
`http://127.0.0.1:9090/stats`; the audit log is `lab/audit.jsonl`.

### Verify the whole pipeline

```bash
lab/verify.sh
```

This is self-contained and does not need Docker. It starts the fallback targets
and a separate gateway on `127.0.0.1:3129`, then checks:

1. in-scope requests return `200`, out-of-scope host/port return `403`;
2. five sequential requests take at least ~1 second (4 rps, burst 1);
3. Nuclei runs through the gateway with `-rate-limit 4 -concurrency 1`;
4. three `403` responses trip the breaker and the next request returns `503`;
5. the audit log contains the block and `circuit_open` events.

Use `lab/verify.sh --no-nuclei` if Nuclei is not installed.

## Nuclei

Only the local lab URLs and the local templates are allowed:

```bash
nuclei \
  -u http://127.0.0.1:3000 \
  -u http://127.0.0.1:8080 \
  -t lab/nuclei-templates \
  -proxy http://127.0.0.1:3128 \
  -rate-limit 4 \
  -concurrency 1 \
  -retries 0 \
  -timeout 10 \
  -disable-update-check \
  -no-interactsh \
  -disable-redirects \
  -nc -silent
```

Why these flags:

- `-rate-limit 4` matches the gateway cap; `-concurrency 1` keeps the run
  deterministic. The gateway enforces the same cap even if a client ignores it.
- `-no-interactsh` prevents any out-of-band callback traffic.
- `-disable-update-check` and explicit `-t` keep the run offline and limited to
  the reviewed templates in `lab/nuclei-templates/`.
- `-proxy` forces traffic through the gateway. Do not rely on `HTTP_PROXY` alone:
  many clients bypass proxies for loopback addresses.

If you want to add official Nuclei templates later, download them deliberately
and run only tags relevant to the lab. Do not enable automatic template updates
inside the lab run.

## Caido (manual only)

Caido is for manual Repeater-style testing, not for an automated scan.

### Headless CLI (Linux)

Official CLI install on Kali/Debian x86_64:

```bash
sudo apt update
sudo apt install caido-cli
caido --allow-guests --no-open --listen 127.0.0.1:8080
```

Useful flags: `--listen <addr:port>`, `--proxy-listen <addr:port>`,
`--ui-listen <addr:port>`, `--invisible`, `--no-open`, `--data-path <dir>`,
`--allow-guests`. Docs: <https://docs.caido.io/app/reference/cli>.

In the headless UI/API, add an HTTP upstream proxy pointing at the lab gateway
(`127.0.0.1:3128`) and scope the two lab URLs only.

1. Create a project in Caido.
2. Add an upstream HTTP proxy: `127.0.0.1:3128`.
3. Set the project scope to exactly:
   - `http://127.0.0.1:3000`
   - `http://127.0.0.1:8080`
4. Browse or send requests manually. Do not use Automate/Scanner/workflows
   against anything outside that scope.
5. Confirm requests are flowing through the gateway:

   ```bash
   tail -f lab/audit.jsonl
   ```

Some HTTP clients skip the upstream proxy for `127.0.0.1`/`localhost`. If Caido
does that, use a hostname that resolves to loopback and is already allowed by
`lab/omnislash/config.json`:

```text
http://juice.127.0.0.1.nip.io:3000
http://dvwa.127.0.0.1.nip.io:8080
```

Those names need DNS (or a local hosts entry). If DNS is unavailable, add to
`/etc/hosts`:

```text
127.0.0.1 juice.127.0.0.1.nip.io dvwa.127.0.0.1.nip.io
```

## Safety controls

`lab/omnislash/config.json` is the reviewed lab profile:

| Control | Lab value |
|---|---|
| `rate_limit.global_rps` / `global_burst` | `4` / `1` |
| `scope.allow_hosts` | loopback and the two optional `nip.io` aliases |
| `scope.allow_ports` | `3000`, `8080` only |
| `scope.allow_private` | `true` (loopback lab only) |
| `safety.stop_statuses` | `403`, `429`, `503` |
| `safety.threshold` / `window` | `3` / `60s` |
| `safety.cooldown` | `10m` |
| `audit.path` | `lab/audit.jsonl` |

The circuit breaker is fail-closed: once open, every HTTP request and CONNECT is
refused until the cooldown expires. Restart the gateway if you need to reset it
during a lab session.

Inspect state and evidence:

```bash
curl -s http://127.0.0.1:9090/stats | jq '.circuit'
tail -n 20 lab/audit.jsonl | jq .
```

Audit entries contain time, kind, method, sanitized target (query string and
userinfo removed), status, proxy label and reason. They never contain request or
response bodies, credentials, or headers.

## Caido + Nuclei + OmniSlash (authorized recon chain)

For in-scope recon collection only, keep the chain:

```text
Nuclei / crawler -> Caido (127.0.0.1:8080) -> OmniSlash Gateway (127.0.0.1:3128) -> Internet
```

- **Caido**: headless MITM collector/passive analyzer. Configure upstream HTTP proxy to OmniSlash gateway.
- **OmniSlash gateway**: enforces scope allowlist, global 4 rps, circuit breaker, JSONL audit.
- **Nuclei**: external template scanner, run through Caido with `-rate-limit 4 -concurrency 1`; filter output via `python3 osint/filter_nuclei.py`.
- **probe/ (smuggling/desync/race)**: MUST bypass Caido and go direct via `Dialer`/`Session` for byte-exact framing.

Helper scripts/modules:
- `lab/run-nuclei-caido.sh` - wiring checklist
- `osint/caido_client.py` - Caido GraphQL export (CAIDO_PAT), HTTPQL/Findings -> unified JSON
- `osint/filter_nuclei.py` - defensive deception/soft-404 quarantine before report

Gateway debug pinning for Replay same exit-IP: set `gateway.proxy_pin_header` in config (e.g. `X-Omnislash-Proxy`) and send proxy label in that header. Disabled by default.

## Boundaries and limitations

- Real Juice Shop and DVWA containers are bound to `127.0.0.1` and attached to an
  internal Docker network; they cannot reach the internet.
- The fallback targets are not vulnerable applications. They exist only to make
  the safety controls verifiable without pulling images.
- CONNECT cannot inspect tunneled HTTP status codes. If you need status-based
  circuit breaking for an HTTPS target, put a local TLS terminator in front of
  the lab target and use plain HTTP to the terminator, or use the Go
  `RotatingTransport` where status recording is built in.
- The plain-HTTP path forwards one request per connection. HTTP Upgrade /
  WebSocket traffic should use CONNECT instead.
- Plain HTTP is parsed and re-serialized by the gateway; it is not
  byte-transparent. Use CONNECT for smuggling/raw-payload work, accepting that
  target status codes are then invisible to the breaker.
- No public proxies, no proxy rotation for evasion, no MAX/Sferum/Calls testing.
  Those targets remain out of scope for this lab.
- The audit log is append-only JSONL; rotate or truncate it deliberately between
  exercises.
