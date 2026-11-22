# OmniSlash — Guide: Launch & Usage

## 1. Requirements

- Go 1.27+
- Python 3.10+ (только для OSIS-движка: `osint/engine.py`)
- Bash + curl + jq (для `lab/verify.sh`)
- nuclei + nuclei-templates (для lab-проверки)

## 2. Launch (Go part)

```bash
# Сборка
go build ./...

# Gateway (локальный HTTP-шлюз: HTTP forward + CONNECT, stats на :9090)
go run ./cmd/gateway -config config.json -proxies proxies.txt \
     -listen 127.0.0.1:3128 -stats 127.0.0.1:9090

# Или через unified CLI
go run ./cmd/omnislash serve -listen 127.0.0.1:3128

# Daemon-проbes
go run ./cmd/omnislashd -config examples/daemon/daemon.json -once
```

## 3. Usage

### 3.1 Проверка прокси-пула

```bash
omnislash check -proxies proxies.txt
omnislash scrape -config config.json -write live.txt
omnislash fetch -url https://api.ipify.org -n 10
```

### 3.2 Запуск лаборатории

```bash
bash lab/verify.sh          # scope / rate limit / nuclei / circuit / audit
bash lab/verify.sh --no-nuclei
```

### 3.3 OSINT-пайплайн (Pre-Flight)

```bash
python3 osint/engine.py --domain example.com --out /tmp/targets_verified.json
python3 -m unittest discover -s osint -p "test_*.py"
```

Полученный `targets_verified.json` → `confidence_score`, `behind_waf`,
`recommended_profile` → подача цели в gateway/probes.

### 3.4 FAQ

```bash
go run ./cmd/omnislash faq
go run ./cmd/omnislash faq -topic rate-limit
```

## 4. Safety recap

- Global rate limit: **4 rps** (≤ 4 req/s).
- Scope: allowlist + fail-closed, private deny.
- Stop statuses: `[403, 429, 503]`.
- Circuit breaker: threshold 5 / 60s, cooldown 10m.
- Audit: JSONL, strip query/userinfo/body.
- L2/L3/L4: runtime transport wiring включён (uTLS handshake, HTTP/2 consistency, timing) **только в рамках safety-gates**; логика обхода ханипотов/десепшенов/canary не добавляется.

## 5. New functionality (delivered)

- **L2 runtime**: `utls.UClient` + `ClientHelloID` + `HandshakeContext`, SNI/ALPN `h2,http/1.1`.
- **L3 runtime**: `HTTP2ConsistencyLayer` + `HTTP2FrameLayer` + `http.Transport.HTTP2` settings.
- **L4 runtime**: `BehavioralTimingLayer` (jitter, warm-up, adaptive hook).
- **OSIS deception detection (defensive)**: `is_honeypot`, `deception_risk` в `targets_verified.json`.
- **Response-side deception/tarpit filter (Go runtime)**: baseline/wildcard calibration, synthetic-200 detection, quarantine unverified secrets/tokens/paths (no auto-reuse), anomaly reaction (cooldown/disable/mark, circuit trip). Config: `safety.deception.*`.
- **Caido integration**: `osint/caido_client.py` (GraphQL, `CAIDO_PAT`) - create project/scope, export HTTPQL/Findings to unified JSON; gateway debug proxy pinning via `gateway.proxy_pin_header` for Replay same exit-IP.
- **Nuclei integration**: external scanner via `Nuclei -> Caido(8080) -> OmniSlash Gateway(3128) -> Internet`; results filtered by `osint/filter_nuclei.py` before report. `probe/` stays direct via `Dialer`/`Session`.
- **OSINT -> Planner -> omnislashd**: `osint/engine.py` enriches `targets_verified.json` (tech/cdn/webserver/cache_headers/baseline/origin_ips/auth_context); `osint/planner.py` drops honeypot/high-deception targets and generates daemon `jobs.json` + fail-closed `generated_scope.allow_hosts`.
- **omnislashd -> Caido bridge**: `osint/caido_bridge.py` watches daemon JSONL audit and forwards confirmed, non-unverified findings to Caido Replay/notes with proxy label for `gateway.proxy_pin_header`.
- **Traffic acceleration**: pool strategy `latency_aware` (выбор по минимальной EWMA latency).

## 6. Tests

```bash
go build ./... && go vet ./... && go test ./... -count=1
python3 -m py_compile osint/engine.py
python3 -m unittest discover -s osint -p "test_*.py"
git diff --check
```
