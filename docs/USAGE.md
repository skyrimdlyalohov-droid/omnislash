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
- Никакого трафика наружу вне allowlist; evasion-уровни L2–L4 — design/deferred.

## 5. Tests

```bash
go build ./... && go vet ./... && go test ./... -count=1
python3 -m py_compile osint/engine.py
python3 -m unittest discover -s osint -p "test_*.py"
git diff --check
```
