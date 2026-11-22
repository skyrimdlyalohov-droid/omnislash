# OmniSlash — архитектурный обзор

OmniSlash — это безопасный Go/Python-пайплайн для авторизованного bug-bounty/recon контура: от OSINT-разведки до байт-точных проб, с fail-closed scope, лимитами, аудитом и защитой от deception/tarpit.

> Границы: только in-scope цели, `global_rps <= 4`, circuit breaker, JSONL audit без query/userinfo/body. Нет обхода honeypot/deception/canary/sandbox. Byte-exact probes (`probe/`) идут напрямую через `Dialer/Session`, минуя MITM.

## ASCII-схема потоков

```text
                         +---------------------------+
                         |   OSINT / Enrichment      |
                         | osint/engine.py           |
                         | crt.sh/OTX/Wayback/...    |
                         | Shodan/Censys/httpx/Caido |
                         +-------------+-------------+
                                       |
                                       v
                         targets_verified.json
                         (tech, cache_headers, baseline,
                          origin_ips, is_honeypot,
                          deception_risk, auth_context)
                                       |
                                       v
                         +-------------+-------------+
                         |        Planner            |
                         | osint/planner.py          |
                         | drop honeypot/high-risk   |
                         | map tech -> probe jobs    |
                         | generated_scope.allow_hosts|
                         +-------------+-------------+
                                       |
                                       v
                                jobs.json + scope
                                       |
          +----------------------------+----------------------------+
          |                                                         |
          v                                                         v
+---------+----------+                                   +----------+---------+
| Nuclei / Crawler   |                                   |   omnislashd       |
| (external recon)   |                                   | daemon + scheduler |
+---------+----------+                                   +----------+---------+
          |                                                         |
          | HTTP proxy                                              | byte-exact
          v                                                         v
+---------+----------+                                   +----------+---------+
| Caido (8080)       |                                   | probe/             |
| headless MITM      |                                   | smuggle-chain      |
| passive findings   |                                   | smuggle/h2race/... |
+---------+----------+                                   | Dialer/Session     |
          |                                              | (NO Caido MITM)    |
          | upstream                                     +----------+---------+
          v                                                         |
+---------+---------------------------+                             |
| OmniSlash Gateway (127.0.0.1:3128)  |<----------------------------+
| scope allowlist (fail-closed)       |   normal HTTP via gateway
| global 4 rps / rate limit           |
| circuit breaker [403,429,503]       |
| JSONL audit                         |
| DeceptionFilter (response-side)     |
| proxy_pin_header for Replay         |
+---------+---------------------------+
          |
          v
      Internet / In-scope target

          +-----------------------------------------------+
          | Post-processing                               |
          | nuclei.raw.jsonl -> osint/filter_nuclei.py    |
          | omnislashd-audit.jsonl -> caido_bridge.py    |
          | confirmed non-unverified -> Caido Replay/note |
          | summary.md / summary.json                     |
          +-----------------------------------------------+
```

## Ключевые модули

| Слой | Модуль | Назначение |
|---|---|---|
| L1-L4 Transport | `obfuscation/*`, `transport.go` | TLS fingerprint (uTLS), HTTP/2 consistency, behavioral timing; только в safety-gates |
| Admission/Pool | `admission.go`, `pool.go`, `dialer.go` | Проверка прокси, ротация, `latency_aware`, cooldown/ban |
| Safety | `scope.go`, `circuit.go`, `audit.go`, `gateway.go` | Fail-closed scope, 4 rps, breaker, JSONL audit |
| Deception defense | `deception.go` | Baseline calibration, synthetic 200/tarpit detection, quarantine `unverified` secrets/tokens/paths, cooldown/circuit reaction |
| OSINT | `osint/engine.py` | Discovery+enrichment+scoring, `is_honeypot/deception_risk`, tech/baseline/cache/origin/auth context |
| Planner | `osint/planner.py` | Отбор целей, tech->probe mapping, `jobs.json`, `generated_scope.allow_hosts` |
| Daemon/Probes | `cmd/omnislashd`, `daemon/*`, `probe/*` | Byte-exact probes, pinned session, JSONL audit |
| Caido/Nuclei | `osint/caido_client.py`, `osint/filter_nuclei.py`, `osint/caido_bridge.py` | Recon chain, filtering, confirmed findings -> Replay |
| Orchestration | `lab/run-pipeline.sh`, `Makefile` | Единый цикл и артефакты `runs/<ts>_<target>/` |

## Пример сценария запуска

```bash
# 1) Полный пайплайн (in-scope домен)
make pipeline TARGET=example.com PIPELINE_ARGS="--skip-nuclei --caido-url http://127.0.0.1:8080/graphql"

# или напрямую
bash lab/run-pipeline.sh --target example.com \
  --httpx-json ./runs/httpx.json \
  --caido-auth ./runs/caido-export.json \
  --skip-nuclei

# 2) Артефакты
# runs/<timestamp>_example.com/
#   targets_verified.json
#   jobs.json
#   omnislash.config.json
#   omnislash-audit.jsonl
#   omnislashd-audit.jsonl
#   caido-bridge.json
#   summary.json / summary.md

# 3) Локальный E2E smoke (без интернета)
bash lab/e2e_smoke_test.sh
```

## Echelon 1 (Meta-Controller + Differential Radar)

| Модуль | Файл | Назначение |
|---|---|---|
| Thompson Sampling | `pool.go` (`strategy: "thompson"`) | Beta($\alpha,\beta$) выбор прокси по успехам/неудачам и latency stability penalty |
| NCD deception | `deception.go` | `NormalizedCompressionDistance` (zlib): dynamic tarpit `<0.25`, structural anomaly `>0.6` |
| Telemetry | `probe/telemetry.go` | Jitter-Gate IQR>25ms, 1D Kalman, cache-buster, pair order, last-byte sync/TTFB |
| Mutator | `probe/mutator.go` | Grammar mutations (control bytes, unpaired CR/LF, space before colon, CL/TE), `tech_stack_hash` |
| Differential fuzz | `probe/differential_fuzz.go`, `daemon/*` | `probe: "differential-fuzz"`, fresh conn per hypothesis, anti-contamination, early stop on `neighbor_shift` |
| Oracle | `research/oracle.py` | Trim 15%, monotonic throttling check, Mann–Whitney p<0.01, Wasserstein, Rank-Biserial r>0.7, TPE-like next-gen budget |
| Meta-controller | `research/meta_controller.py` | Gittins index, Wald SPRT, Kelly allocation |
| Diff radar | `osint/diff_scanner.py` | `targets_verified.json` vs `state/targets_prev.json`, only new/changed |
| Verifier | `research/verifier.py` | 2 cross-proxy confirmations, no deception/unverified, confidence score |
| Notifier | `osint/notifier.py` | Telegram `OMNI_TG_TOKEN/OMNI_TG_CHAT_ID`, Caido Replay push on `confidence_score>=85` |
| Radar run | `lab/run-radar.sh`, `make radar` | Diff -> only-diff plan -> omnislashd -> verify -> notify |

```bash
# Echelon 1 radar
make radar TARGET=example.com RADAR_ARGS="--skip-notify"
```

## Что проверяется тестами

```bash
go test ./... -count=1
go vet ./...
python3 -m unittest discover -s osint -p "test_*.py"
bash lab/e2e_smoke_test.sh
git diff --check
```

## Security boundaries

- **Fail-closed scope**: цели вне allowlist/CIDR/ports отклоняются.
- **Rate/circuit**: global 4 rps, stop statuses `[403,429,503]`, breaker cooldown.
- **Audit**: JSONL, без query/userinfo/body.
- **Deception defense**: детект/карантин/блокировка; секреты `unverified` не переиспользуются автоматически.
- **Probe integrity**: smuggling/desync/race идут через `Dialer/Session` без Caido MITM.
- **No evasion**: нет обхода honeypot/deception/canary/sandbox, нет out-of-scope сканирования.