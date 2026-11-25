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

          +-----------------------------------------------------------+
          | Local control plane: stats.listen / daemon control_addr   |
          | GET / embedded Web UI (web/index.html, //go:embed)         |
          | GET /api/dashboard; POST /api/scrape|calibrate|run|        |
          |                     /api/caido/push                        |
          | legacy JSON: /stats /healthz /readyz /status /experience   |
          +-----------------------------------------------------------+

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
| Control UI | `ui.go`, `web/web.go`, `web/index.html` | Встроенный SPA-дашборд на stats/control-порту, action API `/api/*`, legacy JSON без изменений |

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

## Echelon 2 (Zero-Marginal-Cost Incubator & Global Projection)

| Модуль | Файл | Назначение |
|---|---|---|
| Local stack matrix | `sandbox/docker-compose.stacks.yml` | Локальные связки `Nginx/Envoy/HAProxy -> Python/Node` для фаззинга без интернета |
| Incubator | `lab/run-incubator.sh`, `make incubate` | `omnislashd differential-fuzz + oracle` против `127.0.0.1`, `trust_tier: trusted`, узкий scope |
| Knowledge base | `research/knowledge_base.py`, `state/zero_day_vault.json` | Universal Keys: `raw_payload_b64`, `mutation_type`, `protocol_edge`, `tech_stack_hash` |
| Planner integration | `osint/planner.py` | При совпадении `tech_stack_hash` ставит `raw-replay` Universal Key с высоким Gittins; адаптирует payload через WAFProfile |
| WAF inference | `research/waf_inference.py`, `state/waf_profiles.json` | Упрощённый active grammar inference/L* для HTTP-токенов; `adapt_payload_for_waf` |
| Upgrade-desync | `probe/ws_grpc.go`, `daemon/*`, `osint/planner.py` | `probe: "upgrade-desync"` (WebSocket/gRPC/H2C upgrade), авто-активация по WS/gRPC/портам 8080/8443/9000 |
| Global projector | `osint/global_projector.py`, `make project` | Поиск целей по `tech_stack_hash` в локальном кэше/Shodan/Censys query, Gittins ranking, Wald SPRT 3-5 запросов, verifier+notifier |

```bash
# Локальный инкубатор (нулевая стоимость)
make incubate INCUBATE_ARGS="--skip-docker"

# Глобальная проекция Universal Key
make project TECH="nginx+python+h1.1" PROJECT_ARGS="--targets ./targets_verified.json --skip-notify"
```

## Echelon 3 (Two-Tier Pool, N×M Matrix, Layer Differential)

| Модуль | Файл | Назначение |
|---|---|---|
| Stratified pool | `proxy.go`, `pool.go`, `dialer.go` | `SniperTier` только при `http_parsing` admission, IQR `<20ms`, ≥3 latency samples и отсутствии бана за 1h; `InfantryTier` — весь остальной трафик; `AcquireSniper`/`DialSniperContext` не деградируют до Infantry |
| Tail-latency cut | `proxy.go`, `dialer.go` | rolling P90; для Infantry handshake обрывается на `max(1.5*P90, 300ms)`, Sniper не ограничивается этим потолком |
| Matrix scheduler | `daemon/matrix_scheduler.go` | `Targets × Proxies` fan-out, строгий `per_host_min_interval` 3s + гауссов джиттер, окно параллелизма на хост, AIMD: `+1` на чистый ответ, `floor(W/2)` и кулдаун на `429/403/503`/аномалию |
| Layer spectrometer | `research/layer_analyzer.py` | ортогональные маркеры (`Via`, `Server`, `CF-Ray`, `X-Cache`, формат ошибок) → softmax-вектор `CDN → Envoy → Nginx → HAProxy → backend`, Information Gain |
| Metadata DDT | `research/layer_analyzer.py` | `MetadataDDT` сравнивает `X-Request-ID`/`ETag`/`Vary`/`Age`/`CF-Ray` на сдвигах входа, выделяет `Unkeyed Inputs` |
| Normalization synthesizer | `research/layer_analyzer.py` | по `WAFProfile` синтезирует проверки расхождения парсинга: colon/OWS, NUL, chunk extension, alternate whitespace |

## Echelon 4 (State Reconstruction, Game Arbitrage, Minimal Artifacts)

| Модуль | Файл | Назначение |
|---|---|---|
| State graph miner | `research/state_and_chains.py` | парсит raw/JSON последовательности Caido, строит `S_0→…→S_n`, помечает критические переходы (cart/balance/role/session) и формирует `cross-state-race` задачи с `sync: "last-byte"` и предусловиями |
| Chain synthesizer | `research/state_and_chains.py` | объединяет подтверждённые аномалии в граф достижимости; `z3-solver` опционален, при его отсутствии — детерминированный BFS по правилам; `unverified` отбрасываются |
| Weibull/Kelly scorer | `research/game_arbitrage.py` | `S = impact * exp(-(age/scale)^shape) * f_Kelly`; при `sniper_pool < min_sniper_pool` эффективные odds падают пропорционально дефициту резерва |
| ddmin / MDL | `research/game_arbitrage.py` | 1-минимальные bytes/str/header-list пейлоады через детерминированный delta debugging |
| Minimal artifact | `research/game_arbitrage.py`, `osint/notifier.py`, `osint/caido_bridge.py` | детерминированный `omnislash.minimal-artifact/v1` (минимальный запрос, response diff, proxy attribution, replay steps, sha256) без генеративного текста; передаётся в Caido Replay/Telegram только после сжатия |

## Adaptive Probing (O(log2 N), Syndrome Decoding)

| Модуль | Файл | Назначение |
|---|---|---|
| Group testing | `research/adaptive_prober.py` | `GroupTestSplitter` мультиплексирует до 64 ортогональных кандидатов (unkeyed headers, framing) в один batch-оракул, бинарным расщеплением локализует триггер за `1 + ceil(log2 N)` запросов; триггер = `ncd_delta`/`ttfb_residual_ms`/status-header shift |
| Syndrome decoder | `research/adaptive_prober.py` | `SyndromeDecoder` сопоставляет `[status, error_signature, FIN/RST/KEEPALIVE, ttfb_residual_ms, ncd_delta]` с эталонными синдромами Nginx/Envoy/HAProxy/Cloudflare/Akamai/Go/Gunicorn и возвращает `(frontend_parser, backend_parser, recommended_vector)` |
| ID3 planner | `research/adaptive_prober.py` | `AdaptiveProbePlanner` выбирает следующий зонд по Shannon Information Gain `IG(S,A)=H(S)-Σ|S_v|/|S|H(S_v)`, отсекает ветки ниже `prune_threshold`, эмитит не более 4-7 диагностических запросов или один strike при `posterior >= min_posterior` |
| Planner integration | `osint/planner.py` | `--adaptive` создаёт компактный диагностический пакет; `--adaptive-telemetry` читает `omnislashd` JSONL и достреливает подтверждённый синдром; `--adaptive-plan-out` сохраняет trace `omnislash.adaptive-plan/v1` |
| ddmin/Caido handoff | `research/adaptive_prober.py`, `osint/caido_bridge.py`, `osint/notifier.py` | `distill_trigger()` = `GroupTestSplitter` → `ddmin` → `omnislash.minimal-artifact/v1`; `--adaptive-artifacts` прикрепляет минимальный артефакт к Caido Replay/Telegram |
| Radar flow | `lab/run-radar.sh` | `--adaptive` выполняет diagnostic pass, re-plan по телеметрии и один strike pass; все probe-запуски остаются через `omnislashd`/`Dialer/Session` с обычными safety-инвариантами |

## Autonomous response-shape learning (no Docker)

| Модуль | Файл | Назначение |
|---|---|---|
| Semantic analyzer | `research/semantic_analyzer.py` | Классифицирует `QUEUE_SHIFTED_REDIRECT`, `PARSER_REJECT_STRICT`, `APP_ROUTE_MISS`, `WAF_OR_DECEPTION`, `CLEAN_BASELINE`; строит JSON/HTML skeleton без nonce/dynamic values; `TransitionTracker` считает успехом только `poison_sent -> response_queued -> victim_shifted` с подтверждённым сдвигом на victim |
| Self-learning | `research/self_learning.py` | Ингестит JSONL-аудиты `omnislashd`, exploit-логи и Caido feedback (`--feedback-confirmed` / `--feedback-false-positive`), обновляет EMA-веса и `LinUCB`; явные негативы (`CL 1..3`, duplicate CL, bad timing) вычитаются из score |
| Online loop | `research/online_loop.py`, `online.go`, `daemon/online.go` | Хвост JSONL по персистентному offset, семантическая классификация каждой попытки, atomic `state/learned_weights.json`, hot-reload priors/jobs по `mtime`, control file для паузы; непроверенные hypothesis уходят в `candidates`, а strike требует двух независимых egress-идентификаторов |
| Parameter inference | `research/self_learning.py` | `ParameterInferencer` двухэтапно выводит gadget-path и границу `Content-Length`/тайминги; adaptive binary search идёт по градиенту `PARSER_REJECT_STRICT -> QUEUE_SHIFTED_REDIRECT`, без чтения `solution-derived` playbook |
| Holdout | `research/self_learning.py` | Детерминированный split по host/lab ID; точные host/tech-наблюдения перебивают глобальный `host:"*"` приор через `exact_weight`; пересечение train/validation запрещено |
| Native calibration | `lab/calibrate-brain.sh`, `make calibrate`, `research/self_learning.py` | Только Go/Python + **все** JSONL-аудиты `runs/*` + локальные контрастирующие/негативные примеры (CL 1..3, duplicate CL, bad timing, WAF-stub) и симуляции каскадов H2→H1/CL.TE; строгий per-host holdout; результат — gitignored `state/learned_weights.json` с верхним уровнем `examples` |
| Dashboard telemetry | `ui.go`, `web/index.html` | `holdout_accuracy`/`examples` из весов, vault stacks/keys, findings journal с `confidence_score`/NCD, action API; Online Feedback Loop показывает `ACTIVE`/`PAUSED`, processed episodes, online accuracy/Δ и применяет метки ±2.0 через `/api/learning/feedback` без рестарта |
| Planner integration | `osint/planner.py` | `--adaptive --learned-weights state/learned_weights.json` добавляет h2-cl гипотезы с `provenance: "autonomous-inferred"`; `solution-derived` vault-ключ остаётся отдельным replay-приором |

Curated `solution-derived` сиды остаются видимыми в `/experience` как
`seed_*`, но не являются источником для автономного вывода параметров. Во время
калибровки хосты lab instance попадают в holdout и не обучают модель на самом
себе; inference работает на tech-stack/глобальных признаках и локальных
симуляциях.

Расширенный цикл не требует Docker: вход — все аудиты `runs/*`, локальные
пары прокси+бэкенд на `127.0.0.1` (Go `net/http` + Python `http.server`),
контрастирующие примеры (успешный queue shift против parser-reject/clean
baseline) и явные негативы, включая WAF-stub Cloudflare/Akamai/AWS WAF/QRATOR/Nginx
и чистый шум. Разделение детерминировано по
хосту/lab ID и строго: хост из holdout не участвует в обучении. Число примеров
сохраняется в `state/learned_weights.json` как top-level `examples`, поэтому
дашборд показывает реальный объём выборки, а не только число ячеек;
точность — из `holdout.metrics.accuracy`.

## Embedded Web UI (локальный дашборд)

`web/index.html` — ванильный HTML/CSS/JS SPA, встраиваемый через `//go:embed`
(`web/web.go`) и регистрируемый `RegisterUI` (`ui.go`). Страница отдаётся на
`GET /` на `stats.listen` (по умолчанию `127.0.0.1:9090`) и на `control_addr`
демона, если он настроен. Legacy JSON `/stats`, `/healthz`, `/readyz`,
`/status`, `/experience` сохраняются.

| Маршрут | Назначение | Граница |
|---|---|---|
| `GET /api/dashboard` | pool (sniper/infantry/cooldown/avg IQR), brain (holdout accuracy, examples), vault (stacks/keys), scope, findings, status/experience | только локальный control-порт |
| `POST /api/scrape` | нативный scrape + hot-swap пула | `501`, если скрапер не подключён |
| `POST /api/calibrate` | `lab/calibrate-brain.sh`: калибровка Brain из `runs/*` + локальных примеров | без Docker; пишет `state/learned_weights.json` |
| `POST /api/caido/push` | отправка выбранных подтверждённых finding'ов через `osint/caido_bridge.py` | Caido URL только localhost по умолчанию (`OMNISLASH_CAIDO_HOSTS`), PAT через env `CAIDO_PAT` |
| `POST /api/run` | один scoped-запуск (`adaptive`, `h2-cl`, `smuggle-chain`, `raw-replay`) | fail-closed `scope.allow_hosts` + `Scope.CheckTarget`, иначе `403` |

В журнал попадают только подтверждённые (`*_confirmed`) и не-`unverified`
находки с `confidence_score`/NCD; записи с `unverified` отфильтровываются.
Quick Run валидирует хост по allowlist (включая `*.domain`) и резолвит/пинит
цель до запуска pinned-сессии. `make release` собирает `bin/omnislash` и
`bin/omnislashd` со встроенным UI, поднимает сервис на эфемерном loopback-порту
и проверяет `GET /`, `/stats` и `/api/dashboard` перед остановкой.

## Что проверяется тестами

```bash
go test ./... -count=1
go vet ./...
python3 -m unittest discover -s osint -p "test_*.py"
python3 -m unittest discover -s research -p "test_*.py"
bash lab/e2e_smoke_test.sh
git diff --check
```

## Security boundaries

- **Fail-closed scope**: цели вне allowlist/CIDR/ports отклоняются.
- **Rate/circuit**: global 4 rps, stop statuses `[403,429,503]`, breaker cooldown.
- **Audit**: JSONL, без query/userinfo/body.
- **Deception defense**: детект/карантин/блокировка; секреты `unverified` не переиспользуются автоматически.
- **Probe integrity**: smuggling/desync/race идут через `Dialer/Session` без Caido MITM.
- **Control UI**: только локальный порт; Quick Run fail-closed по `scope.allow_hosts` + `Scope.CheckTarget`; Caido — localhost-only по умолчанию, PAT — через окружение дочернего процесса.
- **No evasion**: нет обхода honeypot/deception/canary/sandbox, нет out-of-scope сканирования.