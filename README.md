# omnislash

Транспортный слой для инструментов, которым нужна **байт-точность** и
**недоверенный egress**. `omnislash` даёт пул прокси, строгий admission,
ротацию исходящих IP и сырой TCP/TLS без `net/http`, чтобы приложение
отправляло ровно те байты, которые собрало само. HTTP request smuggling —
референсный потребитель (CL.TE / TE.CL / TE.TE / HTTP/2 desync), но не
единственный: тот же слой нужен fuzzer'ам, desync- и protocol-differential
инструментам, кастомным TLS/HTTP-клиентам и любым проверкам, где парсер
посредника меняет смысл запроса.

## Что внутри

- **Пул прокси из файла или из сети**: SOCKS5/SOCKS5h, HTTP CONNECT, HTTPS
  CONNECT. Поддерживаются логин/пароль, IPv4/IPv6 и доменные имена.
- **Автосбор бесплатных списков** через [Colly](https://github.com/gocolly/colly):
  текст, HTML/JSON с regex-извлечением, кастомные заголовки, несколько
  источников параллельно.
- **Строгая проверка живых/мёртвых** через
  [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client): настоящий
  браузерный/мобильный TLS-фингерпринт, несколько HTTPS-canary, проверка
  стабильного egress IP, отсев прокси с вашим реальным IP и медленных прокси.
- **Hot-swap пула**: после каждого scrape проверенный набор атомарно заменяет
  пул, состояние уже известных прокси (счётчики, кулдаун) сохраняется. Плохой
  scrape не может обнулить рабочий пул.
- **Scope/SSRF-защита** на базе
  [projectdiscovery/networkpolicy](https://github.com/projectdiscovery/networkpolicy):
  allowlist хостов/CIDR/портов, блокировка private/loopback/link-local и
  cloud-metadata, локальный DNS-резолв и пиннинг IP.
- **Ротация на каждое новое TCP-соединение**: `round_robin`, `random`,
  `least_used`, `sticky` (один прокси на target в течение TTL).
- **Сессия эксперимента**: `Dialer.NewSession(ttl)` жёстко пиннит один прокси
  на явный срок. Все запросы эксперимента выходят с одного IP; после TTL или
  ошибки — отказ, а не тихая ротация.
- **Два admission-режима**: `connect` проверяет CONNECT, сертификат цели,
  паузу и повторный запрос в одном туннеле; `http_parsing` требует точного
  N-байт echo для HTTP-framing (включая конфликтующие `Content-Length`/
  `Transfer-Encoding`). Негативные фикстуры — буфер, переписчик и обрыватель.
- **Trust tiers**: `strict` для публичных прокси (полный admission) и
  `trusted` для своего mobile/LTE-пула (health + egress, без тяжёлых проб).
- **Fail-closed**: `allow_direct` выключен по умолчанию и запрещён в strict;
  смерть прокси посреди запроса возвращает ошибку, а не прямой ответ.
- **Health-check**: параллельные пробы через прокси, восстановление после
  падения, exponential backoff и автоматический вывод мёртвых прокси из ротации.
- **Ретраи**: dial-ошибки и «банные» HTTP-статусы (403/407/429/503) переводят
  прокси в кулдаун и повторяют запрос через другой IP.
- **TLS через прокси**: `DialTLSContext` отдаёт `net.Conn`, сканер сам решает,
  какие байты и с каким ALPN/SNI отправлять.
- **Локальный CONNECT-шлюз**: `127.0.0.1:3128`, через который любой инструмент
  (curl, свой сканер, сторонний бинарь) ходит с ротацией IP. CONNECT
  байт-прозрачен, поэтому подходит для smuggling-пейлоадов.
- **Stats endpoint**: JSON-снимок состояния пула, здоровья и scrape-цикла.
- **Ограничение скорости на прокси** (token bucket), чтобы не сжигать IP.

Собственным остаётся только то, что нельзя взять готовым: байт-точный raw
TCP/TLS транспорт и связка «источник → валидатор → пул → dialer». Инварианты
и привязка к негативным тестам — в [ARCHITECTURE.md](ARCHITECTURE.md).

```
   proxy lists ──> Colly ──> candidates ──> tls-client validator ──┐
   (text/regex)                         (HTTPS canaries, egress IP) │
                                                                    v
                 +-----------------------------+          verified set
  scanner  --->  |  Dialer / RotatingTransport | <── hot-swap ── Pool
  (raw/TLS)      |  pool + strategy + health   | ---> proxy #1 ──> target
                 |  scope + cooldown + limiter | ---> proxy #2 ──> target
                 +-----------------------------+ ---> proxy #N ──> target
                          |
                 local CONNECT gateway 127.0.0.1:3128
```

## Интеграционная матрица

| Поверхность | Из коробки | Атрибуция IP | Ограничение |
|---|---|---|---|
| Go-сканер через `Dialer` / `Session` | да | `ProxyOf(conn)`, сессия = один exit-IP | нужен raw TCP/TLS клиент |
| Локальный CONNECT-шлюз (`serve`) | да | по соединению, не по HTTP-запросу | любой инструмент с `HTTPS_PROXY`; HTTP absolute-form не поддерживается |
| `RotatingTransport` | да | на каждый HTTP-запрос/keep-alive | только для обычного HTTP, не для smuggling |
| Python / Burp / сторонние плагины | TODO | — | используйте CONNECT-шлюз как временный адаптер |
| HTTP-парсеры (не raw) | осознанно нет | — | `http_parsing` admission проверяет байт-прозрачность, но сам слой не парсит payload |

Честная граница: «из коробки» — Go и CONNECT-шлюз. Адаптеры для Python/Burp
пока не входят в поставку; для них есть только шлюз без per-request
атрибуции.

## Запуск одной командой (Docker)

```bash
make up          # docker compose up -d --build: scrape -> validate -> serve
make ps          # статус и health
make logs        # логи scrape/health/gateway
make down        # остановить
```

`make up` собирает образ `omnislash:1.0.0` и поднимает готовый пайплайн:

- `127.0.0.1:3128` — CONNECT-шлюз с ротацией (только loopback);
- `127.0.0.1:9090/stats` — состояние пула, health и scrape;
- `127.0.0.1:9090/readyz` — healthcheck контейнера;
- внутри контейнера уже включён `scraper` из `config.example.json`, поэтому
  пул собирается и проверяется автоматически при старте и по расписанию.

Проверка:

```bash
docker compose exec omnislash /usr/local/bin/omnislash healthcheck
for i in 1 2 3; do curl -s -x http://127.0.0.1:3128 https://api.ipify.org; echo; done
```

Шлюз без compose (после `make docker`):

```bash
docker run --rm -p 127.0.0.1:3128:3128 -p 127.0.0.1:9090:9090 omnislash:1.0.0
```

Внутри контейнера `scope` включён: в `config.example.json` разрешены
`api.ipify.org` и `*.example.com`. Добавьте свои цели в `scope.allow_hosts`,
иначе шлюз вернёт `502` на всё остальное — это fail-closed, а не баг.

Для своего конфига раскомментируйте `volumes` в `docker-compose.yml` и
положите `config.local.json` рядом с compose-файлом. Внутри контейнера
слушатели переопределяются на `0.0.0.0`, но наружу порты опубликованы только
на `127.0.0.1`.

## Быстрый старт без Docker

```bash
cp config.example.json config.json
make build

# собрать, строго проверить и записать живые прокси
./bin/omnislash scrape -config config.json -write proxies.txt

# либо просто запустить сервис: он сам обновит пул
./bin/omnislash serve -config config.json
```

Только шлюз, без сборки бинаря:

```bash
go run ./cmd/omnislash serve -config config.json -listen 127.0.0.1:3128 -stats 127.0.0.1:9090
```

`config.example.json` уже содержит несколько бесплатных HTTP-списков и
включает `scraper`. Scope включён: перед сканированием добавьте свои цели в
`scope.allow_hosts` (по умолчанию разрешены только `*.example.com` и
`api.ipify.org`). Если списки недоступны, `serve` продолжит работать со
старым пулом (или с пустым, пока не появится первый валидный прокси).

`serve` поднимает:

- `127.0.0.1:3128` — локальный CONNECT-прокси с ротацией;
- `127.0.0.1:9090/stats` — состояние пула, health и scrape;
- фоновый health-check (если включён);
- фоновый scrape/validation по `scraper.refresh_interval`.

Проверка ротации (curl для HTTPS использует CONNECT):

```bash
for i in 1 2 3 4 5; do
  curl -s -x http://127.0.0.1:3128 https://api.ipify.org; echo
done
```

Каждый запрос может выйти с другого IP. Для HTTP-целей curl использует
absolute-form GET, а шлюз принимает только CONNECT; для HTTP-сканирования
открывайте CONNECT на порт 80 вручную (пример ниже).

`fetch` — встроенная проверка без шлюза:

```bash
./bin/omnislash fetch -config config.json -proxies proxies.txt \
  -url https://api.ipify.org -n 10 -concurrency 5
```

## CLI

```
omnislash check  [флаги]   проверить все прокси и показать таблицу/JSON
omnislash scrape [флаги]   собрать, строго проверить и показать живые прокси
omnislash fetch  [флаги]   N HTTP-запросов через ротатор (демо)
omnislash serve  [флаги]   CONNECT-шлюз + stats + health/scrape loops
omnislash healthcheck      проверить /readyz (для Docker healthcheck)
```

Общие флаги: `-config`, `-proxies`, `-log-level`.
Дополнительно: `check` — `-json`, `-timeout`, `-concurrency`;
`scrape` — `-source URL` (можно повторять), `-scheme`, `-json`, `-write FILE`,
`-no-validate`, `-max N`;
`fetch` — `-url`, `-n`, `-concurrency`, `-insecure`, `-show-body`;
`serve` — `-listen`, `-stats`, `-token`, `-no-health`
(`-listen off` / `-stats off` отключают компонент).

## Формат списка прокси

Одна строка — один прокси, `#` в начале строки — комментарий. Дубликаты
удаляются. Если схема не указана, берётся `default_scheme` из конфига.

```text
127.0.0.1:1080
socks5://user:password@proxy.example.com:1080
http://user:password@proxy.example.com:8080
https://proxy.example.com:8443
```

Для smuggling-сканирования используйте **только SOCKS5 или CONNECT**:
обычный forward-proxy режим может переписывать запрос. Этот проект для
HTTP/HTTPS-прокси всегда делает `CONNECT` и дальше не трогает байты.

## Конфигурация

Все поля необязательны: отсутствующие берутся из `DefaultConfig()`.
Пример со всеми полями — `config.example.json`. Ключевые параметры:

| Поле | Смысл |
|---|---|
| `default_scheme` | схема для строк без схемы (`socks5` по умолчанию) |
| `strategy` | `round_robin`, `random`, `least_used`, `sticky` |
| `trust_tier` | `strict` (полный admission; по умолчанию) или `trusted` (свой пул: health + egress) |
| `sticky_ttl` | сколько держать один прокси за target в `sticky` |
| `allow_direct` | **опасно**: ходить напрямую, если прокси кончились. По умолчанию `false`; в `strict` запрещён |
| `dial_timeout`, `handshake_timeout` | таймауты TCP и прокси-handshake |
| `max_dial_attempts` | сколько разных прокси пробовать на один dial |
| `cooldown.*` | exponential backoff после ошибок |
| `health.*` | интервал/таймаут/параллелизм проб, `probe_url`, стартовая проверка |
| `http.*` | таймауты, ретраи, `ban_statuses`, кулдаун бана, keep-alive |
| `stats.listen` | адрес JSON-статистики, пусто — выключено |
| `gateway.listen` | адрес локального CONNECT-шлюза, пусто — выключено |
| `gateway.token` | если задан, клиент обязан прислать `Proxy-Authorization: Bearer ...` |
| `rate_limit.per_proxy_rps` | лимит новых соединений на прокси в секунду (0 — выключено) |
| `scope.*` | fail-closed allowlist целей: хосты/CIDR/порты, блокировка private/metadata, DNS-пиннинг |
| `scraper.*` | источники, интервал обновления, лимиты, строгая валидация |
| `scraper.validation.mode` | `connect` (CONNECT + сертификат + пауза) или `http_parsing` (N-байт HTTP echo) |
| `scraper.validation.admission.*` | canary/echo-адреса, hold, размер echo, timeout, запрет skip-verify в strict connect |
| `log_level` | `debug`, `info`, `warn`, `error` |

`ban_statuses` по умолчанию `[403, 407, 429, 503]`. Учтите: `403` может быть
ответом WAF на конкретный путь, а не баном IP. Для «тихого» сканирования
оставьте `[407, 429]` и разбирайте 403 самостоятельно.

## Автосбор и строгая валидация

Цикл одного обновления:

1. **Colly** параллельно скачивает все `scraper.sources` (таймаут, лимит тела,
   User-Agent, кастомные заголовки).
2. Для `type: "text"` прокси извлекаются из строк и HTML-мусора; для
   `type: "regex"` берётся первая группа регулярки. Записи без схемы получают
   `sources[].scheme` (для бесплатных списков почти всегда `http`).
3. Кандидаты дедуплицируются, перемешиваются и ограничиваются
   `max_candidates`.
4. **tls-client** проверяет каждый прокси с выбранным фингерпринтом:
   - минимум `validation.min_canaries` HTTPS-canary должны ответить;
   - все успешные canary должны вернуть один и тот же `egress_ip`
     (`require_same_egress_ip`);
   - `egress_ip` не должен быть private/loopback/metadata
     (`allow_private_egress: false`);
   - `egress_ip` не должен совпадать с вашим реальным IP
     (`require_distinct_from_real_ip`);
   - ответ должен уложиться в `max_latency`.
5. Для `trust_tier: strict` выполняется admission-набор по
   `validation.mode`:
   - `connect`: сырой CONNECT к `admission.tls_canary_url`, проверка цепочки
     сертификата, пауза `hold` и **второй** запрос в том же туннеле;
   - `http_parsing`: echo-проба с HTTP-запросом, где одновременно есть
     `Content-Length` и `Transfer-Encoding`; ответ обязан совпасть байт-в-байт
     (буфер, переписчик заголовков и обрыватель отсеиваются);
   - при заданном `admission.echo_addr` дополнительно проверяется
     N байт туда / N байт обратно. Это должен быть доверенный raw TCP echo
     endpoint, доступный через проверяемый прокси; без него проверка
     пропускается, а `http_parsing`-режим требует его обязательно.
   `trust_tier: trusted` пропускает admission и оставляет health + egress —
   это режим для собственного mobile/LTE-пула.
6. Если живых меньше `min_pool_size`, обновление **отбрасывается** и старый пул
   остаётся нетронутым. Иначе `Pool.Replace` атомарно подменяет набор,
   сохраняя счётчики и кулдауны уже известных прокси.

Проверить один раз вручную:

```bash
./bin/omnislash scrape -config config.json -write proxies.txt
./bin/omnislash scrape -config config.json -source https://example.org/list.txt -scheme http -json
```

`scraper.validation.profile` — имя профиля tls-client. Мобильные варианты:
`safari_ios_26_0`, `safari_ios_18_5`, `okhttp4_android_13`,
`zalando_android_mobile`. Они меняют TLS ClientHello/HTTP2-настройки, а не
только User-Agent. `validation.user_agent` подбирайте под профиль: по
умолчанию используется мобильный Safari UA, для `chrome_*` задайте
соответствующий desktop UA, иначе отпечаток выглядит несогласованно.

`validation.attempts` задаёт число полных повторов проверки одного прокси.
Транзиентная ошибка получения вашего реального IP не кэшируется: следующий
цикл scrape попробует снова.

## Мобильный трафик без статичного IP

Статичный IP для мобильной симуляции не нужен и обычно вреден: реальные
мобильные операторы постоянно меняют адрес. Нужен не «один красивый IP», а
**пул адресов из мобильного ASN**, которые меняются достаточно часто.

Рабочие схемы:

- **Платный mobile/4G backconnect**: провайдер даёт один `host:port`, а IP
  меняется на каждое новое TCP-соединение или по `session-id` в логине.
  Добавьте этот endpoint в пул как обычный SOCKS5/HTTP-прокси. Наша ротация
  на каждое соединение сразу даёт смену IP, а `sticky` с коротким TTL — ту же
  сессию для связанных запросов.
- **Свои LTE-модемы / Android-ферма**: каждый модем — отдельный SOCKS5/HTTP
  выход. Переключение IP — переподключение PDP-контекста или авиарежим. Это
  самый честный вариант, но требует железа и SIM-карт.
- **Бесплатные списки** мобильный ASN практически не дают. В них в основном
  серверные/домашние прокси, часто уже мёртвые или с MITM. Для мобильной
  симуляции они не подходят.

Что проверять, кроме IP:

- **ASN/оператора**, а не только геолокацию. IP может быть «в стране», но
  принадлежать хостингу. Для проверки используйте ASN-API провайдера или
  собственный справочник; в конфиг можно добавить canary, который возвращает
  ASN, и расширить валидатор.
- **Согласованность отпечатка**: мобильный TLS-профиль
  (`safari_ios_26_0` / `okhttp4_android_13`) + мобильный User-Agent + язык/
  заголовки. Один только прокси не делает трафик мобильным.
- **CGNAT**: у мобильных операторов много абонентов делят IP. Некоторые сайты
  это учитывают; помогает смена сессии и ограничение частоты.

Практический конфиг: один источник — backconnect-прокси провайдера,
`strategy: "random"` или `"round_robin"`, `sticky_ttl: "2m"`,
`validation.profile: "safari_ios_26_0"`, `require_same_egress_ip: true`,
`max_latency` под ваш провайдер (мобильные часто медленнее 5 секунд).

## Безопасность недоверенных прокси

Бесплатный прокси — это чужой сервер, который видит ваш трафик и может его
менять. Модуль снижает риск, но не делает прокси доверенным:

- `scope.enabled: true` + `allow_hosts`/`allow_ports` не даёт сканеру уйти на
  внутренние адреса, cloud metadata и произвольные порты.
- При включённом scope имена целей всегда резолвятся локально и проверяются
  все полученные адреса; с `resolve_locally: true` проверенный IP ещё и
  пиннится в CONNECT, поэтому прокси не может подменить DNS. Без scope
  hostname уходит прокси и резолвится на его стороне.
- Источники `scraper.sources` — доверенная конфигурация оператора. Не
  подставляйте туда произвольные URL из недоверенных данных: Colly ходит на
  них напрямую, в обход scope.
- `allow_direct` по умолчанию `false`: при пустом пуле запрос не уйдёт с
  вашего реального IP. В `trust_tier: strict` он запрещён конфигурацией;
  включать его можно только для `trusted`-пула и осознанно.
- В strict-режиме admission проверяет сертификат цели в CONNECT и
  байт-прозрачность framing; `admission.tls_skip_verify` нельзя включить в
  strict connect.
- Смерть прокси посреди запроса возвращает ошибку. Ни `Dialer`, ни `Session`
  не делают скрытый direct fallback.
- Egress-валидация требует HTTPS-сертификат (если не отключён для trusted-пула),
  стабильный и отличающийся от вашего реального IP. Это отсеивает часть
  прозрачных MITM, но не гарантирует честность прокси.
- Не отправляйте через бесплатные прокси токены, cookies, пароли и приватные
  данные. Для smuggling-проб используйте только авторизованные стенды.

Health-check и валидатор намеренно ходят на фиксированные canary URL в обход
scope: это не пользовательские цели. Scope применяется к `DialContext`,
`DialProxy`, прямому dial и локальному шлюзу.

## Интеграция в Go-сканер

### Вариант 1: raw-соединение напрямую через пул

```go
cfg, _ := omnislash.LoadConfig("config.json")
proxies, _ := omnislash.LoadProxyFile("proxies.txt", cfg.DefaultScheme)
pool, _ := omnislash.NewPool(cfg, proxies, nil)
dialer := omnislash.NewDialer(pool, nil)

conn, err := dialer.DialTLSContext(ctx, "tcp", "target.example:443", &tls.Config{
    ServerName:         "target.example",
    InsecureSkipVerify: true,              // только для авторизованных тестов
    NextProtos:         []string{"http/1.1"},
})
if err != nil {
    return err
}
defer conn.Close()

// ВАЖНО: пишем сырые байты, не используем net/http.
_, err = conn.Write(payload) // "POST / HTTP/1.1\r\nHost: ...\r\n..." с нужной framing
```

Каждый `DialContext`/`DialTLSContext` выбирает следующий прокси. Если прокси
умер на handshake, dialer автоматически попробует другой (до
`max_dial_attempts`), а мёртвый отправит в кулдаун.

Если сканер сам распознал бан по ответу (например, 403/429 на smuggling-пробу),
он может вывести конкретный прокси из ротации:

```go
conn, _ := dialer.DialContext(ctx, "tcp", "target.example:443")
tlsConn := tls.Client(conn, &tls.Config{ServerName: "target.example", NextProtos: []string{"http/1.1"}})
_ = tlsConn
// ... сканер пишет свои сырые байты и читает ответ ...

if pr, ok := omnislash.ProxyOf(conn); ok {
    pool.Ban(pr, "target returned 403", 5*time.Minute)
}
```

Для эксперимента, которому нужен один стабильный IP на всю серию запросов,
используйте не `sticky` (он keyed by target и может истечь), а явную сессию:

```go
session, err := dialer.NewSession(10 * time.Minute) // один прокси на весь эксперимент
if err != nil { return err }
defer session.Close()

for _, probe := range probes {
    conn, err := session.DialContext(ctx, "tcp", "target.example:443")
    if err != nil { return err } // отказ, без тихой ротации и direct fallback
    // ... raw TLS/probe ...
    _ = conn.Close()
}
```

`Session.DialContext` никогда не перебирает другие прокси и не уходит
напрямую: ошибка прокси — это ошибка эксперимента. Два независимых
`NewSession` получают разные прокси по стратегии пула.

Полный пример: `examples/rawdial/main.go`. Минимальный шаблон подключения
своего сканера: `examples/dialer/main.go`.

### Вариант 2: локальный CONNECT-шлюз для любого инструмента

```go
gw, _ := omnislash.NewGateway("127.0.0.1:3128", dialer, "", nil)
go gw.Serve(ctx)
```

Сканер открывает TCP к шлюзу, отправляет CONNECT и дальше работает с
полученным потоком как с обычным сокетом:

```text
CONNECT target.example:443 HTTP/1.1
Host: target.example:443

```

После ответа `200 Connection Established` можно делать TLS-handshake и
отправлять любые байты. Шлюз не парсит и не переписывает их.

Это удобно, если сканер уже умеет работать через `HTTP_PROXY`/`HTTPS_PROXY`
или написан на другом языке.

### Обычный HTTP-транспорт (разведка, не smuggling)

```go
transport := omnislash.NewRotatingTransport(pool, dialer, cfg.HTTP, nil)
client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
```

Транспорт ротирует IP на каждый запрос, держит keep-alive соединения
per-proxy, повторяет запрос при сетевых ошибках и «банных» статусах. Тело
запроса буферизуется до `http.max_body_buffer`, чтобы его можно было безопасно
повторить.

## Ротация, здоровье и кулдауны

- Health-check открывает туннель и делает `GET probe_url`. Успех — прокси
  живой, ошибка/таймаут — кулдаун `initial * multiplier^(n-1)` с потолком `max`.
- Успешный dial или health-check сбрасывает серию ошибок и возвращает прокси в
  ротацию.
- `ban_statuses` дополнительно отправляет прокси в `ban_cooldown`.
- Кулдаун не блокирует health-check: прокси может восстановиться раньше.
- `stats`: `available`, `in_cooldown`, `successes`, `failures`, `bans`,
  `inflight`, `latency_ms`, `egress_ip`, `validation_latency_ms`,
  `last_error`, `cooldown_until`, плюс блок `scraper` с итогами последнего
  обновления.

## Ограничения и безопасность

- **Не включайте `allow_direct`,** если не хотите, чтобы при исчерпании пула
  запросы ушли с реального IP. По умолчанию это выключено, а в strict-режиме
  запрещено на уровне конфига.
- HTTP/1.1 keep-alive означает, что несколько запросов могут переиспользовать
  одно TCP-соединение и один IP. Для smuggling-тестов обычно нужно новое
  соединение на пробу — это и даёт ротацию.
- TLS-параметры цели (SNI, ALPN, проверка сертификата) полностью на стороне
  сканера; для проверки desync часто нужен `NextProtos: ["http/1.1"]`.
- SOCKS5 резолвит домен на стороне прокси; CONNECT передаёт прокси имя хоста.
  Так меньше DNS-утечек, но проверка адреса ложится на прокси. Для
  безопасности включайте `scope` (см. выше): тогда адрес проверяется локально
  до открытия туннеля, а `resolve_locally` пинует IP.
- Health-check ходит на `probe_url` через каждый прокси. Убедитесь, что это
  разрешено правилами провайдера/тестового стенда.
- Прокси-провайдеры и целевые системы могут логировать трафик. Используйте
  только свои прокси/стенды и только с письменного разрешения на тестирование.
- `403` в `ban_statuses` может приводить к ложным срабатываниям и сжиганию
  пула. Настройте список под свою задачу.
- Для HTTP-целей (не HTTPS) CONNECT на порт 80 работает, но некоторые
  прокси-провайдеры разрешают только 443. Проверяйте `check`/`fetch`.
- Модуль не реализует HTTP/2 framing, priority-трюки и т.п. — это задача
  сканера. Здесь только транспорт с ротацией IP.

## Тесты

```bash
make test
make race
make vet
make lint
```

Тесты поднимают локальные fake SOCKS5/CONNECT/TLS-серверы и проверяют
handshake, ротацию, auth, health-check, баны, gateway, replay тела запроса,
scope/SSRF-правила, scrape с hot-swap и валидацию через tls-client. Отдельно
есть негативные admission-фикстуры: прокси-буфер, переписчик framing,
обрыватель и MITM с подменённым сертификатом; тесты сессий проверяют, что один
эксперимент не меняет exit-IP и не делает direct fallback при смерти прокси.

## Лицензия

MIT. Полный текст — в [LICENSE](LICENSE).

Модуль использует `gocolly/colly/v2`, `projectdiscovery/networkpolicy`,
`bogdanfinn/tls-client` и его `fhttp`. Их лицензии действуют и на бинарник;
проверьте их перед распространением.
