package main

import (
	"flag"
	"fmt"
	"strings"
)

const faqText = `omnislash FAQ
=============

Q: Что такое OmniSlash?
A: Локальный HTTP-шлюз и ротатор прокси для безопасных L7-проб (сканирование
   только собственного лабораторного стенда: Juice Shop / DVWA).

Q: Какой лимит запросов?
A: Global rate limit: 4 req/s (global_rps=4, global_burst=1). Лимит считается
   контекстным маркером и применяется через safety-механизм.

Q: Что происходит при 403 / 429 / 503?
A: Эти статусы входят в safety.stop_statuses. При превышении порога (threshold=5
   за window=60s) срабатывает fail-closed circuit breaker: запросы блокируются,
   включается cooldown (10m, multiplier 2). Все события пишутся в JSONL audit.

Q: Как работает scope?
A: Scope allowlist (hosts / CIDRs / ports) с fail-closed поведением; приватные
   сети запрещены (allow_private=false).

Q: Как запустить lab-проверку?
A: bash lab/verify.sh — проверяет scope, rate limit, nuclei (-rate-limit 4),
   circuit breaker и audit log. Только локальные цели (127.0.0.1 лаборатория).

Q: Что за 4 obfuscation layers?
A: L1 — LocalGatewayLayer (safety core через шлюз).
   L2 — TLS fingerprint runtime (utls UClient + ClientHelloID).
   L3 — HTTP/2 / L7 header consistency runtime.
   L4 — behavioral timing / jitter / warm-up / adaptive runtime.
   Все слои работают только с safety-gates (scope, ≤4 rps, circuit, audit).
   Обход ханипотов/десепшенов/canary не реализуется.

Q: Как проверить работоспособность?
A: go build ./... && go vet ./... && go test ./...
   python3 -m unittest discover -s osint -p "test_*.py"
   bash lab/verify.sh

Q: Какие источники прокси использует scraper?
A: speedx-http, monosans-http, clarketm-http (config.scrape.sources),
   со строгой валидацией (TLS canary, echo, real-ip check).

Q: Где логи / аудит?
A: audit path из config.audit.path (JSONL), stats — :9090, gateway — :3128.
`

func cmdFaq(args []string) error {
	fs := flag.NewFlagSet("faq", flag.ContinueOnError)
	topic := fs.String("topic", "", "фильтр FAQ по ключу вопроса (подстрока)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *topic == "" {
		fmt.Print(faqText)
		return nil
	}
	for _, q := range strings.Split(faqText, "\n") {
		if strings.Contains(q, *topic) {
			fmt.Println(q)
			break
		}
	}
	return nil
}
