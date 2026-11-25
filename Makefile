VERSION ?= 1.0.0
BINARY  := bin/omnislash
PKG     := ./cmd/omnislash
DAEMON  := bin/omnislashd
DAEMON_PKG := ./cmd/omnislashd
DAEMON_CONFIG ?= examples/daemon/daemon.json
IMAGE   ?= omnislash:$(VERSION)
CONFIG  ?= config.json
COMPOSE ?= docker compose

.PHONY: all build run gateway daemon daemon-build daemon-once release pipeline e2e radar incubate calibrate project test race vet fmt check lint docker up down logs ps scrape clean

all: build

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) $(PKG)

run: build
	$(BINARY) serve -config $(CONFIG)

gateway:
	go run ./cmd/gateway -config $(CONFIG)

daemon-build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(DAEMON) $(DAEMON_PKG)

daemon: daemon-build
	$(DAEMON) -config $(DAEMON_CONFIG)

daemon-once:
	go run $(DAEMON_PKG) -config $(DAEMON_CONFIG) -once

# Single autonomous release: one Go binary with the embedded Web UI, smoke-checked.
release: build daemon-build
	@test -f web/index.html
	@PORT=$$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'); \
	CFG=$$(mktemp); \
	trap 'kill $$PID 2>/dev/null || true; rm -f $$CFG' EXIT; \
	printf '{"trust_tier":"trusted","allow_direct":true,"health":{"enabled":false},"scraper":{"enabled":false},"gateway":{"listen":""},"stats":{"listen":"127.0.0.1:%s"},"audit":{"enabled":false}}' "$$PORT" > $$CFG; \
	./bin/omnislash serve -config $$CFG >/dev/null 2>&1 & PID=$$!; \
	for i in $$(seq 1 50); do \
	  if curl -fsS --noproxy '*' http://127.0.0.1:$$PORT/ 2>/dev/null | grep -q 'OmniSlash Control'; then break; fi; \
	  sleep 0.1; \
	done; \
	curl -fsS --noproxy '*' http://127.0.0.1:$$PORT/ | grep -q 'OmniSlash Control'; \
	curl -fsS --noproxy '*' http://127.0.0.1:$$PORT/stats >/dev/null; \
	curl -fsS --noproxy '*' http://127.0.0.1:$$PORT/api/dashboard >/dev/null; \
	kill $$PID; wait $$PID 2>/dev/null || true
	@./bin/omnislashd -h >/dev/null
	@echo "RELEASE_OK: bin/omnislash + bin/omnislashd include the embedded dashboard"

test:
	go test ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run

check: fmt vet test

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# One-command production pipeline: scrape -> validate -> hot-swap -> serve.
up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

scrape: build
	$(BINARY) scrape -config $(CONFIG) -write proxies.txt

# Full pipeline: OSINT -> planner -> gateway/daemon -> caido bridge -> summary
# Usage: make pipeline TARGET=example.com [PIPELINE_ARGS="--skip-caido --skip-nuclei"]
PIPELINE_ARGS ?=
pipeline:
	bash lab/run-pipeline.sh --target "$(TARGET)" $(PIPELINE_ARGS)

# Autonomous local E2E smoke test (no real internet)
e2e:
	bash lab/e2e_smoke_test.sh

# Echelon 1 radar: diff scan -> only-diff plan -> verify -> notify
# Usage: make radar TARGET=example.com [RADAR_ARGS="--skip-daemon --skip-notify"]
RADAR_ARGS ?=
radar:
	bash lab/run-radar.sh --target "$(TARGET)" $(RADAR_ARGS)

# Echelon 2 incubator: local zero-cost differential fuzzing against docker stacks
INCUBATE_ARGS ?=
incubate:
	bash lab/run-incubator.sh $(INCUBATE_ARGS)

# Native autonomous-brain calibration (no Docker): audits + local simulations -> state/learned_weights.json
calibrate:
	bash lab/calibrate-brain.sh

# Echelon 2 global projector: fan-out universal key to matching targets
# Usage: make project TECH="nginx+python+h1.1" [PROJECT_ARGS="--targets targets_verified.json --skip-notify"]
PROJECT_ARGS ?=
project:
	python3 osint/global_projector.py --tech "$(TECH)" $(PROJECT_ARGS)

clean:
	rm -rf bin
