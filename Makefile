VERSION ?= 1.0.0
BINARY  := bin/omnislash
PKG     := ./cmd/omnislash
DAEMON  := bin/omnislashd
DAEMON_PKG := ./cmd/omnislashd
DAEMON_CONFIG ?= examples/daemon/daemon.json
IMAGE   ?= omnislash:$(VERSION)
CONFIG  ?= config.json
COMPOSE ?= docker compose

.PHONY: all build run gateway daemon daemon-build daemon-once pipeline e2e radar incubate project test race vet fmt check lint docker up down logs ps scrape clean

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

# Echelon 2 global projector: fan-out universal key to matching targets
# Usage: make project TECH="nginx+python+h1.1" [PROJECT_ARGS="--targets targets_verified.json --skip-notify"]
PROJECT_ARGS ?=
project:
	python3 osint/global_projector.py --tech "$(TECH)" $(PROJECT_ARGS)

clean:
	rm -rf bin
