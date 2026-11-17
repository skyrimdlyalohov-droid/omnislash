VERSION ?= 1.0.0
BINARY  := bin/omnislash
PKG     := ./cmd/omnislash
IMAGE   ?= omnislash:$(VERSION)
CONFIG  ?= config.json
COMPOSE ?= docker compose

.PHONY: all build run test race vet fmt check docker up down logs ps scrape clean

all: build

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) $(PKG)

run: build
	$(BINARY) serve -config $(CONFIG)

test:
	go test ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

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

clean:
	rm -rf bin
