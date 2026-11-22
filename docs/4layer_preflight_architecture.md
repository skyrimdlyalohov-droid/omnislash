# Omnislash — Pre-Flight OSINT & 4-Layer Obfuscation Architecture

## System Architecture & Data Flow (ASCII)

```
+--------------------------------------------------------------------------------------------------+
|                              OMNISLASH — PRE-FLIGHT OSINT & ANTI-DECEPTION                     |
|                                       4-LAYER OBFUSCATION ARCHITECTURE                        |
+--------------------------------------------------------------------------------------------------+

        ┌──────────────┐
        │  TARGET      │
        │  SCOPE       │
        │  (allowlist,│
        │   ASN, TLD) │
        └──────┬───────┘
               │ passive observation only
               ▼
        ┌─────────────────┐      ┌──────────────────┐      ┌──────────────────┐
        │ STAGE 1         │ ────► │ STAGE 2          │ ────► │ STAGE 3         │
        │ Passive         │      │ Anti-Canary/     │      │ API Enrichment │
        │ Discovery       │      │ Noise Sanitize  │      │ + Cross-Verify │
        │ crt.sh,         │      │ OAST/Canary strip│     │ Censys/Shodan/ │
        │ CertSpotter,   │      │ CT-wildcard regex│     │ FOFA/ZoomEye/   │
        │ OTX, Wayback,  │      │                  │      │ Netlas/CIP/GN  │
        │ URLScan.io     │      └────────┬─────────┘      └────────┬─────────┘
        └─────────────────┘                │                       │
                                           │ consensus /           │
                                           │ dedup                 │
        ┌─────────────────┐      ┌──────────────▼─────────────┐     │
        │ STAGE 4         │ ◄──────┤ STAGE 3 results enriched │     │
        │ Confidence      │      └──────────────────────────┘     │
        │ Scoring: +2/    │                                         │
        │ -5/-3, behind_  │                                         │
        │ waf             │                                         │
        └─────────────────┘                                         │
                                                                   │
                                                                   ▼
        ┌──────────────────────────────────────────────────────────────────────────────┐
        │ HANDSHAKE → targets_verified.json                                             │
        │ {                                                            "target":     │
        │   "ip": ...,                                                 "confidence_ │
        │   "score": int,                                              "behind_     │
        │   "waf": bool,                                                "recommended_ │
        │   "profile": "l7_web"|"full",                                  "known_      │
        │   "ports": [80,443] }                                         │  ports":[]}   │
        └──────────────────────────────┬───────────────────────────────────────────┘
                                       │ decoupled handoff — OSINT → gateway, NO shared
                                       │ state, no probing overlap, no API key overlap
                                       ▼
        ┌─────────────────┐      ┌─────────────────────────────────────────────────────┐
        │ OMNISLASH       │◄─────►│ GATEWAY (local)                                     │
        │ GATEWAY         │      │ proxy pool · global rate limit · fail-closed     │
        │ (scanner-side  │      │ circuit breaker · JSONL audit · scope allowlist   │
        │  orchestrator) │      └─────────────────────────────────────────────────────┘
                                       │
                                       ▼
        ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
        │ ACTIVE PROBING  │ ────► │ NUCLEI          │ ────► │ CAIDO           │
        │ (via gateway)  │      │ (through gw)    │      │ (manual only)  │
        └─────────────────┘      └─────────────────┘      └─────────────────┘
```

## Zero-Trust OSINT Flow

```
[1] TARGET SCOPE ──► [STAGE 1: Passive Discovery] ──► [STAGE 2: Anti-Canary/Noise Sanitize]
                                                              │
                                                              ▼
                                                     [STAGE 3: API Enrichment + Cross-Verification]
                                                              │
                                                              ▼
                                                     [STAGE 4: Confidence Scoring]
                                                              │
                                                              ▼
                                              targets_verified.json ──► OMNISLASH GATEWAY
```

## Module 4 — Layer Design Specifications (design implemented, runtime evasion deferred)

- **L2 — TLS Handshake Mimicry (JA3/JA4):** `refraction-networking/utls` in Go to spoof
  exact ClientHello signatures of modern browsers (Chrome/Firefox/Safari) with matching ALPN
  (`h2`, `http/1.1`) and cipher suites; zero use of default Go `crypto/tls` fingerprints.
  **Delivered:** `obfuscation/tls.go` — `TLSFingerprintLayer` + `NewTLSFingerprintTransport`
  (ClientHelloID `<Client>_<Version>`, e.g. `Chrome_131`; via `tls.UTLSIdToSpec`).
- **L3 — Application Protocol & HTTP/2 Consistency (L7):** strict header ordering
  (`Sec-Ch-Ua`, `Sec-Fetch-*`, `User-Agent`, `Accept-Encoding`) and HTTP/2 frame parameters
  (`SETTINGS`, `WINDOW_UPDATE`, pseudo-header order) matching the TLS profile from L2;
  prevent profile mismatches (e.g., Chrome TLS + Firefox User-Agent).
  **Delivered:** `obfuscation/http2_consistency.go` — `HTTP2ConsistencyLayer` with canonical
  header ordering + pruning.
- **L4 — Behavioral Timing & Flow Control:** log-normal/Gaussian jitter generator with
  occasional long idle pauses; warm-up request flows (root path / favicon / cookies before
  probing specific endpoints); adaptive backoff triggers (auto IP quarantine on HTTP 429/403
  or tarpit latency spikes).
  **Delivered:** `obfuscation/timing.go` — `BehavioralTimingLayer` (Gaussian jitter via
  Box-Muller, `WarmUp` + `LongIdle`, `Adaptive` backoff hook).

Design-layer implementations are delivered as composable `Layer`s behind the `Layer` interface
(`obfuscation/layer.go`); runtime transport wiring is now implemented (uTLS `UClient` handshake,
HTTP/2 transport settings, timing layer) and must be used only with safety gates (scope allowlist
fail-closed, global rate limit <=4 rps, circuit breaker, JSONL audit). No honeypot/deception/canary
evasion logic is included.

## Safety boundary (important)
Traffic obfuscation/fingerprint-consistency layers are allowed only for **authorized in-scope**
testing and must keep safety gates enforced. The project does not implement honeypot/deception/
canary-token evasion, sandbox detection bypass, or scope/rate/audit bypass. L1 proxy rotation for
evasion remains out of scope.

---

## Module 3 — Python OSIS Scoring & Key-Rotation Engine

**Delivered:** `osint/engine.py` — runnable script implementing Stage 1 (crt.sh, CertSpotter,
OTX, Wayback, URLScan.io), Stage 2 (canary/OAST strip, CT wildcard), Stage 3 (Censys/Shodan/FOFA/
ZoomEye/Netlas/Criminal IP/GreyNoise enrichment + cross-verify), Stage 4 (confidence scoring
+2/−5/−3, behind_waf, recommended_profile, known_ports) with `targets_verified.json` output.

**Test:** `python3 osint/engine.py --domain example.com --out /tmp/targets_verified.json` → exit 0,
schema-valid output produced.

---

## Module 4 — Go 4-Layer Obfuscated HTTP Client

**Delivered:** `obfuscation/layer.go` + `obfuscation/layer_test.go` (Layer/Chain/local gateway
layer, tests green); `obfuscation/tls.go` (L2 runtime: `utls.UClient` + `ClientHelloID`),
`obfuscation/http2_consistency.go` (L3: header consistency + HTTP/2 frame layer),
`obfuscation/timing.go` (L4: jitter/warm-up/adaptive hook) + `obfuscation/layers_test.go`.

**Status:** L2/L3/L4 runtime transport wiring implemented and test-covered, behind safety gates.
No honeypot/deception/canary evasion logic is included.

**Deferred:** Any detection-evasion behavior remains out of scope.

