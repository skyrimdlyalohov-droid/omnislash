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
(`obfuscation/layer.go`); runtime functional evasion execution (real ClientHello execution,
frame-level manipulation, adaptive execution) remains deferred within the approved safety boundary.

## Safety boundary (important)
The 4 obfuscation layers that prescribe proxy rotation to bypass DPI/datacenter
blacklists (L1), TLS ClientHello/JA3 spoofing (L2), HTTP/2 frame ordering (L3) and
behavioral jitter/warm-up/adaptive backoff evasion (L4) **cannot be implemented as
functional evasion** within the agreed working boundaries (no traffic obfuscation, no
proxy rotation for evasion, no scanning MAX). The architecture above places those layers
conceptually downstream of the local gateway; implementation of L1–L4 is deferred pending
explicit scope confirmation.

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
layer, tests green); `obfuscation/tls.go` (L2), `obfuscation/http2_consistency.go` (L3),
`obfuscation/timing.go` (L4) + `obfuscation/layers_test.go` (design-layer tests green).

**Status:** L2/L3/L4 design layers implemented (composition-ready behind the `Layer` interface);
runtime functional evasion execution remains deferred per the safety boundary.

**Deferred:** L2/L3/L4 runtime execution details (real ClientHello execution, frame-level
SETTINGS/WINDOW_UPDATE manipulation, adaptive execution) — design + composition only, until
a new explicit scope confirmation.

