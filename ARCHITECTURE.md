# Architecture and invariants

`omnislash` is a transport layer for integrity-sensitive tools that must send
exact bytes through an untrusted egress. Request smuggling is the reference
consumer because it makes every violation obvious, but the same invariants
apply to protocol differential testing, custom TLS clients and raw fuzzers.

## Invariants

1. **One experiment = one exit IP.**
   `Dialer.NewSession(ttl)` selects a proxy once and pins it for an explicit
   lifetime. `Session.DialContext` never retries through another proxy and
   never falls back to a direct dial. After expiry it returns
   `ErrSessionExpired`. Code: `session.go`. Test:
   `TestSessionPinsOneProxyForExperiment`,
   `TestSessionFailsClosedAfterExpiry`.

2. **Fail-closed on proxy failure.**
   `allow_direct` defaults to `false` and is rejected in `trust_tier: strict`.
   A proxy that completes CONNECT and dies mid-request produces a connection
   error; it is not replaced by a direct connection. Code: `dialer.go`,
   `transport.go`, `config.go`. Tests: `TestDialerNoDirectFallback`,
   `TestDialerProxyFailureMidRequestIsAnError`,
   `TestStrictTierForbidsDirectFallback`.

3. **Two admission modes with different probes.**
   `validation.mode: connect` runs a raw CONNECT canary, verifies the target
   certificate, pauses, then makes a second request on the same tunnel.
   `validation.mode: http_parsing` requires exact N-bytes-out/N-bytes-back for
   an HTTP payload with conflicting `Content-Length` and `Transfer-Encoding`.
   Code: `admission.go`. Tests:
   `TestAdmissionConnectVerifiesCertificateAndLongLivedTunnel`,
   `TestAdmissionEchoAcceptsTransparentTunnel`,
   `TestAdmissionHTTPPayloadKeepsConflictingFraming`.

4. **Negative canaries are mandatory.**
   The admission suite is tested against good and bad fixtures: a transparent
   echo tunnel, a buffering proxy, a framing rewriter, a dropper and a TLS MITM.
   Code: `admission_test.go`. Tests:
   `TestAdmissionEchoRejectsBufferingProxy`,
   `TestAdmissionEchoRejectsFramingRewriter`,
   `TestAdmissionEchoRejectsDroppingProxy`,
   `TestAdmissionConnectRejectsMITMCertificate`.

5. **Two trust tiers, one implementation.**
   `strict` applies egress plus the full admission suite. `trusted` applies
   health plus egress only, for an operator-owned mobile/LTE pool. Both use the
   same `Pool`, `Dialer` and `Validator`. Code: `config.go`, `validate.go`,
   `scraper.go`. Test: `TestTrustTierSwitchesAdmissionPolicy`.

6. **Target certificate verification in CONNECT mode.**
   The connect admission probe requires a verified chain and rejects a
   substituted certificate. `admission.tls_skip_verify` is forbidden in strict
   connect mode. Tests:
   `TestAdmissionConnectVerifiesCertificateAndLongLivedTunnel`,
   `TestAdmissionConnectRejectsMITMCertificate`,
   `TestStrictConnectForbidsAdmissionSkipVerify`.

7. **Scope is a local, fail-closed allowlist.**
   Targets are checked before any proxy is contacted; hostnames resolve locally
   when scope is enabled; metadata addresses are always denied. Code:
   `scope.go`. Tests: `scope_test.go`.

## Data flow

```
proxy sources -> Colly -> dedupe/shuffle -> egress canaries
                                             |
                                   strict: connect / http_parsing admission
                                             |
                                   atomic Pool.Replace (hot swap)
                                             |
scanner -> Dialer / Session / CONNECT gateway -> opaque proxy tunnel -> target
```

The proxy never receives target bytes through `net/http`; HTTP proxies always
use CONNECT, SOCKS5 tunnels are byte-transparent, and the gateway copies raw
streams. Admission probes are the only place where omnislash itself writes
HTTP-like bytes, and they are isolated from scanner traffic.
