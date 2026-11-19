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
   The guarantee is per proxied endpoint: a backconnect proxy that rotates
   its exit per connection defeats it, so the pool must map one endpoint to
   one exit (owned modems, provider session-id endpoints).

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

## Probe layer

Attack modules live in `probe/` and follow one rule: **omnislash owns the socket,
the probes own the logic.**

- A `Probe` receives an already dialed `net.Conn` and returns a `Result`. It
  never calls `net.Dial`, `net/http` or `http.Client`, so it cannot leak the
  host IP, cannot open a second connection, and cannot move half of an
  experiment to another exit IP.
- Requests are emitted with `conn.Write`; responses are parsed by the probe's
  own reader. That is what keeps the bytes on the wire identical to the bytes
  the probe built - a desync needs a front-end and a back-end to disagree, so
  nothing in the path may normalize framing first.
- Libraries still do the hard parts: projectdiscovery/rawhttp renders request
  lines and duplicate/obfuscated headers into a `bytes.Buffer`, and
  `x/net/http2` + `hpack` encode H2 frames. Neither gets the socket.
- `Result` carries `Attribution` (proxy label and validated egress IP resolved
  from the conn), every write, every parsed response with its raw bytes, and
  heuristic `Findings` with explicit confidence. The evidence is the raw
  exchange; the verdict is only a hint.
- `Runner` opens exactly one pinned session per execution. `Run` = one probe on
  one IP, `Rotate` = one probe per fresh session (gadget lists), `Fanout` =
  the same probe on independent sessions in parallel (rate-limit bypass).

Modules: `SmugglingProbe` (CL.TE, TE.CL, TE.TE, H2 downgrade), `RaceProbe` (H1
single-packet), `H2RaceProbe` (last-frame sync), `H2TunnelProbe` (CRLF in
`:path`, tunnelled response over-read, cache poisoning verified with a normal
GET), `GadgetProbe` (WAF bypass), `CachePoisonProbe` (poisoner then victim on
one conn), `WebSocketProbe` (documentedly unimplemented). See `probe/README.md`.

Some techniques need more than one socket: a front-end can close every client
connection while reusing its back-end connection, so a desync planted on one
socket is observed on the next. `MultiConnProbe` covers that case. It receives a
`ConnSource` created by `Runner`, not a dialer: every connection still belongs
to one pinned session and one exit IP, and the probe still only writes bytes.

## Daemon

`omnislashd` is the automation layer: jobs from a JSON file, a scheduler with
per-job intervals, bounded concurrency, retries and a JSONL audit record per
attempt. It chooses one `probe.Runner` per TLS mode (`none`, `h1`, `h2`) and
calls the same `Probe` implementations the library exposes.

- One scheduled execution may contain several attempts; each attempt is a fresh
  pinned session and a fresh set of sockets.
- Success is explicit. With `success_contains` the marker must appear in a
  response body, header or reason. Without a marker the job counts as successful
  when the probe completed; the evidence is still in the audit log.
- `exit_on_success` turns the daemon into a CI/lab command: it returns 0 only
  after a job reaches its declared goal.
- The control endpoint is bound to `control_addr` and exposes only `/healthz`
  and `/status`; it is not an open proxy or an arbitrary job API.

For a lab without proxies the transport must be `trust_tier: trusted` with
`allow_direct: true` and a scope pinned to that lab. In that mode
`Dialer.NewSession` pins direct egress; it never falls back to direct after a
proxy failure. A direct session has no proxy attribution, so
`Result.Attribution.Verified` stays false - that is the honest answer, not a
finding that a proxy was used.

## Known boundaries

- Admission runs at scrape time. A hand-written `proxies.txt` loaded by
  `serve` or `cmd/gateway` is trusted input; only the per-connection TLS
  verification done by the client protects that path.
- `check` runs health and egress probes, not admission.
- The CONNECT gateway attributes an exit IP to a TCP connection, not to an
  individual HTTP request. Tools that need per-request attribution must use
  `Dialer`/`Session`.
- Free public proxies are intermittent: the same proxy can pass a canary and
  later serve a wrong certificate. Verification is therefore per connection,
  not a one-time property of the pool entry.

## Data flow

```
proxy sources -> Colly -> dedupe/shuffle -> egress canaries
                                             |
                                   strict: connect / http_parsing admission
                                             |
                                   atomic Pool.Replace (hot swap)
                                             |
scanner -> Dialer / Session / CONNECT gateway -> opaque proxy tunnel -> target
probe   -> Runner -> pinned Session -------------------^  (conn.Write only)
daemon  -> probe jobs -> Runner (one pinned Session per attempt)
```

The proxy never receives target bytes through `net/http`; HTTP proxies always
use CONNECT, SOCKS5 tunnels are byte-transparent, and the gateway copies raw
streams. Admission probes are the only place where omnislash itself writes
HTTP-like bytes, and they are isolated from scanner traffic.
