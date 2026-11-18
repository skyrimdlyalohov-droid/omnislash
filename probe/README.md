# probe

Attack modules that run on top of an omnislash connection.

The split is deliberate: **omnislash owns the socket, the probes own the
logic**. A probe receives an already dialed `net.Conn`, usually from a pinned
`Session`, writes bytes with `conn.Write` and reads with its own
`bufio.Reader`. No probe calls `net.Dial`, `net/http` or `http.Client`, so a
probe can neither leak the host IP nor split an experiment across two exit
addresses.

```go
type Probe interface {
	Name() string
	Execute(ctx context.Context, target Target, conn net.Conn) (*Result, error)
}
```

`Result` always contains the evidence, not just a verdict:

| Field | Meaning |
| --- | --- |
| `Attribution` | proxy label and its validated egress IP, resolved from the conn itself |
| `Exchanges` | every byte written, in one entry per `conn.Write` |
| `Responses` | parsed status/headers/body plus the exact raw bytes consumed |
| `Payloads` | the individual requests inside a burst (a burst is often one write) |
| `Burst` | how the batch was emitted: requests, bytes, writes, mode |
| `Findings` | heuristics with an explicit `low`/`medium`/`high` confidence |

## Modules

| Module | Type | Technique |
| --- | --- | --- |
| Smuggling & desync | `SmugglingProbe` | `cl.te`, `te.cl`, `te.te`, `h2.downgrade`; one variant per connection |
| Race H1 | `RaceProbe` | single-packet attack: `single_write`, `writev`, `last_byte` |
| Race H2 | `H2RaceProbe` | last-frame synchronization: all HEADERS first, all END_STREAM DATA in one write |
| WAF bypass / fuzzing | `GadgetProbe` + `Gadgets()` | duplicate and obfuscated framing headers, one gadget per rotated session |
| Cache poisoning | `CachePoisonProbe` | poisoner then victim on one connection (cache stickiness) |
| Rate-limit bypass | `RaceProbe` + `Runner.Fanout` | synchronized bursts in parallel across pool IPs |
| WebSocket handshake | `WebSocketProbe` | documented `ErrNotImplemented` stub, see below |

### Library substitutions

Three libraries named in the original design are not usable as Go packages, so
the logic lives in this package instead of behind a fake import:

* `github.com/DonatoReis/racey` does not exist publicly. The single-packet
  logic is `sendBurst` in `race.go`: it is ~100 lines and has to know about
  TLS records anyway (`writev` on a `tls.Conn` degrades into one record per
  buffer, which reintroduces the gap the attack removes).
* `github.com/nxenon/h2spacex` is a Python package. `h2race.go` implements the
  same last-frame synchronization with `golang.org/x/net/http2` and `hpack`,
  writing frames directly to the provided conn.
* `github.com/httpsuite/smugglefuzz` does not exist. `gadgets.go` carries a
  small hand-written table of documented parser disagreements. It is a table,
  not a scraped corpus, so every entry can be explained in a report.

`github.com/projectdiscovery/rawhttp` *is* used, but only as a byte renderer:
`render` hands it a `bytes.Buffer`, never the socket. rawhttp preserves header
order, casing, duplicates and whitespace, which `net/http` cannot.

### WebSocket

`gorilla/websocket` performs its own handshake on a connection it dials, so it
cannot adopt a socket that omnislash already owns. Calling it here would either
open a second connection (a different exit IP) or duplicate the handshake. The
compliant path is: render the upgrade request with `render`, write it, read the
`101` with the package reader, then parse frames (`FIN`/opcode/mask/length)
directly. That parser needs its own fixtures for masking, fragmentation and
control frames, so the module ships as an explicit `ErrNotImplemented` rather
than a broken imitation.

## Running

```bash
go run ./examples/probe -probe race   -target api.ipify.org:443 -host api.ipify.org -path '/?format=json' -count 10
go run ./examples/probe -probe smuggle -target example.test:443 -host example.test -path /
go run ./examples/probe -probe h2race  -target example.test:443 -host example.test
go run ./examples/probe -probe gadgets -target example.test:443 -host example.test
```

Every run goes through `Runner`, which creates a pinned session, dials exactly
one connection, executes the probe and closes both. `Runner.Rotate` runs one
probe per fresh session (gadget rotation); `Runner.Fanout` runs the same probe
on independent sessions in parallel (rate-limit bypass across IPs).

Only use these probes against systems you are authorized to test.
