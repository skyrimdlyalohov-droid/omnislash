# Omnislash manifesto

**Omnislash owns the socket, probes own the logic.**

Omnislash is a platform for controlled, verifiable HTTP desync research. It is
not a WAF bypass kit, not an evasion framework and not a stealth tool. The
fingerprint rotation and proxy pool exist so that a lab result is attributable
to a parser difference — not to a Go `ClientHello`, a leaked source IP or a
silently rewritten request.

## No evasion

- We do not build, document or sell WAF/IDS evasion. Fingerprint profiles make
  an experiment reproducible across intermediaries; they do not make traffic
  anonymous or undetectable.
- We do not hunt public targets. OSINT modules collect intelligence only. They
  never turn an observation into an attack job.
- A target is in scope only because an operator put it there. An explicit scope
  file (`--scope-file`) or `scope.allow_hosts` is mandatory for unattended runs;
  without it, the transport refuses to dial.
- Rotation is a research control, not camouflage. Every attempt keeps its proxy
  label and egress identity in the audit log.

## Fail closed, always

- No silent direct fallback. If the pinned proxy dies, the experiment fails. A
  caller that wants direct egress must opt in explicitly with `allow_direct`
  and a trusted pool.
- One experiment, one session, one exit IP. A probe can never open a second
  connection behind the transport's back.
- Probes receive an already dialed `net.Conn`. No `net/http`, no `net.Dial`, no
  library request writer inside a probe. Bytes on the wire are bytes the probe
  built.
- The declared job is immutable. Learning reorders already declared variants,
  mutations and framing lengths; it never invents a probe or a verdict.

## Evidence before verdicts

- A finding is a heuristic until the raw exchange and a real target response
  say otherwise. `unverified` is a quarantine label, not a finding.
- Proxy failures, WAF pages and parser rejections are separate outcome classes.
  Proxy failures never train the learner. WAF/rejection events are weak negative
  evidence. Only verified target responses are full evidence.
- Two independent, attributed proxy exits are required before a learned
  hypothesis can become an executable strike job. One exit cannot confirm
  itself.
- Exploration is one epsilon decision per attempt, shared by every ranking
  stage. Learning must not inflate exploration by stacking independent rolls.
- Deception detection excludes and quarantines tarpits; it never claims to beat
  them. `ncd_tarpit` and `ncd_structural` are conservative thresholds, and
  baseline calibration runs before the first probe.
- If the semantic skeleton service is unavailable, the filter says so and uses
  sampled bytes. It never fabricates a baseline.

## Honest tooling

- The Go core is stdlib-only apart from refraction-utls, rawhttp and HTTP/2
  framing. The learning loop is stdlib Python. No Docker, Node.js, npm or CDN is
  required to run or calibrate it.
- Audit records carry evidence and attribution, not credentials or secrets.
- Every claim in the README maps to a test. If a guarantee is not enforced by
  code, it is not a guarantee.

Use this only on labs and systems you own or have written authorization to
test. If the scope is not yours, do not run it.
