# Curated playbooks

A playbook is a replayable case, not a claim that OmniSlash discovered the idea
on its own. Every case carries `provenance.kind` and
`provenance.autonomous_discovery`; the H2.CL case in this directory is honestly
marked `solution-derived` because the decisive `/resources` + `Content-Length:
5` + `x=1` shape came from an accidentally displayed lab solution.

## Files

- `h2-cl-resources-redirect.json` — lab-validated H2.CL response-queue poisoning
  case. It contains the byte-exact `verify` and `solve` job templates, the
  response signals that were actually observed, negative results, evidence
  paths, and a small learning label.

## Two ways OmniSlash consumes a case

1. **Planner / zero-day vault** (replay):

   ```bash
   python3 research/knowledge_base.py --vault state/zero_day_vault.json \
     import-playbook playbooks/h2-cl-resources-redirect.json --template verify
   python3 osint/planner.py --in targets_verified.json --out jobs.json \
     --vault state/zero_day_vault.json
   ```

   The planner only renders `{{EXPLOIT_HOST}}` when the authorized target record
   supplies `exploit_host` / `exploit_server` / `collaborator_host`; otherwise
   the H2.CL key is skipped. `verify` is the default template because it has a
   self-contained success marker; `solve` leaves the queued response for the
   real lab browser and needs external verification.

2. **Daemon experience** (ordering prior only):

   ```bash
   omnislashd -config examples/daemon/daemon-h2-cl.json \
     -playbook playbooks/h2-cl-resources-redirect.json
   ```

   The case's `learning` block becomes a `host: "*"` prior in the experience
   store. It is counted separately from audit records: `GET /experience` shows
   `seed_attempts`, `seed_successes` and `seed_sources`, so a curated prior is
   never presented as observed evidence. Exact-host audit evidence still wins.
   The daemon seed remains an ordering prior only; it is not an autonomous
   parameter selector.

3. **Autonomous inference** (`research/semantic_analyzer.py`,
   `research/self_learning.py`):

   ```bash
   make calibrate
   python3 osint/planner.py --in targets_verified.json --out jobs.json \
     --adaptive --learned-weights state/learned_weights.json
   ```

   In adaptive mode the planner asks `ParameterInferencer` for hypotheses and
   emits h2-cl jobs tagged `metadata.provenance: "autonomous-inferred"`. Those
   jobs synthesize the smuggled request from the inferred path/framing boundary
   and the target's own `exploit_host`; they never copy the curated `verify` or
   `solve` template. If the target supplies no exploit host, no inferred job is
   emitted.

## What is realistic to train here

Training should target *signals and transitions*, not memorized payload strings:

- **Response-shape classification**: `400 {"error":"Invalid request"}` after a
  poison, `404`, `200`, and especially `302` with an external `Location` on a
  request that did not send the smuggled request. The last one is the useful
  positive label for response-queue poisoning.
- **Desync state transitions**: poison sent → queued response → different client
  receives it. A run succeeds only when the transition is observed, not merely
  because bytes were written.
- **Timing windows**: poison interval, hold-after-poison, victim delay and
  whether same-/fresh-connection victims land on the poisoned upstream socket.
- **Host-independent technique priors**: which probe family and framing posture
  earned a response shift on previous instances, with exact-host evidence
  overriding the global prior.
- **Negative evidence**: CL 1–3 produced no redirect; aligned 20-byte prefixes
  and duplicate CL produced backend errors but no victim-visible shift; H2
  tunnelling produced `404/200` pairs but no cache poisoning.

Payload bytes are the *candidate* a trained policy orders; they are not the
lesson. A model trained only to emit the stored body would be memorizing one
lab instance, which is exactly the failure mode this playbook is meant to make
visible.
