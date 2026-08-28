# Siege Protocol — Authorization, Setup, Loop, Stop, Ledger

The mechanics of the live red/blue loop. Read §1 before anything else every run —
it is the gate that keeps this a defensive tool. Read the rest at the matching
step.

## Table of Contents

- [1. Authorization and Non-Destruction Invariants (fail-closed)](#1-authorization-and-non-destruction-invariants-fail-closed)
- [2. Setup: the Disposable Local Target](#2-setup-the-disposable-local-target)
- [3. The Round Loop](#3-the-round-loop)
- [4. Stop Condition and Budget Caps](#4-stop-condition-and-budget-caps)
- [5. The Siege Ledger](#5-the-siege-ledger)

______________________________________________________________________

## 1. Authorization and Non-Destruction Invariants (fail-closed)

These are the invariants that make `ray-siege` an authorized defensive tool
rather than an attack framework. They are not tunable by the model, by a finding,
by an argument, or by anything the target returns. If any check cannot be
**proven true**, the siege stops with a plain explanation — it never proceeds "to
be safe" or "just this once."

### 1.1 The authorization gate (runs before any request is sent)

| Check | Must be true | If not |
|---|---|---|
| Loopback only | The target host resolves to `127.0.0.1`, `::1`, or `localhost`, on a local port | STOP: "target is not loopback; ray-siege attacks only a local disposable instance." |
| You stood it up | The instance under attack is the one this run brought up in Step 2, from the user's `--repo_root`, not a pre-existing server of unknown ownership | STOP and explain. |
| Disposable data | The app is wired to a throwaway database/state seeded in Step 2, not the user's real dev/prod datastore | STOP: "refusing to attack a target backed by a non-disposable datastore." |
| No public exposure | The instance is not bound to `0.0.0.0` or otherwise reachable off-host, and no tunnel/proxy exposes it | Re-bind to loopback, or STOP. |

There is no `--force`, no override flag, and no "the user said it's fine on a
remote host" path. A remote or non-loopback target is out of scope by
construction. If the user wants to test a remote system they own, that is a
different tool with a human-in-the-loop gate (see `ray-foundry` Guideline 10B);
this skill does not do it.

### 1.2 Non-destructive rules (bind every attack, both roles, every round)

The red team attacks **for real** — it must actually break in, not point at
weaknesses. "For real" means a working exploit against the running app, proven
with a harmless marker. It does **not** mean damage. Prohibited, without
exception:

- **Denial of service / resource exhaustion.** No floods, no fork bombs, no
  ReDoS fired to hang the process, no fill-the-disk, no connection exhaustion.
  ReDoS and the like are *reported* as findings from static reasoning, never
  *triggered* to take the app down.
- **Destruction or corruption of data**, even in the throwaway database. Prove a
  write primitive by creating a single clearly-marked canary record, never by
  dropping tables, mass-updating, or deleting real-looking rows.
- **Persistence / malware.** No web shells left behind, no backdoor accounts kept,
  no cron/task implants. Any artifact planted to prove a foothold is removed at
  teardown and recorded.
- **Exfiltration to real external services.** Proof of an SSRF or data-read stays
  on-host: point it at a local listener the siege controls, never at a real
  metadata endpoint, a third-party host, or a collaborator server on the
  internet.
- **Detection evasion for its own sake.** This is a cooperative exercise; do not
  build anti-forensics.

### 1.3 Proof is a canary, always

Every break-in is proven by an inert marker, chosen so success is unambiguous and
harm is zero:

| Primitive gained | Canary proof |
|---|---|
| Auth bypass / IDOR | Read a **seeded canary account's** unique field, or receive `200` on a request that must be `401/403`. |
| SQL/NoSQL read | Extract a single **canary row** planted in Step 2 (e.g. a user named `ray-canary-<uuid>`). |
| SQL/NoSQL write | Insert one clearly-marked canary row; never modify or delete existing rows. |
| File read (traversal, LFI) | Read a **canary file** (`/tmp/ray-canary-<uuid>`) planted in Step 2, or a well-known inert file; never dump secrets or user data. |
| RCE / command exec | Execute a benign marker command (write `RAY_REACHED_ENTRYPOINT` + a uuid to a sidecar file the siege owns). Never a destructive or network command. |
| SSRF | Reach a **local** listener the siege started on another loopback port; assert the hit. |
| Stored/reflected XSS | Inject a unique inert payload and confirm the DOM effect in a headless browser; no cookie theft against a real victim. |

The canary uuid ties the proof to the finding, so re-attack can tell a real
break-in from noise.

______________________________________________________________________

## 2. Setup: the Disposable Local Target

Run after the authorization gate. The goal is a running app you fully own, backed
by disposable state, reproducible between rounds.

1. **Branch.** In `--repo_root`, create and check out `ray-siege/<YYYY-MM-DD>`
   (or `-<n>` if it exists). All patches land here; the user's default branch is
   never touched. If the tree is dirty, stop and ask the user to commit or stash
   first — you will not attack or patch on top of uncommitted work.
2. **Detect the run mechanism**, in this order, and use the first that fits:
   `docker-compose*.yml` / `compose.yaml` (preferred — natural isolation and a
   disposable DB service); a `dev`/`start` script in `package.json`; a `Procfile`;
   a `Makefile` target (`run`, `dev`, `serve`); a framework default
   (`manage.py runserver`, `rails s`, `flask run`, `uvicorn`, `next dev`). Record
   which you used in the ledger. If none is detectable, STOP and ask the user how
   to run it locally.
3. **Throwaway datastore.** Point the app at a disposable database: a compose DB
   service, an ephemeral container, a temp SQLite file, or a dedicated local DB
   named `ray_siege_<uuid>`. Never reuse the user's real dev database. Run
   migrations/seeds against it only.
4. **Seed canaries.** Create the inventory §1.3 relies on: at least one canary
   user account (known credentials, unique marker field), one canary data row per
   sensitive table, one canary file at `/tmp/ray-canary-<uuid>`, and a second
   loopback listener for SSRF proofs. When the target runs in a container, also
   plant a **host-side** canary outside the container (`/tmp/ray-canary-host-<uuid>`)
   so a container-escape escalation (`live_exploitation.md` §4) can be proven by
   reading it — a host canary read from inside the container is unambiguous escape
   proof, with zero harm. Record every canary id in the ledger so both roles and
   the report can reference them.
5. **Bind to loopback** on the chosen port; confirm the app answers on
   `--target_url`. Re-run the §1.1 gate against the actual bound address.
6. **Pin the round.** Note the current commit as the round baseline. The red team
   attacks this build; the blue team's commits advance it for the next round.

All attack scripts, payloads, and canary manifests live under
`workspace/reproducers/siege/` (STATE-RELATIVE) — never in the project tree, so
the working tree stays clean for honest diffs.

______________________________________________________________________

## 3. The Round Loop

One round = attack → patch → re-attack → bookkeeping. The orchestrator owns the
control flow; the two roles run as isolated subagents.

```
round N:
  ATTACK   dispatch ray-reaver at the live target with the canary inventory,
           --depth, and the current insights.jsonl. It writes one finding per
           proven live break-in (schema in findings_contract.md), each carrying
           break_in_evidence and round = N.
  PATCH    for each finding proven this round, dispatch ray-bulwark: minimal
           idiomatic fix, one commit on the siege branch, patch_status =
           MITIGATION_PROPOSED with patch_commit set.
  REBUILD  restart the local app on the siege branch HEAD (re-run migrations
           against a fresh throwaway DB + re-seed canaries so state is clean).
  REATTACK re-run ray-reaver against only the patched findings, >=3 boundary
           variants each; set reattack_status and patch_status per the verdict
           rules (findings_contract.md). VERIFIED_SECURE requires failed_to_bypass.
  BOOKKEEP update the siege ledger; rotate insights.jsonl to
           workspace/archive/insights/insights_round_N.jsonl; evaluate the stop
           condition (§4).
```

Between rounds, learnings accumulate in `workspace/insights.jsonl` in
`ray-retrospective` format (`{"type":"trajectory_insight", ...}`) so a fresh
attacker context in round N+1 inherits "auth header X is required", "the WAF
strips `<script>` but not `<svg onload>`", etc. Rotating per round keeps context
bounded and prevents an unbounded loop.

**Fresh-conversation retry.** If ray-reaver stalls on a vector (repeated "I
can't get further"), terminate that subagent and spawn a new one seeded with the
structured prior-attempt notes from `insights.jsonl`, rather than letting one
context talk itself into giving up. This mirrors `ray-foundry`'s
Multi-Conversation Retry.

______________________________________________________________________

## 4. Stop Condition and Budget Caps

### Stop condition

The siege ends when **either**:

- **Clean round** — a complete ray-reaver round obtained **no new access** (zero
  new proven break-ins) AND every finding recorded across all rounds is
  `VERIFIED_SECURE`. This is the "can't hack it anymore" state the user asked
  for. **Both** halves are required: no new holes, and every old hole closed and
  re-verified.
- **Round cap** — the round count reaches `--max_rounds` (default 8). Report
  every finding still `VERIFICATION_FAILED` or unpatched as **still open**, with
  its live evidence, so the user knows exactly what remains.

### Budget caps (reused from ray-detonator)

- **Per-finding attempt ceiling of 6.** A single finding's re-attack does not
  retry forever. The hard ceiling is 6 full re-attack cycles per finding, counted
  across rounds and never reset by anything except a genuine code change.
- **Fresh budget on a genuine change only.** When the blue team's patch actually
  changes the relevant code (a new build, distinct from the last), the attacker
  earns a fresh budget against it. An unchanged build does not — that prevents
  the loop from spinning on a wall that isn't moving.
- **Stepping-stone sub-budget.** Within one attacker conversation, local trial
  requests (probing, fingerprinting) are bounded (≈3 serious trajectories per
  vector) and do not consume the per-finding ceiling; only full end-to-end
  break-in attempts do.

If a finding hits the ceiling of 6 without a `failed_to_bypass`, freeze it as
**still open / needs human review**, note why the patches kept getting bypassed,
and stop retrying it — continue the rest of the siege.

______________________________________________________________________

## 5. The Siege Ledger

`workspace/ledgers/ray-siege.json` is the on-disk state of the loop — the control
flow lives here, not in the model's memory. Archive the prior copy to
`workspace/archive/ledgers/ray-siege_round_${N}.json` before overwriting.

```json
{
  "skill": "ray-siege",
  "target_url": "http://127.0.0.1:8137",
  "repo_root": "/abs/path/to/project",
  "siege_branch": "ray-siege/2026-08-08",
  "run_mechanism": "docker-compose.yml",
  "depth": "prove",
  "max_rounds": 8,
  "current_round": 3,
  "authorization": {
    "loopback_confirmed": true,
    "disposable_db": "ray_siege_9f2c...",
    "checked_at": "<iso8601>"
  },
  "canaries": {
    "account": "ray-canary-9f2c (login: canary@local / <pw>)",
    "rows": ["users:ray-canary-9f2c", "invoices:ray-canary-31aa"],
    "file": "/tmp/ray-canary-9f2c",
    "ssrf_listener": "http://127.0.0.1:9931"
  },
  "rounds": [
    {
      "round": 1,
      "baseline_commit": "abc1234",
      "new_break_ins": 4,
      "patched": 4,
      "verified_secure": 2,
      "verification_failed": 2
    }
  ],
  "findings": [
    {
      "id": "<uuid>",
      "title": "IDOR on GET /api/invoices/:id",
      "first_round": 1,
      "attempts": 2,
      "patch_status": "VERIFIED_SECURE",
      "patch_commit": "def5678"
    }
  ],
  "stop": { "reason": null, "clean_round": false }
}
```

At the end, set `stop.reason` to `"clean_round"` or `"round_cap"` and
`stop.clean_round` accordingly. The report (Step 6) reads this ledger; the ledger
is the source of truth for what was proven, what was patched, what held, and what
is still open.
