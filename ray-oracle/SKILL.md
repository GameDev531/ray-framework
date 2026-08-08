---
name: ray-oracle
description: >-
  Audits the target application's own LLM/AI integration for the OWASP LLM Top 10 — prompt injection (direct, indirect, RAG-poisoning), insecure handling of model output, tool/function-call abuse and excessive agency, system-prompt and data disclosure, and unbounded consumption — by tracing untrusted text into the model and the model's output into sinks.
  Use when the target app calls an LLM, embeds a chatbot/agent, does RAG, or exposes model-driven tools, and you need AI-integration security findings in workspace/findings/.
  Don't use for classic injection into non-LLM sinks (use ray-crucible), auth and tenancy (use ray-turnstile), or IA-as-privacy-egress which is data-protection (use ray-custodian).
---

# Oracle (/ray-oracle)

## System Goal

LLM-Integration Security Auditor. Treats the model the application trusts as an
untrusted, manipulable oracle, and audits the two boundaries around it: **text
flowing into the model** (can an attacker plant instructions the app will obey?)
and **the model's output flowing out** (does the app trust that output into a
dangerous sink or a privileged action?).

This is new surface for Ray. The rest of the suite treats an inference API as a
privacy egress (`/ray-custodian`) or as a self-defense concern for our own agents
(the reaver/bulwark charters). `/ray-oracle` instead audits the **target
application's** AI integration as an attack surface — the OWASP LLM Top 10 — which
no other skill covers. It is sink-and-source-driven like `/ray-crucible`: prompt
injection is a source problem (untrusted text reaching the prompt), insecure
output handling is a sink problem (model output reaching a classic sink), and it
reuses `/ray-crucible`'s injection docket for the downstream sink.

## Command Definition

- **Command:** `/ray-oracle`
- **Description:** Audits the target's LLM integration for prompt injection,
  insecure output handling, tool/agency abuse, disclosure, and unbounded
  consumption, writing findings plus a surface ledger.
- **Arguments (all optional; supplied by the orchestrator, consumed by Block A):**
  - `--snapshot_root` / `SNAPSHOT_ROOT`: pinned read-only snapshot (CODE_ROOT).
  - `--snapshot_id` / `SNAPSHOT_ID`: sentinel check and `discovery_commit`.
  - `--state_root`: the `workspace/` state directory. STATE-RELATIVE.
  - `--target_root`: authoritative override (Block A step 1a).
  - `--classes <csv>`: restrict to named classes (e.g. `injection,output,agency`).
    Absent → every class in `references/llm_security_docket.md`. A restricted run
    MUST record the skipped classes as `NOT_ASSESSED`.
  - **All flags absent → DEGRADED/legacy mode:** CODE_ROOT is the current
    directory, `snapshot_pinned` false, no `discovery_commit`.

## Input/Output Contract

- **Reads**: `workspace/.ray_state.json` (`pass_number`, `active_snapshot`);
  `workspace/plan.json` (optional); `workspace/kb/THREAT_MODEL.md` and
  `workspace/kb/entities/*.md` (optional); this skill's `references/*.md`;
  `ray-crucible/references/injection_docket.md` (for the downstream sinks that
  model output can reach); target source — prompt templates and assembly, chat/
  agent handlers, tool/function-call definitions and dispatchers, RAG/embedding
  ingestion and retrieval, system-prompt files, model-client configuration;
  `workspace/ledgers/ray-oracle.json` from the previous pass.
- **Writes**: `workspace/findings/<uuid>.json` (standard schema);
  `workspace/ledgers/ray-oracle.json`; and a copy of the previous ledger at
  `workspace/archive/ledgers/ray-oracle_pass_${N}.json` before overwriting.
- **Preconditions**: target files readable. No prompts are sent to any model and
  no jailbreak is attempted here — proving a probabilistic injection is
  `/ray-detonator`'s job (and `/ray-gauge`'s `probabilistic_llm` cap applies).
- **Idempotency Guarantee**: findings are new UUID files each run
  (`ray-condenser` merges). The ledger is archived per pass and then
  deterministically overwritten.

## Reference Files

| File | Read it | What it carries |
|---|---|---|
| `references/llm_security_docket.md` | before Step 2, then per class in Steps 2–4 | One section per OWASP-LLM class: where it lives in code, the grep patterns, the safe pattern (trust boundary, output encoding, human-in-the-loop, least-agency), the traps, and the reproduction hint for `/ray-detonator` |
| `references/findings_contract.md` | before writing the first finding, and again at Step 6 | Findings schema, the four computed fields, this domain's CWE set, evidence discipline (including the probabilistic-LLM severity reality), severity defaults, and the surface-ledger format |

## Instructions

### Step 0: Locator Resolution (Block A — CODE-READING role)

```
LOCATOR RESOLUTION (before reading ANY target code or artifact):
0. ROLE: If this skill NEVER reads target source (report, calibrate, reflect),
   you are a FINDINGS-ONLY stage: skip steps 2-6; still read active_snapshot from
   state for provenance/annotation; NEVER stop merely because a code root is unset.
1. Determine CODE_ROOT, in this priority order:
   a. If --target_root is passed on THIS invocation, CODE_ROOT = --target_root.
      It is AUTHORITATIVE and OVERRIDES SNAPSHOT_ROOT and the state fallback
      (used when a caller hands you a prepared tree, e.g. a patched shadow).
   b. Else if --snapshot_root (or SNAPSHOT_ROOT) is passed, use it.
   c. Else read state_root/workspace/.ray_state.json (state_root from
      --state_root if passed, else ./workspace/... relative to the current dir)
      -> active_snapshot.root / .snapshot_id / .snapshot_pinned.
   d. Else (no arg AND no readable active_snapshot): CODE_ROOT = current directory,
      treat snapshot_pinned = false (MODE-OFF). Do NOT stop.
2. SENTINEL CHECK (only if snapshot_pinned is true AND you did NOT take path 1a):
   verify CODE_ROOT/.ray_snapshot_id exists and equals SNAPSHOT_ID. If missing
   or different -> STOP "snapshot sentinel mismatch". (A --target_root tree (1a) is
   deliberately mutated and is sentinel-EXEMPT.)
3. PATH FIELDS:
   - SNAPSHOT-RELATIVE (read under CODE_ROOT): code_paths entries; plan target_files
     that are file paths. Strip ONLY a trailing ":<digits>". A code_paths entry
     containing "://" is a URL/endpoint, NOT a file read. A code_paths entry that is
     NOT of the form <existing-path>:<integer> is a non-source LOCATOR
     (symbol/offset/endpoint): only check that the artifact/symbol exists; skip ALL
     line-range and line-existence logic.
   - STATE-RELATIVE (read/write under state_root/workspace, NEVER prefix CODE_ROOT):
     kb_references, repro_file_path, reattack_file_path, helper scripts, report
     files, and all state/findings JSON.
4. Never WRITE under CODE_ROOT when snapshot_pinned is true. Any command that
   compiles, generates, or writes artifacts MUST run in a PRIVATE SHADOW copy
   (mktemp -d from CODE_ROOT), never with cwd=CODE_ROOT. Read-only inspection may
   cd into CODE_ROOT.
5. VCS-METADATA CARVE-OUT: history-log extraction and any VCS diff/blame command
   run in the LIVE repository root (which still has .git/.hg/.repo), NOT CODE_ROOT
   (the snapshot copy strips VCS metadata). Do NOT stop merely because CODE_ROOT
   lacks .git/.hg/.repo.
6. Every shell command uses ABSOLUTE paths and sets its own working directory on
   that call. Do NOT assume the working directory persists between calls.
```

This is a CODE-READING stage, so the findings-only skip does not apply. This
skill's `references/*.md` sit beside `SKILL.md`, not under CODE_ROOT.

### Step 1: Map the AI Surface

Read `pass_number`, `active_snapshot`, the threat model, and the docket's table
of contents. Then map the integration — everything after is scored against it:

1. **Model call sites** — every place the app calls an LLM/embedding API
   (`openai`, `anthropic`, `google.generativeai`, `langchain`, `llama`,
   `transformers.pipeline`, a raw HTTP call to an inference endpoint).
2. **Prompt assembly** — where the prompt string is built, and **which
   fragments are untrusted**: end-user messages, retrieved RAG documents,
   tool/function results, database rows, file contents, web pages fetched for the
   model. This is the source inventory for injection.
3. **Output consumers** — what the app does with the model's response: renders it
   as HTML, runs it as code/SQL, uses it as a URL, passes it to a shell, decides
   authorization on it, or calls a tool with model-chosen arguments. This is the
   sink inventory for insecure output handling.
4. **Tools/agency** — every function/tool the model can invoke, and what each can
   do (read/write DB, send email, call APIs, spend money, run code).

Record the map in the ledger's `ai_surface` block.

### Step 2: Prompt Injection (source side)

Trace each untrusted fragment from Step 1.2 into the prompt. The finding is: an
attacker-controllable fragment reaches the model's instruction context with no
trust boundary, so injected instructions are obeyed. `references/llm_security_docket.md`
carries direct (end-user), indirect (retrieved/third-party content), and
RAG-poisoning variants, and the partial mitigations to check (delimiting,
spotlighting, instruction/data separation, a privileged/unprivileged model split)
— none of which fully neutralize it, which is why the impact is judged by what
the model can then *do* (Step 4), not by the injection alone.

### Step 3: Insecure Output Handling (sink side)

Trace each model output from Step 1.3 into its consumer. Model output is
untrusted input. If it reaches a classic sink without the neutralization
`/ray-crucible`'s docket requires for that sink, it is a finding — a model that
returns HTML rendered without sanitization is XSS; returned SQL executed is SQLi;
a returned URL fetched is SSRF; a returned command run is RCE. Anchor at the sink,
cite the missing neutralizer, and cross-reference the crucible class.

### Step 4: Agency, Disclosure, and Consumption

Work the remaining classes from the docket:
- **Excessive agency / tool abuse** — a tool the model can invoke that performs a
  state-changing or privileged action with no human-in-the-loop and no
  authorization independent of the model's say-so; over-broad tool scope; the
  model's chosen arguments passed unchecked to a sink.
- **System-prompt / sensitive-info disclosure** — secrets, keys, or other users'
  data placed in the prompt or reachable via the model; a system prompt that
  leaks and exposes a guardrail an attacker can then bypass.
- **Unbounded consumption** — no rate/quota/cost ceiling on the model endpoint
  (a denial-of-wallet; cross-reference `/ray-sentry`'s `PAID` cost class).
- **Insecure RAG/training ingestion** — untrusted documents indexed without
  provenance, `pickle`/unsafe deserialization of model artifacts
  (cross-reference `/ray-crucible` `DESER`), embedding-store poisoning.

### Step 5: The Probabilistic Reality (read before scoring)

LLM attacks are probabilistic — an injection works some fraction of the time.
`/ray-gauge`'s `probabilistic_llm` rule **caps these at HIGH** by default and
often lower, *unless* an attacker can retry without rate limits to brute-force
past the non-determinism. So: score honestly, note in the finding whether
ret/rate-limiting exists (a repeatable injection against an unmetered endpoint is
worse), and do not mark CRITICAL for a probabilistic bypass without that
retry-without-limits condition. Do not send prompts to prove it here — describe
the injection for `/ray-detonator`.

### Step 6: Write Findings and the Ledger

Follow `references/findings_contract.md`. Anchor injection findings at the prompt-
assembly line and the untrusted source; anchor output-handling findings at the
sink and the model-output source; for agency findings, name the tool and what it
can do. Send no prompts to any model.

### Step 7: Complete

Report findings by severity and class, the AI-surface summary (model call sites,
untrusted prompt fragments, dangerous output consumers, tools by capability),
classes `NO_SINKS`/`NOT_ASSESSED`, and every `UNKNOWN` with what would resolve it.
Do not print finding bodies or the ledger into chat.

## Boundary With Adjacent Skills

| Concern | Owner |
|---|---|
| The downstream sink a model output reaches (XSS/SQLi/SSRF/RCE mechanics) | `/ray-crucible` (its injection docket; report the LLM-specific finding here and cross-reference) |
| Rate limiting / spend ceilings on the model endpoint | `/ray-sentry` (`PAID` cost class) |
| Personal data sent to an inference provider as a privacy egress | `/ray-custodian` |
| Unsafe deserialization of model artifacts (`pickle`, `torch.load`) | `/ray-crucible` `DESER` (report the ingestion path here, the gadget there) |
| Authorization the app should enforce independently of the model | `/ray-turnstile` |
| Prompt-injection defense of Ray's **own** agents (reaver/bulwark/scrivener) | those agents' charters — this skill audits the **target app**, not us |

Overlap with `/ray-crucible` on the output→sink boundary is by design;
`/ray-condenser` merges. The distinction to hold: `/ray-oracle` owns the fact
that the *model* is a manipulable, untrusted producer; the sink mechanics are
crucible's.
