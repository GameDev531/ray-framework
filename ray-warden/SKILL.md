---
name: ray-warden
description: >-
  Detection and response on a running estate — alert triage, threat hunting, and incident response. Dispatches the ray-vigil agent to investigate a case and return a scored verdict with a tier-appropriate recommendation.
  Use when you operate a live system with alerts and telemetry, not for a point-in-time code audit. The analyst recommends; a human or a tier gate acts.
---

# Warden (/ray-warden)

## System Goal

Detection & Response Coordinator. Track C of the framework, and the only one that
runs continuously rather than as a point-in-time audit. It turns alerts and
telemetry from a running estate into scored verdicts and tier-appropriate
recommendations, dispatching the `ray-vigil` analyst agent per case.

## Command Definition

- **Command:** `/ray-warden [--alert=<ref>] [--hunt=<hypothesis>] [--tier=<0|1|2>] [--sources=<list>]`
- **Description:** Triage an alert, run a hunt, or coordinate incident response.
- **Parameters:**
  - `--alert`: an alert/case reference to triage.
  - `--hunt`: a threat hypothesis to hunt proactively.
  - `--tier`: autonomy tier (see Step 0). Default 0 (recommend-only).
  - `--sources`: available telemetry (logs, EDR, SIEM, netflow) the analyst may read.

## Input/Output Contract

- **Reads**: the alert/case, the telemetry `--sources`, and prior case memory.
- **Writes**: a scored verdict + recommendation per case to `workspace/cases/`;
  hunt results and kill-chain coverage notes. Read-only against the estate at tier 0.
- **Preconditions**: authorization to access the estate's telemetry; a defined
  autonomy tier.
- **Idempotency**: a case already triaged at the same evidence state returns the
  same verdict.

## Instructions

### Step 0 — Autonomy tier (set expectations first)

The tier bounds what may happen automatically:
- **Tier 0 (default): recommend-only.** The analyst investigates read-only and
  recommends; a human acts. Use this unless told otherwise.
- **Tier 1: gated action.** A defined gate may take pre-approved, reversible
  containment (isolate a host, disable a token) after the verdict.
- **Tier 2: autonomous containment** for a narrow, pre-authorized set only.

The **analyst only recommends** regardless of tier; acting is the gate's job, never
the analyst's. Never exceed the authorized tier.

### Step 1 — Dispatch ray-vigil

For an `--alert` or `--hunt`, dispatch the `ray-vigil` agent. It reads the analyst
docs in order: autonomy tiers → the class playbook (auth · phishing · endpoint ·
exfil · IoC) → the findings contract. It recalls prior case memory, frames the
triage, runs the class-appropriate playbook, correlates telemetry, and returns a
**scored verdict with a confidence** plus a tier-appropriate recommendation.

### Step 2 — Hunt & kill-chain coverage

For a `--hunt`, vigil pursues the hypothesis across telemetry and maps findings to
kill-chain stages. Because `ray-reaver` performs only the local slice and reports
the rest of the chain as impact, **the blue side must detect the whole chain** —
vigil's kill-chain detection map is where red's impact notes become detection
coverage. Gaps in coverage are logged as detection-engineering work.

### Step 3 — Verdict & response

Record the verdict (benign / suspicious / malicious), confidence, the evidence
chain, and the recommended action matched to the tier. For a confirmed incident,
follow the DFIR playbook: scope, contain (via the gate, not the analyst), eradicate,
recover, and capture lessons for the next hunt.

## Safety

- The analyst recommends; only the tier gate acts, within its pre-authorized scope.
- Tier 0 is read-only against the estate — never change state at tier 0.
- Never access telemetry or systems outside the authorized estate.

When complete, notify the user.
