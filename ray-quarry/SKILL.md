---
name: ray-quarry
description: >-
  External attack-surface reconnaissance on assets you are authorized to assess — passive OSINT, DNS and subdomain enumeration, certificate-transparency mapping, and exposed-service discovery. Use to map what is publicly reachable before a deeper review.
  Runs standalone. Authorization is mandatory — never recon an asset you do not own or have written permission to test.
---

# Quarry (/ray-quarry)

## System Goal

Attack-Surface Cartographer. Maps what an external attacker can see of the target
before any code is read — the domains, subdomains, certificates, and exposed
services that make up the reachable perimeter. Feeds `ray-perimeter`'s threat model
with a real, observed surface instead of an assumed one.

## Command Definition

- **Command:** `/ray-quarry --scope=<domains/IPs> [--passive] [--active] [--out=<dir>]`
- **Description:** Enumerates the external attack surface for authorized assets.
- **Parameters:**
  - `--scope`: REQUIRED — the exact domains/IP ranges you are authorized to assess.
  - `--passive`: OSINT and public datasets only (no packets to the target).
  - `--active`: light active enumeration (DNS resolution, port/service probing)
    within scope. Default is passive-only.
  - `--out`: where to write the surface map (default `workspace/recon/`).

## Input/Output Contract

- **Reads**: the `--scope` list; public sources (certificate transparency, DNS,
  passive datasets) via the available network.
- **Writes**: `workspace/recon/surface.md` (a structured map: domains, subdomains,
  resolved IPs, open services, technologies, notable exposures) and, for any
  clearly exposed sensitive service, a `workspace/findings/<uuid>.json`.
- **Preconditions**: **explicit authorization for every asset in scope.**
- **Idempotency**: overwrites the surface map; re-running refreshes it.

## Instructions

### Step 0 — Authorization gate (MANDATORY, do this first)

Confirm the user is authorized to assess every asset in `--scope`. If scope is
missing, vague ("the internet"), or you cannot establish authorization, STOP and
ask. Reconnaissance against assets you do not own or have permission to test is out
of bounds — this gate is not optional.

### Step 1 — Passive first

Stay passive unless `--active` is given:
- **Certificate transparency**: enumerate subdomains from CT logs (crt.sh-style
  sources) for the in-scope domains.
- **DNS**: records (A/AAAA/MX/TXT/NS/CNAME), SPF/DMARC/DKIM posture.
- **Passive datasets**: public tech fingerprints, known hosts, archived endpoints.
- Keep everything within `--scope`; do not pivot to out-of-scope assets you
  discover — note them, don't probe them.

### Step 2 — Light active enumeration (only with `--active`)

Within scope: resolve discovered subdomains, probe for live web services, capture
server/tech banners and TLS configuration, and note obviously exposed surfaces
(admin panels, `/.git/`, open storage indexes, dev/staging hosts). Keep it
non-destructive and rate-limited — recon, not exploitation.

### Step 3 — Map and hand off

Write `surface.md`: the domains/subdomains, resolved IPs, live services and their
technologies, and a "notable exposures" section. For a clearly exposed sensitive
service (an open admin panel, an exposed `.git`, a public staging DB), write a
finding. Hand the surface to `ray-perimeter` so the threat model reflects the real
perimeter, and to `ray-siege` if a live test is authorized.

## Safety

- Authorization is a precondition, re-checked here — never recon out of scope.
- Passive by default; active enumeration stays non-destructive and rate-limited.
- Discovered-but-out-of-scope assets are noted, never probed.

When complete, notify the user.
