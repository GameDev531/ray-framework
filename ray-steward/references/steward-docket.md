# Steward Docket — steward

Vulnerable→safe patterns for `ray-steward`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## End-of-life runtime / dependency — CWE-1104 · A06:2021
- **Broken:** an EOL language runtime, framework major, OS base image, or database
  version no longer receiving security fixes.
- **Safe:** supported versions with a documented upgrade path before EOL.

## Patch cadence — A06:2021
- **Broken:** no process to apply security updates; dependencies months/years behind;
  no automated advisory alerting.
- **Safe:** a regular update cadence; advisory monitoring wired to the SBOM.

## Backup & restore integrity — CWE-1188
- **Broken:** no backups; backups never test-restored; backups reachable (and
  encryptable) by the same credentials as production (ransomware blast radius); no
  offsite/immutable copy.
- **Safe:** backups taken, periodically restore-tested, and stored immutably/offline
  with separate credentials.

## Disaster recovery / rollback — CWE-1188
- **Broken:** no documented DR plan; no tested rollback; a single region/zone with no
  failover for a CRITICAL-tier service.
- **Safe:** an exercised DR runbook; tested rollback; failover matched to the
  availability tier.

## Secret / key rotation — CWE-798
- **Broken:** long-lived static secrets never rotated; no revocation path on leak.
- **Safe:** scheduled rotation; a rehearsed revocation/rotation procedure.

## What is NOT a finding here

- A young dependency merely "not latest" with no security or support-window impact.
- A LOW_CRITICALITY utility with no DR — match the recommendation to the availability
  tier, don't demand DR for a toy.
- A backup gap in a stateless service with no data to lose.
