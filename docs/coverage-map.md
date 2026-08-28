# Coverage Map — charter, domains, and target profiles

What Ray covers, which skill owns each concern, and how a target profile tunes the
pipeline. This is the charter boundary the Field Manual footer points to.

## Charter

Ray audits source code, binaries, IaC, dependencies, and (via Track B) a running
local app, and operates detection on a live estate (Track C). It is **evidence-first**:
no single model call is the verdict — findings are guilty until disproven
(`ray-arbiter`), viability-checked (`ray-magistrate`), reproduced (`ray-detonator`),
and capped by 27 auditable severity rules (`ray-gauge`). It is domain-agnostic by
default and tunes to a target type via a **profile**.

Out of charter: attacking assets you are not authorized to test; production systems
in Track B; anything a profile or the threat model marks out of scope.

## Concern → owning skill

| Concern | Skill |
|---|---|
| Structural index | ray-lattice |
| Directory digests | ray-prism |
| Knowledge base | ray-blueprint |
| Threat model | ray-perimeter |
| Review plan | ray-compass |
| VCS history signal | ray-ledger |
| Generalist audit (business logic, races, chains) | ray-prospector |
| Injection | ray-crucible |
| Identity & access (authn/authz, IDOR/BOLA/BFLA, tenancy) | ray-turnstile |
| Client/server boundary (CORS, CSP, host header, redirect) | ray-seam |
| Abuse & observability (rate limit, exposed endpoints, webhooks) | ray-sentry |
| Datastore & crypto | ray-vault |
| Deployed architecture | ray-citadel |
| Privacy & web surface (TLS, cookies, PII) | ray-custodian |
| Native memory safety | ray-marrow |
| The app's own LLM feature | ray-oracle |
| Dependencies (CVE/SBOM) | ray-manifest |
| IaC / cloud / containers | ray-terrain |
| Maintenance over time (EOL/DR) | ray-steward |
| Dedup / validate / viability | ray-condenser / ray-arbiter / ray-magistrate |
| Reproduce / patch / chain | ray-detonator / ray-anvil / ray-cascade |
| Score / report / learn | ray-gauge / ray-chronicle / ray-retrospective |
| Secret guard & scan | ray-cloak |
| External recon | ray-quarry |
| Live attack+fix | ray-siege (→ ray-reaver, ray-bulwark) |
| Detection & response | ray-warden (→ ray-vigil) |
| Change review | ray-loupe (→ ray-scrivener) |
| Custom harness | ray-foundry / ray-conductor |

## Target profiles

A profile picks the domain skills to run and injects override blocks into the threat
model. `ray-arbiter` reads **Review Overrides** (auto-dismissal rules to suspend);
`ray-gauge` reads **Calibration Overrides** (severity caps to lift). Full text in
`profiles/*.md`.

| Profile | Headline domains | Suspends (so these surface) |
|---|---|---|
| **web-app** | turnstile, crucible, seam, sentry, vault, custodian | CORS, security headers, cookie flags (arbiter r02); rate limit (arbiter r07); dependency-CVE force-LOW (gauge `third_party_reachability`) |
| **native** | marrow, crucible, vault | parser/decoder DoS (arbiter r07) |
| **library** | per-surface + manifest | intrinsic-flaw emphasis (arbiter r08); no "no caller here" down-weight |
| **llm-app** | oracle, turnstile, crucible, sentry, cloak | model-extraction rate limits (r07); probabilistic prompt-injection (gauge `probabilistic_llm`) |

### Why profiles exist

Ray's conservative defaults are correct for a parser in C but wrong for a web SaaS:
they dismiss "missing rate limit" and "open CORS" as hygiene and bury an unproven
dependency CVE at LOW. The `web-app` profile is the opt-in switch that keeps exactly
those in scope — the classes the linked video-guide teaches and that a SaaS owner
most wants to see. A profile never *invents* findings; each still clears the
hunting-doctrine bar. Absent a profile, Ray behaves domain-agnostically, exactly as
its validation stages were originally tuned.

## The video-guide's seven doors → coverage

autenticação → turnstile · autorização/IDOR → turnstile · input/SQLi → crucible +
seam · CORS → seam · secrets/`.env`/git-history → cloak + manifest + ledger · rate
limit → sentry. Run `/ray-conductor --sync --profile=web-app` to cover all seven on
a web SaaS in one pass.
