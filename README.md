<div align="center">

<img src="banner.png" alt="Ray Framework Banner" width="100%" />

<h1>Ray Framework</h1>

<strong>An agentic, evidence-first security review pipeline built as a set of composable Claude Skills.</strong>

<br />

<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
<a href="#"><img src="https://img.shields.io/badge/Status-Active-success.svg" alt="Status: Active" /></a>
<a href="#"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" /></a>

<br /><br />

<em>Ray decomposes a full security audit&mdash;from mapping a codebase to shipping a stakeholder-facing report&mdash;into independent, single-responsibility stages.</em>

</div>

<hr />

<h2>Why Ray Exists</h2>

<p>Most LLM-driven vulnerability scanners rely on a single prompt asking <em>"is this code vulnerable?"</em>. This approach yields unpredictable false-positive and false-negative rates, essentially acting on the model's disposition.</p>

<p><strong>Ray takes a distinct approach: No single model call serves as the final verdict.</strong></p>

<ul>
  <li><strong>Findings start as guilty, not innocent.</strong> The validation stage assumes every reported anomaly is a false positive. It must be explicitly disproven against the source code to survive.</li>
  <li><strong>A vulnerability is not confirmed until it is reproduced.</strong> Static suspicion triggers a sandboxed proof-of-concept. Authentic execution evidence (e.g., a sanitizer trace, an unauthorized HTTP 200 response, a crash signal) is strictly required.</li>
  <li><strong>Severity is capped, not merely scored.</strong> A rules-based sanity layer mitigates inflated severity by identifying dead code, test-only paths, implausible attacker positions, or missing defense-in-depth measures. A HIGH severity finding represents a validated risk.</li>
  <li><strong>The codebase is frozen mid-audit.</strong> Every execution pass runs against an immutable, content-hashed snapshot. A finding's line numbers, unresolved status, and regression history remain accurate as the repository evolves.</li>
  <li><strong>Nothing is silently discarded.</strong> Ambiguous cases are routed to <code>NEEDS_RESEARCH</code>, ensuring manual review. Regressions are explicitly flagged and tracked.</li>
</ul>

<hr />

<h2>Pipeline Architecture</h2>

<p>Each stage degrades gracefully if surrounding modules are unavailable, ensuring no single point of failure disrupts the campaign.</p>

```mermaid
graph LR
    A[ray-lattice<br/><sub>structural index</sub>] --> B[ray-prism<br/><sub>directory digests</sub>]
    B --> C[ray-blueprint<br/><sub>knowledge base</sub>]
    C --> D[ray-perimeter<br/><sub>threat model</sub>]
    D --> E[ray-compass<br/><sub>review plan</sub>]
    E --> F[ray-prospector<br/><sub>code audit</sub>]
    E --> N[domain audit suite<br/><sub>7 specialized sweeps</sub>]
    F --> G[ray-condenser<br/><sub>dedupe</sub>]
    N --> G
    G --> H[ray-arbiter<br/><sub>adversarial review</sub>]
    H --> I[ray-magistrate<br/><sub>viability judge</sub>]
    I --> J[ray-detonator<br/><sub>PoC + reproduce</sub>]
    J --> K[ray-gauge<br/><sub>risk scoring</sub>]
    K --> L[ray-chronicle<br/><sub>report</sub>]
    F -.-> M[ray-retrospective<br/><sub>learnings</sub>]
    
    classDef default fill:#1a1a24,stroke:#4a4a6a,stroke-width:2px,color:#fff;
    classDef meta fill:#2a1a3a,stroke:#6a4a8a,stroke-width:2px,color:#fff;
    classDef domain fill:#1a2a24,stroke:#4a8a6a,stroke-width:2px,color:#fff;
    class M meta;
    class A meta;
    class N domain;
```

<hr />

<h2>The Skills Suite</h2>

<p>Ray's architecture relies on distinct, isolated skills. Each directory is self-contained with a dedicated <code>SKILL.md</code> documentation file.</p>

<table>
  <thead>
    <tr>
      <th>Skill</th>
      <th>Stage</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong><code>ray-prism</code></strong></td>
      <td>Pre-processing</td>
      <td>Generates bottom-up, security-focused digests of every directory.</td>
    </tr>
    <tr>
      <td><strong><code>ray-blueprint</code></strong></td>
      <td>Knowledge base</td>
      <td>Synthesizes architecture, entities, and data flows into a linked knowledge base.</td>
    </tr>
    <tr>
      <td><strong><code>ray-perimeter</code></strong></td>
      <td>Knowledge base</td>
      <td>Builds the threat model, defining trust boundaries, attacker profiles, and assets.</td>
    </tr>
    <tr>
      <td><strong><code>ray-compass</code></strong></td>
      <td>Planning</td>
      <td>Translates the threat model and history into a targeted investigation roadmap.</td>
    </tr>
    <tr>
      <td><strong><code>ray-prospector</code></strong></td>
      <td>Discovery</td>
      <td>Performs wave-based swarm auditing of source files against the generated plan.</td>
    </tr>
    <tr>
      <td><strong><code>ray-condenser</code></strong></td>
      <td>Consolidation</td>
      <td>Merges duplicate findings across parallel sub-agents and execution passes.</td>
    </tr>
    <tr>
      <td><strong><code>ray-arbiter</code></strong></td>
      <td>Validation</td>
      <td>Assumes every finding is a false positive; actively attempts to disprove findings.</td>
    </tr>
    <tr>
      <td><strong><code>ray-magistrate</code></strong></td>
      <td>Validation</td>
      <td>Judges production viability, filtering out dead code, debug builds, and test-only paths.</td>
    </tr>
    <tr>
      <td><strong><code>ray-detonator</code></strong></td>
      <td>Verification</td>
      <td>Develops and executes sandboxed PoCs, demanding concrete execution evidence.</td>
    </tr>
    <tr>
      <td><strong><code>ray-gauge</code></strong></td>
      <td>Scoring</td>
      <td>Computes the final risk utilizing 27 sanity caps to prevent over-scoring and under-scoring.</td>
    </tr>
    <tr>
      <td><strong><code>ray-chronicle</code></strong></td>
      <td>Reporting</td>
      <td>Produces the finalized, stakeholder-facing Markdown review packet.</td>
    </tr>
    <tr>
      <td><strong><code>ray-retrospective</code></strong></td>
      <td>Meta</td>
      <td>Extracts durable lessons from agent trajectories for future passes.</td>
    </tr>
    <tr>
      <td><strong><code>ray-lattice</code></strong></td>
      <td>Meta (optional)</td>
      <td>Builds an AST-level structural index tailored for grep-scale codebases.</td>
    </tr>
    <tr>
      <td><strong><code>ray-foundry</code></strong></td>
      <td>Meta</td>
      <td>Acts as an interactive consultant for engineering custom orchestrators around Ray.</td>
    </tr>
  </tbody>
</table>

<hr />

<h2>The Domain Audit Suite</h2>

<p>The core pipeline is domain-agnostic: it maps, plans, audits, validates, reproduces, and scores whatever the codebase happens to be. The domain audit suite adds seven specialized discovery stages, each carrying a single security domain's obligation set so the rest of the pipeline does not have to.</p>

<p><strong>They are drop-in siblings of <code>ray-prospector</code>.</strong> Each one writes standard finding JSON to <code>workspace/findings/&lt;uuid&gt;.json</code> — same schema, same <code>signature</code>/<code>lineage_id</code>/<code>discovery_commit</code> rules, same snapshot pinning — so <code>ray-condenser</code> through <code>ray-chronicle</code> consume their output unchanged. They can run in place of, or alongside, the generic audit stage.</p>

<p><strong>Each skill is structured for progressive disclosure.</strong> The <code>SKILL.md</code> carries the workflow and the pointers; the detail lives in <code>references/</code> and is read only when a step calls for it. Every skill ships a <code>findings_contract.md</code> (schema, the four computed fields, CWE set, evidence discipline, severity defaults, ledger format) plus one or more domain dockets. That keeps the always-loaded body around 200&ndash;280 lines while the obligation sets behind it stay as long as they need to be.</p>

<p>Each also writes a <strong>control ledger</strong> to <code>workspace/ledgers/&lt;skill&gt;.json</code>, recording every control that was checked and its state (<code>PRESENT</code>, <code>PARTIAL</code>, <code>ABSENT</code>, <code>NOT_APPLICABLE</code>, <code>UNKNOWN</code>). This is what makes the <em>absence</em> of a finding meaningful: a control marked <code>NOT_APPLICABLE</code> with a stated reason is a documented security decision; a silent omission is not.</p>

<table>
  <thead>
    <tr>
      <th>Skill</th>
      <th>Domain</th>
      <th>Description</th>
      <th>References</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong><code>ray-custodian</code></strong></td>
      <td>Data protection</td>
      <td>Personal-data inventory, TLS and response headers, cookie flags, consent ordering, retention, data-subject rights, and third-party PII egress (LGPD/GDPR).</td>
      <td><code>privacy_docket.md</code><br/><code>web_surface_baseline.md</code><br/><code>findings_contract.md</code></td>
    </tr>
    <tr>
      <td><strong><code>ray-turnstile</code></strong></td>
      <td>SaaS identity &amp; tenancy</td>
      <td>Credential storage, sessions and JWTs, MFA and credential stuffing, recovery flows, IDOR/BOLA/BFLA authorization, tenant isolation, secrets, and races on critical operations.</td>
      <td><code>identity_docket.md</code><br/><code>tenancy_isolation.md</code><br/><code>findings_contract.md</code></td>
    </tr>
    <tr>
      <td><strong><code>ray-crucible</code></strong></td>
      <td>Untrusted input</td>
      <td>Sink-driven sweep of the OWASP canon: injection, XSS, CSRF, SSRF, deserialization, traversal, upload, redirect, prototype pollution, timing, and dependencies.</td>
      <td><code>injection_docket.md</code><br/><code>owasp_mapping.md</code><br/><code>findings_contract.md</code></td>
    </tr>
    <tr>
      <td><strong><code>ray-seam</code></strong></td>
      <td>Client/server trust seam</td>
      <td>Error leakage and fail-open paths, backend validation, mass assignment, CORS, client-side credential storage, bundle secrets, log hygiene, limits, caching, and client-supplied values.</td>
      <td><code>seam_docket.md</code><br/><code>findings_contract.md</code></td>
    </tr>
    <tr>
      <td><strong><code>ray-sentry</code></strong></td>
      <td>Service protection</td>
      <td>Rate limiting by cost class, exposed internal endpoints, service-to-service auth, API key lifecycle, GraphQL limits, webhook signatures, audit logging, and alerting.</td>
      <td><code>service_docket.md</code><br/><code>findings_contract.md</code></td>
    </tr>
    <tr>
      <td><strong><code>ray-vault</code></strong></td>
      <td>Datastore exfiltration</td>
      <td>Database privileges, network reachability, encryption in transit/at rest/at field level, credential sourcing, backups and restore testing, non-production copies, and data-layer auditing.</td>
      <td><code>datastore_hardening.md</code><br/><code>findings_contract.md</code></td>
    </tr>
    <tr>
      <td><strong><code>ray-citadel</code></strong></td>
      <td>Architecture at scale</td>
      <td>Network layering, statelessness, environment isolation, secret topology, pipeline and supply-chain integrity, container and Kubernetes hardening, observability, and incident readiness.</td>
      <td><code>architecture_baseline.md</code><br/><code>findings_contract.md</code></td>
    </tr>
  </tbody>
</table>

<h3>Running a Domain Sweep</h3>

<pre><code>/ray-custodian    # privacy and web-surface exposure
/ray-turnstile    # identity, authorization, tenancy
/ray-crucible     # untrusted-input canon
/ray-seam         # client/server trust boundary
/ray-sentry       # abuse resistance and detection
/ray-vault        # datastore exfiltration barriers
/ray-citadel      # deployed architecture</code></pre>

<p>Run whichever domains the target actually has, then continue into <code>/ray-condenser</code> and the rest of the validation chain exactly as with a generic pass. Domains overlap deliberately at their edges (each <code>SKILL.md</code> ends with a <em>Boundary With Adjacent Skills</em> section); overlapping findings are merged by <code>ray-condenser</code>, never lost.</p>

<hr />

<h2>Design Principles</h2>

<ol>
  <li><strong>Deterministic contracts.</strong> Every skill explicitly declares its read operations, write operations, and idempotency guarantees.</li>
  <li><strong>Snapshot-pinned by default.</strong> Executions run against one frozen, content-hashed repository state, ensuring reproducibility and precise regression tracking.</li>
  <li><strong>Strictly advisory accelerators.</strong> Optional components (such as semantic retrieval or structural indexing) may reorder workloads but cannot authorize the skipping of files or call-sites.</li>
  <li><strong>Fail conservative.</strong> When a stage cannot confidently ascertain a result, it routes to <code>NEEDS_RESEARCH</code>, <code>not_attempted</code>, or <code>UNKNOWN</code>. It never issues a false positive clearance.</li>
  <li><strong>Token-efficient state management.</strong> State resides on disk via UUID-keyed JSON objects. Agents communicate via references rather than transmitting extensive text payloads.</li>
  <li><strong>Coverage is recorded, not implied.</strong> Domain stages write a control ledger listing every control checked and its state. A control that does not apply is marked so, with a reason; the absence of a finding is only meaningful when the check is on record.</li>
</ol>

<hr />

<h2>Multi-AI Integration & Getting Started</h2>

<p>Ray Framework is engineered to be platform-agnostic and works seamlessly across multiple AI agent environments. On Claude Code it installs as a first-class <strong>plugin</strong>; on every other assistant the skills are plain <code>SKILL.md</code> directories you copy into place.</p>

<h3>Install as a Claude Code plugin (recommended)</h3>

<p>The repository ships a <code>.claude-plugin/</code> with a plugin manifest and a marketplace catalog, so the entire framework installs in two commands — no files to copy:</p>

<pre><code>/plugin marketplace add GameDev531/ray-framework
/plugin install ray@ray-framework</code></pre>

<p>All 21 skills register at once and become available as <code>/ray-*</code> commands (and trigger automatically by description). Update later with <code>/plugin marketplace update ray-framework</code>. The always-on cost is deliberately small — each skill's <code>SKILL.md</code> body is a lean workflow, and its detailed reference dockets load only when the skill is invoked.</p>

<h3>Manual install (Gemini, Codex, Cursor, Antigravity, or Claude without the plugin)</h3>

<p>Copy or symlink the required <code>ray-*</code> skill directories into the corresponding configuration folder of your chosen assistant:</p>

<ul>
  <li><strong>Claude:</strong> <code>.claude/skills/</code> within your workspace (or <code>~/.claude/skills/</code> for every project).</li>
  <li><strong>Antigravity:</strong> <code>.agents/skills/</code> at your project root (the Agent Skills standard — same <code>SKILL.md</code> format, no changes needed).</li>
  <li><strong>Gemini:</strong> <code>.gemini/skills/</code>.</li>
  <li><strong>Codex / OpenAI:</strong> <code>.codex/skills/</code>.</li>
  <li><strong>Cursor:</strong> <code>.cursor/rules/</code>, so they are ingested as repository rules.</li>
</ul>

<p>Empty template directories for several of these platforms are already included at the root of this repository (<code>.claude</code>, <code>.gemini</code>, <code>.codex</code>, <code>.cursor</code>) to serve as structural references.</p>

<hr />

<h3>Executing a Pass</h3>

<p>Once the skills are integrated into your AI environment's context, a minimal execution pass requires invoking them in the following sequence:</p>

<pre><code>/ray-prism        # Generate repository map
/ray-blueprint    # Synthesize the knowledge base
/ray-perimeter    # Construct the threat model
/ray-compass      # Generate workspace/plan.json
/ray-prospector   # Execute audit and populate workspace/findings/*.json
                  # (optionally add domain sweeps here: /ray-custodian, /ray-turnstile,
                  #  /ray-crucible, /ray-seam, /ray-sentry, /ray-vault, /ray-citadel)
/ray-condenser    # Deduplicate findings
/ray-arbiter      # Validate findings
/ray-magistrate   # Assess production viability
/ray-detonator    # Reproduce sandbox environments
/ray-gauge        # Calculate risk scores
/ray-chronicle    # Assemble final report</code></pre>

<blockquote>
  <p><strong>Note:</strong> For continuous integration on a living codebase or when building a custom orchestrator, it is highly recommended to start with <code>ray-foundry</code>. It provides comprehensive guidance on the Pass Lifecycle Contract (sync, pin, run, archive) and optional extensions.</p>
</blockquote>

<hr />

<h2>Status</h2>

<ul>
  <li><strong>Packaging:</strong> Installs as a Claude Code plugin (<code>ray@ray-framework</code>) via the bundled <code>.claude-plugin/</code> marketplace; validated with <code>claude plugin validate --strict</code>, all 21 skills load.</li>
  <li><strong>Core Pipeline:</strong> 14 skills are fully implemented and internally consistent.</li>
  <li><strong>Domain Audit Suite:</strong> 7 skills (<code>ray-custodian</code>, <code>ray-turnstile</code>, <code>ray-crucible</code>, <code>ray-seam</code>, <code>ray-sentry</code>, <code>ray-vault</code>, <code>ray-citadel</code>) implemented against the shared findings contract, each with a <code>references/</code> directory holding its findings contract and domain dockets.</li>
  <li><strong>Pending Components:</strong> Patch generation (<code>ray-anvil</code>), exploit chaining (<code>ray-cascade</code>), VCS history extraction (<code>ray-ledger</code>), and the reference orchestrator (<code>ray-conductor</code>). Contributions for these components are welcome.</li>
</ul>

<h2>License</h2>

<p><a href="LICENSE">MIT License</a></p>
