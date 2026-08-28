# Oracle Docket — oracle

Vulnerable→safe patterns for `ray-oracle`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## Prompt injection (direct & indirect) — LLM01:2025 · ATLAS
- **Broken:** untrusted text (user input, a retrieved doc, a tool result, a fetched
  page) concatenated into the prompt with no separation, able to override the system
  instructions or exfiltrate the context.
- **Safe:** untrusted content clearly delimited and treated as data; least-privilege
  system prompt; output-side guards; not relying on "please ignore injections".

## Insecure output handling — LLM02:2025
- **Broken:** model output rendered as raw HTML (XSS), passed to `exec`/a shell, used
  to build a SQL query, or auto-followed as a URL, without validation.
- **Safe:** model output escaped/validated for its sink exactly like any untrusted
  input (hand off to ray-crucible's sink rules).

## Excessive agency — LLM06:2025
- **Broken:** the agent can call destructive/high-privilege tools (delete, pay, email,
  shell) with no human-in-the-loop and no per-action scoping; one compromised prompt
  reaches every tool.
- **Safe:** tools scoped and least-privilege; confirmation/allow-list on destructive
  actions; the agent's authority bounded per request.

## MCP / tool poisoning — LLM07:2025 (supply chain of tools)
- **Broken:** tool definitions or MCP server descriptions (untrusted) injected into the
  prompt; a malicious tool result steering later calls; unpinned/unverified MCP servers.
- **Safe:** tool metadata treated as untrusted; pinned/verified tool sources; tool
  results validated before they influence actions.

## Sensitive-info disclosure / extraction — LLM02/LLM06
- **Broken:** system prompt or other users' data recoverable via crafted queries; the
  model echoes secrets placed in its context; no rate limit enabling model extraction
  (→ ray-sentry).
- **Safe:** secrets kept out of the model context; per-user context isolation; output
  filtering.

## What is NOT a finding here

- Model non-determinism alone (probabilistic behavior is capped, not zero — see
  ray-gauge's `probabilistic_llm` rule) unless the attacker can retry without limit.
- A codebase that merely CALLS a third-party AI API with no untrusted content entering
  the prompt and no action driven by output.
- Prompt-injection resistance that is genuinely enforced by an output-side control.
