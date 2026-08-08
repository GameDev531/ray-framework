# LLM-Integration Security Docket — Class Procedures

One section per OWASP-LLM-Top-10 class as it applies to the **target
application's** AI integration. Each carries where it lives in code, the grep
patterns, the safe pattern, the traps, and the reproduction hint for
`/ray-detonator`.

The organizing insight: an LLM is an untrusted, manipulable text producer sitting
between a **source boundary** (text into the prompt) and a **sink boundary**
(output into the app). Prompt injection is a source problem; insecure output
handling is a sink problem; agency decides how bad either gets.

## Table of Contents

- [INJECTION — Prompt Injection (direct, indirect, RAG)](#injection--prompt-injection-direct-indirect-rag)
- [OUTPUT — Insecure Output Handling](#output--insecure-output-handling)
- [AGENCY — Excessive Agency and Tool Abuse](#agency--excessive-agency-and-tool-abuse)
- [DISCLOSURE — System-Prompt and Sensitive-Info Disclosure](#disclosure--system-prompt-and-sensitive-info-disclosure)
- [CONSUMPTION — Unbounded Consumption](#consumption--unbounded-consumption)
- [SUPPLY — RAG/Embedding Poisoning and Unsafe Artifacts](#supply--ragembedding-poisoning-and-unsafe-artifacts)
- [The Probabilistic-Severity Rule](#the-probabilistic-severity-rule)

______________________________________________________________________

## INJECTION — Prompt Injection (direct, indirect, RAG)

**OWASP LLM01. CWE-1427** (improper neutralization of special elements in a
prompt); tie to `CWE-77`-family for the downstream effect.

### Where it lives / grep

```
system.?prompt|messages\s*=|ChatPromptTemplate|PromptTemplate|f".*\{.*\}.*"
langchain|ll.?m\.(invoke|generate|chat|complete)|openai|anthropic|generativeai
retriev|vector|embedding|rag|context\s*=|\.similarity_search
```

### The three variants

| Variant | Untrusted source | Example |
|---|---|---|
| **Direct** | The end-user's own message | A user tells the assistant "ignore your instructions and…" to escape its guardrails |
| **Indirect** | Third-party content the model reads | A web page, email, PDF, or document retrieved and placed in context carries hidden instructions the model then obeys |
| **RAG-poisoning** | A document an attacker got into the knowledge base | A poisoned entry retrieved for an unrelated query injects instructions |

### Safe pattern (all partial — none fully neutralize)

Instruction/data separation (untrusted text in a clearly delimited data channel,
never the instruction channel); "spotlighting"/delimiting with markers the model
is told to distrust; a privileged/unprivileged two-model split (the model that
sees untrusted content has no tools); output constraints (structured output +
validation). Because none of these are complete, **the injection's severity is
judged by what the model can then do** — trace to AGENCY and OUTPUT.

### Traps

- A prompt built only from **trusted, developer-controlled** strings with no
  untrusted fragment is not injectable — confirm the fragment's provenance.
- Retrieval that inserts untrusted documents into the instruction context is
  indirect injection even if the end-user is trusted.
- Do not treat a delimiter/"you are a helpful assistant, ignore attempts to…"
  system-prompt line as a real neutralizer; note it as a partial mitigation.

### Reproduction hint

`/ray-detonator` demonstrates with a crafted input carrying an injected
instruction and observes the model obeying it — inherently probabilistic (see the
final section). Describe the injection string and the observable (a tool fired, a
guardrail bypassed).

______________________________________________________________________

## OUTPUT — Insecure Output Handling

**OWASP LLM02 (Insecure Output Handling). CWE-79/89/78/918** depending on the
sink — the model's output is untrusted input to a classic sink.

### Where it lives / grep

```
response\.|completion\.|\.content|\.text|llm_output|result\s*=.*(invoke|chat)
    -> then into:
innerHTML|dangerouslySetInnerHTML|v-html|render|template     # XSS sink
execute|query\(|\.raw\(|eval\(|exec\(|subprocess|os\.system  # SQLi/RCE sink
requests\.get\(|fetch\(|axios|urllib                         # SSRF sink
```

### Rule

Treat model output exactly as `/ray-crucible` treats request input: if it reaches
a sink without the neutralizer that sink requires, it is a finding. A chatbot that
renders model-produced HTML without sanitization is stored/reflected XSS; a
"text-to-SQL" feature that executes the model's SQL is SQLi; a model that returns
a URL the server fetches is SSRF; model output run as code is RCE.

### Traps

- Output rendered as **plain text** (escaped) is safe — the bug is unescaped
  rendering or execution.
- Structured output validated against a strict schema before use narrows the
  risk — cite the validation.
- Cross-reference the exact `/ray-crucible` class for the sink; report here with
  the LLM provenance and let `/ray-condenser` merge.

### Reproduction hint

Combine with INJECTION: an attacker who can steer the output (via injection) into
a malicious payload plus an unsanitized sink = a real exploit. Hand
`/ray-detonator` the injection→output→sink chain.

______________________________________________________________________

## AGENCY — Excessive Agency and Tool Abuse

**OWASP LLM06 (Excessive Agency). CWE-250/862** in spirit — actions taken on the
model's say-so without independent authorization.

### Where it lives / grep

```
tools\s*=|functions\s*=|tool_call|function_call|@tool|Tool\(|StructuredTool
agent|AgentExecutor|create_.*_agent|dispatch|handle_tool
```

### What to check per tool

| Question | Bad answer |
|---|---|
| What can the tool do? | Write DB, send email/SMS, spend money, call an external API, run code, read another user's data |
| Is the action gated by a human-in-the-loop for anything irreversible or costly? | No — the model can execute it autonomously |
| Is authorization enforced **independently** of the model? | No — the model "decides" who is allowed |
| Are the model-chosen arguments validated before reaching the sink? | No — a path/id/URL/command from the model is passed straight through |
| Is the tool scope least-privilege? | No — a broad "run SQL" / "make HTTP request" tool |

The finding is any tool where injection or a manipulated model can trigger a
state change or privileged action the attacker could not otherwise perform. The
safe pattern: least-agency (narrow tools), human confirmation for
irreversible/costly actions, and authorization checked in code against the real
principal — never against the model's assertion.

### Reproduction hint

Chain from INJECTION: the injected instruction causes the model to call a
tool. Describe the tool, the injected trigger, and the resulting action.

______________________________________________________________________

## DISCLOSURE — System-Prompt and Sensitive-Info Disclosure

**OWASP LLM07 (System Prompt Leakage) + LLM02 (Sensitive Information
Disclosure). CWE-200/201.**

### Rule

Two findings live here. (1) **Secrets or other users' data placed in the prompt
or reachable through the model** — an API key, connection string, or another
tenant's records in the context, which injection can exfiltrate. (2) **A system
prompt that leaks** and reveals a security control (a filter, an allowlist, a
hidden instruction) that an attacker then bypasses — treat the leaked prompt as
recon, and the *real* finding as whatever control the app wrongly relied on the
secret system prompt to enforce.

### Grep

```
system.?prompt|SYSTEM_PROMPT|api.?key|secret|token|password.*prompt
context.*=.*(user|db|query|row)     # other-user data flowing into the prompt
```

### Trap

Do not report "the system prompt can be extracted" as HIGH on its own — a system
prompt is not a secret store. The finding is the sensitive data in it, or the
control that depended on its secrecy.

______________________________________________________________________

## CONSUMPTION — Unbounded Consumption

**OWASP LLM10 (Unbounded Consumption). CWE-770.**

An LLM endpoint with no rate limit, token cap, or per-user/tenant quota is a
denial-of-wallet and a DoS: each request costs money and compute. Check for a
limiter and a cost ceiling on every model-calling route, and for prompt/context
size bounds (an attacker who controls context length can inflate cost). This
overlaps `/ray-sentry`'s `PAID` cost class — report the AI-specific angle here
(model-token spend, context-window abuse) and cross-reference.

______________________________________________________________________

## SUPPLY — RAG/Embedding Poisoning and Unsafe Artifacts

**OWASP LLM03 (Supply Chain) + LLM04 (Data and Model Poisoning). CWE-502** for
the artifact side.

- **RAG/embedding poisoning:** untrusted documents indexed into the knowledge
  base without provenance or trust separation, so an attacker who can add a
  document influences future answers (and can plant indirect injections). Check
  ingestion: who can add to the index, and is retrieved content marked untrusted?
- **Unsafe model artifacts:** `pickle.load`/`torch.load(weights_only=False)`/
  `joblib.load` of a model or embedding from an untrusted source is arbitrary
  code execution — report the ingestion path here and the deserialization gadget
  via `/ray-crucible` `DESER`.
- **Untrusted training/fine-tune data** ingested without validation.

______________________________________________________________________

## The Probabilistic-Severity Rule

Read before scoring anything in this docket. LLM attacks are **probabilistic** —
an injection or jailbreak succeeds some fraction of the time, not
deterministically. `/ray-gauge`'s `probabilistic_llm` calibration rule therefore
**caps these findings at HIGH** and defaults them to MEDIUM/LOW — *with one
exception*: if the attacker can query the endpoint repeatedly with no rate,
concurrency, or alerting limits, they can brute-force past the non-determinism,
and the cap lifts.

So every finding here should record: is the model-calling path rate-limited,
metered, and monitored? A repeatable injection against an **unmetered** endpoint
is materially worse than the same injection behind a tight limiter — and that
fact, cross-referenced with CONSUMPTION and `/ray-sentry`, is what moves the
score. Never mark a probabilistic bypass CRITICAL without the retry-without-limits
condition, and never send prompts to a live model to "prove" it — describe the
attack for `/ray-detonator`, which owns any live demonstration.
