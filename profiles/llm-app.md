# Target profile: llm-app

For an application whose primary surface is an LLM/agent feature — a chatbot, a RAG
pipeline, a tool-calling agent, an MCP server/client. Selected with
`/ray-conductor --profile=llm-app`.

## Domain skills to run

`ray-prospector` (floor) + `ray-oracle` (the headline: prompt injection, tool
poisoning, excessive agency) + `ray-turnstile` (who can drive the agent) +
`ray-crucible` (model output reaching a sink — insecure output handling) +
`ray-sentry` (rate limits enabling model extraction / cost abuse) + `ray-cloak`
(secrets in prompts/context) + `ray-manifest` (the AI stack's deps).

## Review Overrides (ray-arbiter)

```
Review Overrides:
- IN_SCOPE: rate_limit        # unlimited model queries enabling extraction/cost abuse is in scope (rule 07 exception)
- IN_SCOPE: probabilistic     # do not dismiss a prompt-injection path merely because it is probabilistic; the attacker can retry
```

## Calibration Overrides (ray-gauge)

```
Calibration Overrides:
- LIFT_CAP: probabilistic_llm   # when the attacker can query without rate limits, the probabilistic cap is lifted (as ray-gauge already allows for that case)
```
