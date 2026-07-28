---
caseId: "035"
title: "Open WebUI's Ollama proxy checked model access on one endpoint and forgot the other four"
filed: "2026-07-28"
filedDisplay: "28 Jul 2026"
firstObserved: "05 May 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Open WebUI (<=0.8.12; fixed in 0.9.0), Ollama proxy endpoints /api/generate, /api/embed, /api/embeddings, /api/show"
cve: "CVE-2026-44563"
readTime: "4 min read"
related: ["030", "008", "013"]
---

## Summary

Open WebUI lets administrators restrict which users can reach which Ollama models — a common control in shared deployments where a large, expensive model should stay limited to one team. That restriction was enforced on the main chat endpoint but never implemented on four other Ollama proxy routes, which forwarded any authenticated user's request to any model by name with no access check at all. Any logged-in user who knew or guessed a restricted model's name could query it directly.

## What was observed

Open WebUI's `/ollama/api/chat` route is the one most users interact with through the UI, and it correctly checks `AccessGrants.has_access()` before proxying a request to Ollama — a user without a grant for a given model gets a 403. Four sibling routes that exist for the same backend — `generate`, `embed`, `embeddings`, and `show` — required only that the caller be an authenticated, non-pending user, and validated the requested model name against the full unfiltered model list rather than the caller's own access grants.

```
# /api/chat  — checks AccessGrants.has_access(user, model) → 403 if absent
# /api/generate, /api/embed, /api/embeddings, /api/show
#   — checks only that the model name exists at all, not who can use it
```

That gap meant model-level access control was enforced only for the chat window, not for the backend it sits on top of. A user restricted to a small model in the UI could call `/api/generate` directly with the name of a model reserved for another group and get a completion back. `/api/show` was the more sensitive route of the four: it returned a restricted model's full configuration, including its system prompt, parameters, and template — information an organization may have specifically wanted to keep out of a lower-privilege group's hands, independent of whether that group could run the model at all. `/api/embed` and `/api/embeddings` allowed unauthorized use of restricted embedding models, which matters for cost and capacity in shared GPU deployments as much as for confidentiality.

The vendor's own CVSS scoring (3.1, base score 5.4, "moderate") reflects that this requires an authenticated account already inside the deployment, and that the impact is bounded by the Ollama access-control boundary rather than crossing into another tenant's data outright. That scoring holds up: this is a real gap in a control administrators believe they've turned on, but it's confined to organizations that both run Ollama as a backend and have deliberately configured per-model restrictions — not a default-open misconfiguration reachable by an anonymous caller.

## Mitigation

Upgrade to Open WebUI 0.9.0 or later, which extends the access-grant check to all four previously unprotected endpoints. If your deployment uses Ollama model access control, audit for any restricted model whose name could be guessed or discovered by users outside its intended group, and treat the pre-patch period as one where that restriction may not have held on anything but the chat UI. More generally, when a platform proxies the same backend resource through multiple routes, verify that an authorization check added to one route was actually propagated to all of them — a security control implemented once and assumed to cover every path to the same resource is the recurring failure mode here, not the access-control design itself.
