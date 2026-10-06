---
caseId: "151"
title: "vLLM Harmony tool continuations rebuilt engine input without cache_salt, placing follow-up prefixes in the shared unsalted cache namespace"
filed: "2026-10-06"
filedDisplay: "06 Oct 2026"
firstObserved: "28 Sep 2026"
severity: low
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "vLLM (<= 0.25.1, fixed in 0.30.0), GPT-OSS Harmony /v1/responses endpoint with prefix caching and a tool server enabled"
cve: "CVE-2026-105752 (GHSA-935w-9g4m-p28p)"
readTime: "3 min read"
related: ["113", "149", "097"]
---

## Summary

vLLM's per-tenant `cache_salt` isolates prefix-cache entries between users of a shared deployment. On the Harmony `/v1/responses` path, the first turn of a request carried the salt but the tool-continuation re-submission did not, so the post-tool prefix was cached in the unsalted namespace. An authenticated tenant could then infer whether a guessed prompt had been processed by another tenant. The exposure is a cache-hit timing and token-count signal, not direct content disclosure.

## What was observed

The GitHub advisory GHSA-935w-9g4m-p28p was published on 28 Sep 2026 and last updated on 06 Oct 2026. It is classed as CWE-200 and CWE-524 with a CVSS v3.1 score of 3.1 (AV:N/AC:H/PR:L). Versions up to 0.25.1 were confirmed affected, and the fix shipped in vLLM 0.30.0.

According to the advisory, turn 1 of a Harmony request passed `request.cache_salt` into the engine input correctly. When a tool call completed and the server re-submitted the conversation to continue generation, `vllm/entrypoints/openai/responses/serving.py` rebuilt the engine input with `tokens_input(token_ids)` and no salt argument. Prefix-cache blocks created by that continuation were therefore keyed without the tenant's salt and shared across all callers.

```
# Illustrative, vLLM <= 0.25.1, Harmony /v1/responses, prefix caching on
# turn 1:        tokens_input(ids, cache_salt=request.cache_salt)   # isolated
# continuation:  tokens_input(token_ids)                            # salt dropped
# attacker replays a guessed post-tool history and reads cached-token counts
```

Exploitation had several preconditions: a shared deployment serving a Harmony model, prefix caching enabled (the default), a built-in or MCP tool server enabled by the operator, a victim that sets `cache_salt` and triggers a continuation, and an attacker able to reconstruct the post-tool history accurately enough to match. The attacker observed whether the cached-token count of a guessed prompt was non-zero. The advisory reports the reporters as KernelClint and dhalf and records discovery via GPT-5.5-Cyber under the Patch the Planet initiative.

The rubric rating is low and agrees with the CVSS headline: the signal is a boolean about prompt presence, requires an authenticated position, and depends on an exact reconstruction of tool output.

## Mitigation

Upgrade vLLM to 0.30.0 or later. The advisory's fix threads the originating request through `HarmonyContext` so the continuation call passes `cache_salt=context.request.cache_salt`. Until upgraded, deployments that expose tool servers to multiple tenants can disable prefix caching on the Harmony path or run separate instances per trust boundary.

A cache isolation key that is applied on one code path and not its sibling provides isolation only for the paths that remember it.
