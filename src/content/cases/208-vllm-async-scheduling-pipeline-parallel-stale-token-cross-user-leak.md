---
caseId: "208"
title: "vLLM's non-last pipeline ranks never wrote generated tokens back under async scheduling, so a batch slot's previous occupant fed into the next user's KV cache"
filed: "2026-11-16"
filedDisplay: "16 Nov 2026"
firstObserved: "03 Apr 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "vLLM (>=0.16.0, <0.21.0), V1 model runner with async scheduling and pipeline_parallel_size > 1"
cve: "No CVE assigned as of writing; tracked as GHSA-v97p-wpxp-px84 (CVSS 3.1 4.8)"
readTime: "4 min read"
related: ["182", "207"]
---

## Summary

In vLLM's V1 model runner, pipeline-parallel ranks other than the last did not record generated tokens in their CPU-side token buffer when async scheduling was enabled, and reset the per-request token count on every step. When a batch fell back to reading that buffer, it read token IDs left behind by whichever request had previously held the same batch slot. Those stale tokens were run through the model and written into the KV cache of the current request, so fragments of one user's context could shape or appear in another user's output. Version 0.21.0 corrects the bookkeeping.

## What was observed

The behaviour was first reported publicly as issue #38903 on 03 Apr 2026, titled as cross-request context contamination with async scheduling and pipeline parallelism on a multi-node H100 deployment. A fix, pull request #41133, was opened on 28 Apr 2026 and merged on 06 May 2026; it framed the defect as token loss degrading accuracy under concurrency, measuring GSM8K strict-match accuracy of 0.832 with two pipeline stages and 256 concurrent requests against 0.874 with tensor parallelism, and no drop with async scheduling disabled. GitHub advisory GHSA-v97p-wpxp-px84 followed on 09 Nov 2026, reclassifying the same defect as cross-user data leakage. It credits agis09 and jperezdealgaba.

Per the advisory and the fix, two pieces of per-request state diverged on non-last ranks. `token_ids_cpu`, the host-side buffer holding each slot's token sequence, was never written with newly generated tokens, because under async scheduling those tokens arrive only at the last rank. `num_tokens_no_spec` was overwritten each step in `_update_states` with `num_computed_tokens`, which during chunked prefill is smaller than the true prompt length. The correct update existed in `_bookkeeping_sync`, but that path ran only without pipeline parallelism or on the last rank.

```
# Illustrative, vLLM 0.16.0-0.20.x, PP > 1, async scheduling on
# slot 7: request A (user 1) finishes; its tokens remain in token_ids_cpu[7]
# slot 7: request B (user 2) is scheduled; non-last rank never writes B's new tokens
# mixed prefill/decode batch -> fallback reads token_ids_cpu[7]
#   -> A's stale token IDs become B's model input -> written into B's KV cache
```

Once the stale tokens were in the KV cache, every later token of the affected response was conditioned on them. The contamination was therefore not a transient output glitch but persisted for the remainder of that request. The leaked material was fragmentary and its selection was not attacker-controlled: an outside user could not choose whose context they received, only be scheduled into a slot after someone else.

The rating is medium. The data at risk is other tenants' prompt and output content, but reaching it required a non-default deployment shape, pipeline parallelism across ranks combined with async scheduling, and the leak was opportunistic rather than directed. That shape is common in large multi-node serving, which is where multi-tenant traffic is most concentrated.

## Mitigation

Upgrade vLLM to 0.21.0 or later. On affected versions, either launch with `--no-async-scheduling` or set `pipeline_parallel_size=1`; the advisory lists both as sufficient. Operators who ran an affected configuration for multi-tenant traffic should treat responses served during that period as potentially containing other users' content when assessing exposure of logged outputs.

The fix shipped six months before the advisory, filed as an accuracy regression. A benchmark score that drops only under concurrency is a cross-request state bug until shown otherwise, and in a shared inference server a cross-request state bug is a confidentiality bug.
