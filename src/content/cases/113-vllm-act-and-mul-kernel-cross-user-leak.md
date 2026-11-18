---
caseId: "113"
title: "An integer overflow in vLLM's activation kernel could splice one user's output into another user's response"
filed: "2026-09-11"
filedDisplay: "11 Sep 2026"
firstObserved: "11 Aug 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "vLLM (<0.27.0), act_and_mul_kernel activation kernel under continuous batching"
cve: "CVE-2026-73558 (GHSA-7m6h-x95x-82q5)"
readTime: "4 min read"
related: ["097", "021", "008"]
---

## Summary

vLLM's throughput model depends on continuous batching: requests from potentially unrelated callers are packed into a single batch and run through the model together, then split back into per-request responses afterward. An integer overflow in `act_and_mul_kernel`, the CUDA kernel that computes an activation function over a batch's concatenated hidden states, could corrupt the offset arithmetic used to keep one request's output separate from another's. Under specific request-length and batch-composition conditions, the last request in a batch could receive a partial or complete copy of an earlier user's inference result.

## What was observed

Continuous batching packs pending requests into one forward pass and relies on per-request offsets to know where one caller's slice of the shared output buffer ends and the next begins. `act_and_mul_kernel` computes activation over the concatenated hidden states of every request in the batch, writing each request's result back into its designated slice using that offset arithmetic.

```
# act_and_mul_kernel computes activation over concatenated per-request
# hidden states held in one shared buffer, indexed by per-request offsets
#
# offset arithmetic overflows under certain request-length / batch-size
# combinations -> one request's write lands inside a neighboring
# request's output slice -> that request's response includes data
# computed for a different caller
```

The overflow occurred in the offset computation itself, not in a bounds check that could have caught it, so the kernel had no way to detect the collision — it wrote to whatever address the arithmetic produced. On a shared, multi-tenant inference endpoint, where requests from different callers are routinely batched together for GPU efficiency, this meant one caller's prompt-and-response content could physically land inside another caller's HTTP response body.

## Mitigation

Upgrade to vLLM 0.27.0 or later, which fixes the overflow in the batch-offset arithmetic. This site rates the mechanism medium rather than high: continuous batching is vLLM's default execution path, and cross-tenant response content is exactly the kind of exposure this database usually rates high, but the overflow depends on specific request-length and batch-composition conditions that limit how precisely an attacker can target a chosen victim rather than simply harvesting whatever happens to land next to their own request. Operators running vLLM as a shared inference backend for multiple tenants should treat this as a reminder that batching architectures collapse the request isolation a naive per-request mental model assumes — and should weigh that against any workload where confidentiality between tenants' prompts and completions actually matters.
