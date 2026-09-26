---
caseId: "137"
title: "vLLM's sparse-tensor guard for prompt embeddings was a process-global flag, and two parts of one request could race it off"
filed: "2026-09-26"
filedDisplay: "26 Sep 2026"
firstObserved: "04 Sep 2026"
severity: low
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (>=0.20.2rc0, <0.26.0), OpenAI-compatible server started with --enable-prompt-embeds"
cve: "CVE-2026-73557 (GHSA-pr7f-p5mw-fc87); incomplete fix for CVE-2025-62164"
readTime: "4 min read"
related: ["097", "127"]
---

## Summary

vLLM's defense against CVE-2025-62164 — malformed sparse tensors smuggled in as serialized prompt embeddings — relied on PyTorch's `torch.sparse.check_sparse_tensor_invariants()` context manager. That context manager saves, enables, and restores a process-global flag rather than a per-call one. A later chat feature began resolving multiple prompt-embedding parts from a single `/v1/chat/completions` request concurrently, so one part's guard could switch invariant checking off while another part was still being loaded. An invalid sparse tensor then reached the same `to_dense()` sink the original fix was meant to protect. Fixed in 0.26.0.

## What was observed

Prompt embeddings let a client submit pre-computed embedding tensors instead of text tokens. After CVE-2025-62164, vLLM's `safe_load_prompt_embeds` in `vllm/renderers/embed_utils.py` wrapped deserialization and dense conversion inside `check_sparse_tensor_invariants()`, so a tensor whose indices fell outside its declared shape would be rejected at load time rather than written out of bounds during densification.

The guard was correct for one tensor at a time. It was not correct for two. Chat requests route multimodal and embedding parts through `AsyncMultiModalItemTracker.resolve_items`, which gathers them with `asyncio.gather` onto the event loop's default thread-pool executor. Each part entered its own invariant-checking context, but all contexts toggled the same global PyTorch state. When a benign part finished first, its context exit restored the flag to `False` — while a second, malicious part in the same request was still inside what it believed was a guarded region.

```
# one request, two prompt_embeds parts, resolved on separate executor threads
# thread A (benign):    enter guard -> flag=True ... load ok ... exit -> flag=False
# thread B (malicious): enter guard -> flag=True ...      (A exits) ... torch.load()
#                       -> invariants not checked; indices [[10],[10]] accepted for shape [3,3]
#                       -> to_dense() reached with an invalid tensor
```

The reporter reproduced the sequence deterministically against the affected revision on PyTorch 2.11.0: the same loader rejected the malformed payload when submitted alone, then accepted it when paired with a benign part scheduled on a different executor thread. The run stopped at the `to_dense()` call, so crash and memory-corruption consequences were inherited from the original CVE's documented behavior rather than re-demonstrated; remote code execution was neither tested nor claimed.

Exposure was narrow. The trigger required `--enable-prompt-embeds`, which is off by default. It did not require multiple renderer workers, a multimodal model, or `--enable-mm-embeds`, and the stock server installs authentication middleware only when an API key is configured, so an enabled endpoint without a key was reachable by any network client. The GitHub advisory rated the issue moderate (CVSS 3.1 5.3, availability only); this file rates it low because the vulnerable path sits behind a non-default flag.

## Mitigation

Upgrade to vLLM 0.26.0 or later. Deployments that cannot upgrade should leave `--enable-prompt-embeds` off unless a workload requires it, and should never expose an embeddings-enabled server without an API key. The broader lesson concerns remediation that borrows a library's safety context: a guard implemented as save-enable-restore over global state is a lock with no mutual exclusion, and it holds only until the surrounding code becomes concurrent. When a fix depends on a flag, the review question is who else can flip it.
