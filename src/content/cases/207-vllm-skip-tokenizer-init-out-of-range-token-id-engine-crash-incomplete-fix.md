---
caseId: "207"
title: "vLLM's vocabulary check on prompt token IDs returned early when no tokenizer was loaded, so one out-of-range ID under --skip-tokenizer-init killed the engine"
filed: "2026-11-11"
filedDisplay: "11 Nov 2026"
firstObserved: "21 Oct 2026"
severity: low
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (>=0.28.0, <0.33.0), only when started with --skip-tokenizer-init"
cve: "No CVE assigned as of writing; tracked as GHSA-q9v9-qpjp-fc24 (CWE-20 / CWE-1284, CVSS 3.1 7.5); incomplete fix for CVE-2026-93592 (GHSA-25q3-v2hm-8vpf)"
readTime: "3 min read"
related: ["149", "168", "198"]
---

## Summary

vLLM 0.28.0 added a vocabulary-range check on client-supplied prompt token IDs as the fix for GHSA-25q3-v2hm-8vpf, covered in case 149. The check ran only when a tokenizer was loaded. Servers started with `--skip-tokenizer-init` have none, so a large positive token ID passed request validation, raised an index error in the model forward pass, and terminated the engine for every client. Version 0.33.0 enforces the bound from the model's vocabulary size when no tokenizer is present.

## What was observed

The fix was opened publicly as pull request #62911 on 21 Oct 2026 and merged on 22 Oct 2026. GitHub advisory GHSA-q9v9-qpjp-fc24 followed on 02 Nov 2026, describing the issue as an incomplete fix of GHSA-25q3-v2hm-8vpf. The reporter was credited as Chocolatine75. Affected versions were 0.28.0 up to, but not including, 0.33.0.

Per the advisory, the request schema for the `/v1/completions` `prompt` field enforced only a lower bound (`ge=0`), the half of the check that the earlier fix had added. The upper bound against the vocabulary lived in the input validator, and that validator returned early when the tokenizer was absent. The ID therefore reached the embedding lookup unchecked. The resulting exception propagated out of the engine step through a busy loop with no per-step guard, and the engine-core process treated it as fatal and signalled the API server that the engine was dead.

```
# Illustrative, vLLM 0.28.0-0.32.x started with --skip-tokenizer-init
POST /v1/completions  {"model": "<m>", "prompt": [999999]}
  -> schema: id >= 0                    # passes
  -> vocab check: no tokenizer, return  # skipped
  -> embedding lookup: index error -> EngineCore fatal -> server down
```

The advisory lists `/v1/embeddings` and `/pooling` as reachable by the same path when the tokenizer is disabled. No authentication or user interaction was required. The configuration is used for pre-tokenized, token-in-token-out and reinforcement-learning rollout serving, not for typical chat or RAG deployments that tokenize server-side.

The rubric rating is low rather than the advisory's High: the flaw exposes no data, recovers on restart, and is reachable only under a non-default flag.

## Mitigation

Upgrade vLLM to 0.33.0 or later. Where that is not immediately possible, keep `--skip-tokenizer-init` deployments off untrusted networks, reject token IDs at or above the model's vocabulary size at a gateway, and run the server under a supervisor that restarts it on engine death.

A validation fix that is conditional on an optional component inherits that component's absence. The earlier advisory closed the negative-index path; this one shows the bound had been attached to the tokenizer rather than to the embedding table it protects.
