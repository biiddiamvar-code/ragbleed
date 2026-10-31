---
caseId: "189"
title: "vLLM let a request choose the processor code revision imported under trust_remote_code"
filed: "2026-10-31"
filedDisplay: "31 Oct 2026"
firstObserved: "06 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "vLLM (>=0.7.3, <0.31.0), multimodal requests with trust_remote_code enabled"
cve: "CVE-2026-114053 (GHSA-h3rc-6mm3-gc2m, CWE-829, CWE-94)"
readTime: "4 min read"
related: ["116", "026", "188"]
---

## Summary

vLLM accepted a client-supplied `mm_processor_kwargs` object on multimodal requests and forwarded it to the Hugging Face processor loader without reserving the `code_revision` key. On servers started with `trust_remote_code` and serving a model whose processor uses dynamic `auto_map` code, a request could select which revision of the processor repository was imported. The import executed Python in the API or renderer process. The fix shipped in vLLM 0.31.0.

## What was observed

The advisory GHSA-h3rc-6mm3-gc2m, published 6 Oct 2026 and recorded as CVE-2026-114053 on 21 Oct 2026, describes request-supplied processor kwargs that were not separated from processor-construction arguments. The value travelled through the renderer, the kwarg-merging code, and the processor cache, and reached `AutoProcessor.from_pretrained`. There it controlled which revision of the dynamic module Transformers loaded. The operator-pinned model revision stayed unchanged, while the executed processor code could come from a different revision of the same repository.

Two entry points were named: `TokenizeChatRequest.mm_processor_kwargs` on `/tokenize`, and `ChatCompletionRequest.mm_processor_kwargs` on chat completions. The `/tokenize` route sits outside vLLM's authentication middleware, so it remained reachable without a key even when `--api-key` was set, unless a proxy protected it.

```
# Request shape (illustrative, no payload)
# POST /tokenize
# { "messages": [ ... multimodal content ... ],
#   "mm_processor_kwargs": { "code_revision": "<other revision of the model repo>" } }
# trust_remote_code on + dynamic auto_map processor -> that revision's module is imported
```

Severity is rated medium, below the CVSS 4.0 score of 9.2 the CNA assigned. The advisory text suggests 9.8 while its own CVSS panel shows 8.1 with high attack complexity. The precondition is an operator opt-in (`trust_remote_code`) combined with a model that ships dynamic processor code, and the attacker needs a second, attacker-influenced revision to exist in the model's repository. The default setting, `trust_remote_code=False`, was not affected. Where those preconditions hold, the outcome is arbitrary code execution as the serving process, with no authentication on `/tokenize`.

## Mitigation

Upgrade vLLM to 0.31.0 or later. Where an upgrade is delayed, disable `trust_remote_code`, or place `/tokenize` and the chat endpoints behind an authenticating proxy. The advisory recommends allowlisting request-time preprocessing controls, rejecting loader controls such as `code_revision` in request kwargs, and pinning the processor-code revision to the server's configured value. Request fields that reach a loader constructor have to be treated as loader configuration, not as request data.
