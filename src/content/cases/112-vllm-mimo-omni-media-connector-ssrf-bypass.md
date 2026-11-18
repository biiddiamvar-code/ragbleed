---
caseId: "112"
title: "vLLM's MiMo-V2-Omni multimodal processor bypassed three rounds of SSRF hardening"
filed: "2026-09-11"
filedDisplay: "11 Sep 2026"
firstObserved: "08 Sep 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "vLLM (<0.26.0), MiMo-V2-Omni multimodal processor (vllm/transformers_utils/processors/mimo_v2_omni.py)"
cve: "CVE-2026-73560 (GHSA-4hhp-h66f-j5j7)"
readTime: "4 min read"
related: ["021", "097", "027"]
---

## Summary

vLLM centralizes image and audio fetching for multimodal models in a `MediaConnector` class, which enforces a URL-scheme allowlist, a network-target allowlist, a download size cap, and a restriction on which local paths can be read. Those protections exist because vLLM had already shipped SSRF and arbitrary-file-read bugs in this exact area, across three prior advisories. The processor written for the MiMo-V2-Omni model family didn't call into `MediaConnector`. It fetched images and audio directly, none of the accumulated hardening applied, and the result was the same SSRF and local-file-read primitive the earlier advisories had already fixed elsewhere in the codebase.

## What was observed

When a caller attached an image, audio, or video payload to a request through vLLM's standard `multi_modal_data` field, a request destined for a MiMo-V2-Omni model was routed to `vllm/transformers_utils/processors/mimo_v2_omni.py` instead of the hardened `MediaConnector` path. That processor's `_fetch_image` handler and its companion audio loader took the raw URL or local-path string straight from the request and dispatched it:

```
# MediaConnector.load_from_url() / load_from_url_async():
#   validates URL scheme, resolves and checks the target host
#   against an allowlist, enforces a download size cap, restricts
#   local paths to allowed_local_media_path
#
# mimo_v2_omni.py _fetch_image() / audio loader:
#   requests.get(user_supplied_url) directly
#   Image.open(user_supplied_local_path) directly
#   none of the above checks applied
```

Any caller able to submit an inference request against a MiMo-V2-Omni deployment could point the image or audio field at an internal address — a cloud metadata endpoint, an internal admin service, a loopback port — and have the fetched content reflected back through the model's handling of it, or point it at a local file path and have vLLM read arbitrary files off the host's disk. The advisory describes this explicitly as the same bug class as three earlier MediaConnector advisories, reintroduced because a new model-specific processor shipped with its own fetch logic instead of routing through the already-hardened shared code path.

## Mitigation

Upgrade to vLLM 0.26.0 or later, which rewires the MiMo-V2-Omni processor to use `MediaConnector` like every other multimodal model in the codebase. This site rates the mechanism medium rather than higher: exploitation requires a deployment actually serving the MiMo-V2-Omni model family, which narrows it below a default-config, any-multimodal-model bug, even though it is trivial to trigger once that condition holds. The structural lesson repeats a pattern seen elsewhere in this database — centralizing a security control in one class only works if every new code path is actually routed through it. Three advisories had already established what safe media fetching looks like here; none of that protection was structural enough to stop a fourth code path from skipping it entirely. Projects that maintain a hardened fetch helper should audit new code for direct `requests.get()` or file-open calls on user input, rather than assuming the helper's existence means it's being used.
