---
caseId: "198"
title: "vLLM capped images per item but not per request, so one message with many remote image URLs could exhaust frontend memory"
filed: "2026-11-07"
filedDisplay: "07 Nov 2026"
firstObserved: "02 Nov 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (>=0.6.0, <0.33.0), multimodal request handling on /v1/messages, non-Harmony /v1/responses and equivalent chat-rendering paths"
cve: "No CVE assigned as of writing; tracked as GHSA-5r3c-5x4v-8gjh (CWE-400 / CWE-770, CVSS 3.1 7.5)"
readTime: "3 min read"
related: ["029", "097", "149"]
---

## Summary

vLLM validated the number of images in a request and the limits on each individual item, but enforced no total budget across the whole request. A single request referencing many individually valid remote images caused the frontend to download and decode all of them concurrently before prompt-length checks ran. Version 0.33.0 adds request-wide media resource budgeting.

## What was observed

The advisory, published 02 Nov 2026, describes a missing request-wide media budget. Per-item checks and per-response HTTP size limits were in place, but each applied to one image at a time. Completed downloads accumulated in memory while the remaining ones were still in flight, and the prompt-length check that would have rejected the request ran only after the media had been fetched and decoded.

The advisory states that the aiohttp connection pool limit and the decode worker count bound instantaneous concurrency, not aggregate memory. The affected paths named are `/v1/messages`, the non-Harmony `/v1/responses` path, and equivalent chat-rendering paths.

```
# illustrative request shape, not a working exploit
# one chat message -> content: [ image_url_1, image_url_2, ... image_url_N ]
# each URL passes per-item checks; no check sums the N items
# frontend fetches and decodes all N before the prompt-length check runs
```

The advisory reports that API authentication is optional by default, and that ordinary inference access is sufficient where authentication is enabled. Its proof of concept demonstrates the allocation behavior rather than an actual out-of-memory crash, so the point at which a given host fails was not shown. The reported effect is consumption of frontend memory, CPU, network connections and decoder capacity, with possible termination of the API process or degraded service for other users.

The CVSS 3.1 score is 7.5 (availability only). The mechanism is rated medium here: the impact is limited to availability, requires a deployment serving multimodal input, and the advisory did not demonstrate a crash.

## Mitigation

Upgrade vLLM to 0.33.0 or later. The fix is PR #61226 in the vLLM repository; no separate workaround is listed in the advisory. Until upgraded, require authentication on the API, and enforce a request body and content-array length limit at a gateway in front of the server. Per-item limits do not bound a request; the budget has to be stated for the request as a whole.
