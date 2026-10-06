---
caseId: "152"
title: "vLLM mirrored multimodal processor caches desynchronized after a rejected request, turning later requests with the same media hash into engine assertion failures"
filed: "2026-10-06"
filedDisplay: "06 Oct 2026"
firstObserved: "28 Sep 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (<= 0.25.1, fixed in 0.28.0), multimodal serving with default mm_processor_cache_type=\"lru\""
cve: "CVE-2026-105753 (GHSA-ph3r-5jfg-f84f)"
readTime: "3 min read"
related: ["097", "149", "117"]
---

## Summary

vLLM's default multimodal processor keeps two mirrored caches, one in the frontend process (P0) and one in the engine process (P1), and assumes both update in lockstep on every request. A request rejected after media rendering but before reaching the engine broke that invariant. Later requests reusing the same media hash then triggered an assertion in the engine preprocessing loop. The result is availability loss for a remote client with ordinary API access; no data disclosure or code execution is involved.

## What was observed

The GitHub advisory GHSA-ph3r-5jfg-f84f was published on 28 Sep 2026 and reviewed on 06 Oct 2026. It is classed as CWE-617 (reachable assertion) with a CVSS v3.1 score of 6.5 (AV:N/AC:L/PR:L, availability high). Versions up to 0.25.1 were confirmed affected, and the fix shipped in 0.28.0.

According to the advisory, P0 committed cache metadata for a media item during rendering. If the request was then rejected by a later admission check, for example a `max_model_len` validation, P1 never received the payload. A subsequent request carrying the same media hash led P0 to return the item as `None`, treating it as already cached, while P1 had no stored item and failed with `Expected a cached item for {mm_hash=}`.

```
# Illustrative, vLLM <= 0.25.1, mm_processor_cache_type="lru"
# req A: media M renders (P0 records hash)  -> rejected by length check (P1 never stores M)
# req B: media M, same hash                 -> P0 sends None, P1 asserts, request fails
```

Only the default `lru` mirrored cache was affected. The advisory states that the `processor_only` and `shm` modes and a disabled cache were not. An attacker who could submit a request that passes rendering and fails admission could poison the hash for identical later requests, including those of other users submitting the same media.

The rubric rating is medium: the configuration is the default and the trigger is reachable with low privileges, but the impact is limited to availability of the affected requests.

## Mitigation

Upgrade vLLM to 0.28.0 or later. Where an upgrade is delayed, switch the multimodal processor cache to `processor_only` or `shm`, and reject over-length or otherwise inadmissible requests before multimodal rendering begins.

State mirrored across processes needs a commit step that both sides agree on, not an update on the first side to see the request.
