---
caseId: "195"
title: "vLLM keyed shared caches on caller-supplied values, so a forged EXIF ImageID or a cache_salt equal to a LoRA name collided with another request's cache entry"
filed: "2026-11-05"
filedDisplay: "05 Nov 2026"
firstObserved: "20 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "vLLM (<0.31.0, fixed in 0.31.0)"
cve: "CVE-2026-114054 (GHSA-72rf-5fg2-rm98 / upstream GHSA-rh6f-3x46-j33q; CWE-284; CVSS v4 7.1)"
readTime: "3 min read"
related: ["151", "182", "113"]
---

## Summary

vLLM used values supplied by the caller as keys in shared caches. Two collisions were described: a UUID-formatted EXIF ImageID that matched the cache key of another request's processed media, and a `cache_salt` equal to a LoRA name that matched the first-block KV state of another request. Version 0.31.0 fixes the issue. The public records give no detail of the code change, and the root cause is described here only at the level the advisory states it.

## What was observed

The VulnCheck and GitHub records, published 20 and 21 Oct 2026, describe a cache aliasing flaw classified as improper access control (CWE-284). An authenticated caller could force two different requests onto the same cache key by controlling a component of that key.

In the first variant, setting a UUID-formatted EXIF ImageID in an uploaded image allowed the caller to retrieve another request's cached processed media. In the second, setting `cache_salt` to a string equal to a LoRA adapter name allowed reuse of first-block KV state belonging to another request. The advisory text states both outcomes as cross-request reuse.

The records do not name the functions involved, the key-derivation code, or a proof of concept, and the upstream advisory page could not be retrieved during this review. The exact key layout was therefore not independently verified. No in-the-wild exploitation is reported.

The published CVSS v4 vector scores availability impact high and confidentiality and integrity impact none, which does not match the description of one request obtaining another's cached media. The mechanism is rated here by what the description states: reuse of another request's cached data across a boundary the cache was meant to enforce. Severity is rated medium, because exploitation requires an authenticated caller on a shared server and the reachable data is limited to cache entries the attacker can guess or match.

## Mitigation

Upgrade vLLM to 0.31.0 or later; no workaround is listed. On shared servers running earlier versions, treat `cache_salt` as a server-assigned tenant secret rather than a client field, strip client-supplied salt values at the gateway, and keep adapter names out of any value a tenant can set. Cache keys that include caller-chosen strings need a server-side namespace the caller cannot spell.
