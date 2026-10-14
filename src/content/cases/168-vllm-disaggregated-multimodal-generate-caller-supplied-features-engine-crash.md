---
caseId: "168"
title: "vLLM's /inference/v1/generate route passed caller-supplied multimodal features to the engine without checking them against the renderer's output"
filed: "2026-10-14"
filedDisplay: "14 Oct 2026"
firstObserved: "05 Oct 2026"
severity: low
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "vLLM (all versions before 0.30.0; fixed in 0.30.0)"
cve: "CVE-2026-105754 (GHSA-ph72-cqr5-qpp7, CVSS 3.1 6.5)"
readTime: "3 min read"
related: ["152", "149", "130"]
---

## Summary

In vLLM's scale-out disaggregated multimodal path, the generate route accepted a caller-supplied `features` object and handed it to the engine as though the renderer had produced it. An authenticated caller could forge a single field and crash the shared EngineCore process. The flaw was fixed in vLLM 0.30.0.

## What was observed

The route `POST /inference/v1/generate` accepts a `features` object describing pre-rendered multimodal inputs. The advisory reports that this object was not validated against what the active model's renderer would produce. A render body containing one forged field was sufficient to reach the engine with malformed state.

```
# POST /inference/v1/generate
# body: features = { <one forged field> }     (no comparison with renderer output)
# engine consumes features as trusted
# -> CUDA illegal-memory-access, rank-mismatch ValueError, or hard assert
```

The advisory lists three outcomes. First, denial of service: the forged field could crash the shared EngineCore process through a CUDA illegal-memory-access, a rank-mismatch `ValueError`, or an `assert`, which ends service for every tenant on that engine. Second, encoder-cache keys were not bound to the payload, which the advisory says can expose or corrupt shared encoder state across requests. Third, sparse placeholder masks could be dropped during render-to-generate replay. The advisory's CVSS vector scores availability only (A:H, PR:L); the cache and mask effects are described without a detailed mechanism, and this entry does not characterize them further. The advisory names GHSA-wv77-2vpf-vmmg and GHSA-c65p-x677-fgj6 as distinct multimodal issues.

Severity is rated low here, below the CVSS 6.5 headline, because the route belongs to the scale-out disaggregated deployment mode rather than the default single-server configuration, and the verified impact is loss of availability.

## Mitigation

Upgrade vLLM to 0.30.0 or later. The advisory lists no workarounds. Operators running disaggregated multimodal serving should keep the generate route reachable only from the trusted render tier and not expose it to end-user traffic. An interface designed for a trusted internal hop must either validate its inputs or be unreachable from untrusted callers.
