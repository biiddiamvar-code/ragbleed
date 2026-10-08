---
caseId: "156"
title: "Open WebUI let authenticated users choose any configured Ollama backend through an unchecked url_idx path parameter"
filed: "2026-10-08"
filedDisplay: "08 Oct 2026"
firstObserved: "17 Jun 2026"
severity: low
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Open WebUI (pip package, all versions before 0.9.6), index-addressed Ollama proxy routes"
cve: "CVE-2026-54021 (GHSA-9rpj-v7hf-vv2w, PYSEC-2026-2718, CVSS 3.1 6.3)"
readTime: "3 min read"
related: ["035", "073", "079"]
---

## Summary

Several Open WebUI proxy routes for Ollama took a caller-supplied `url_idx` path parameter and used it directly as an index into the administrator's `OLLAMA_BASE_URLS` list. The access check confirmed that the user could use the requested model but never checked which backend received the request. Any authenticated user could therefore direct requests to backends they were not meant to reach.

## What was observed

The advisory was published on 17 Jun 2026 and updated on 20 Jul 2026. The weakness is classified as CWE-863, incorrect authorization.

Open WebUI supports multiple Ollama backends, configured as an ordered list of base URLs. The index-addressed routes let a client name a backend by its position in that list. Authorization on these routes was model-scoped: the handler verified access to the model named in the request and then forwarded the call to whichever backend the index selected. The two decisions were never joined, so the index acted as an unauthenticated selector over the admin-configured list.

```
# Illustrative
# authenticated low-privilege user
# request: index-addressed Ollama route with url_idx = <position of a restricted backend>
# model access check passes (model is permitted) -> request forwarded to the selected backend
```

The advisory names three target classes: internal backends, higher-privilege backends, and backends an administrator had explicitly disabled. A disabled backend remained reachable by position because the route read the raw list rather than the set of enabled connections.

The rubric rating is low, which is below the vendor's medium CVSS score. The flaw requires a valid account and a deployment with more than one Ollama backend, and the advisory describes no direct data disclosure beyond the reach of the selected backend.

## Mitigation

Upgrade to Open WebUI 0.9.6 or later. Deployments that run multiple Ollama backends with different trust levels should not rely on the application list order as a boundary and should restrict network access to the privileged backends at the infrastructure level.

An authorization check that validates the object a request names while ignoring the destination it is routed to leaves the destination unprotected.
