---
caseId: "219"
title: "RAGFlow's set_api_key endpoint sent outbound requests to a caller-supplied base_url and returned the raw exception text, turning model-key validation into an internal port scanner"
filed: "2026-11-22"
filedDisplay: "22 Nov 2026"
firstObserved: "6 Nov 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "infiniflow RAGFlow (< 0.27.0), POST /v1/llm/set_api_key in api/apps/llm_app.py; fixed in 0.27.0"
cve: "CVE-2026-49951 (CNA: VulnCheck; CWE-918, CVSS 4.0 5.3, CVSS 3.1 6.3)"
readTime: "3 min read"
related: ["143", "197", "090"]
---

## Summary

RAGFlow's `set_api_key()` handler, which registers a model provider's API key and endpoint for a tenant, accepted a `base_url` from the caller without validating its destination and made outbound requests to it from the server. When those requests failed, the raw upstream exception text was returned in the API response. An authenticated user could point `base_url` at addresses inside the deployment and read back which services answered and how. Version 0.27.0 adds URL checking against SSRF.

## What was observed

CVE-2026-49951 was published on 6 Nov 2026 by VulnCheck, crediting Sheer Galor; the identifier had been reserved in June. The record places the flaw in `set_api_key()` in `api/apps/llm_app.py`, reached through `POST /v1/llm/set_api_key`, and requires an authenticated session.

The endpoint exists so a user can supply credentials and a custom endpoint for an LLM or embedding provider, which the server then contacts. The record states that `base_url` was used for those outbound requests with no restriction on the target host or port. The connection attempt itself was the probe; the response completed it. Errors raised by the HTTP client or the provider SDK were passed back to the caller verbatim, and the record states that this text disclosed service details, open ports and configuration fingerprints for whatever the server had been pointed at.

```
# authenticated user -> RAGFlow
POST /v1/llm/set_api_key
  { <provider fields>, "base_url": "http://<internal-host>:<port>/" }
# RAGFlow -> internal-host:port      (no destination check)
# RAGFlow -> user: raw exception text  (reveals whether and what answered)
```

The CVE record names the services a standard RAGFlow deployment places on the same network as the API server: MySQL, Elasticsearch, Redis, MinIO, the Infinity vector engine, and cloud metadata endpoints. These are the stores that hold tenants' documents, chunks and embeddings. The fix is attributed to commit `b058229` and PR #17641 ("Check the URL to prevent SSRF attack"); the diff could not be retrieved for this case, so whether 0.27.0 also stopped reflecting upstream exception text was not independently confirmed.

Severity is rated medium, in line with the CVSS headline. The endpoint was available to any logged-in user, but the documented impact was reconnaissance of internal services and limited interaction with them through the request the server chose to send, not direct retrieval of stored data.

## Mitigation

Upgrade RAGFlow to 0.27.0 or later. Independently of the version, restrict egress from the RAGFlow API container to the model providers it is meant to reach, and keep MySQL, Elasticsearch or Infinity, Redis and MinIO on a network segment that requires authentication from every client, including the application tier. Require IMDSv2 or the platform equivalent on cloud hosts. Disable open self-registration on instances that do not need it, which narrows the set of accounts able to reach the endpoint.

Any feature that lets a user say where the server should connect is an SSRF surface, and any feature that returns why the connection failed is its read-back channel.
