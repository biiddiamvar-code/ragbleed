---
caseId: "065"
title: "Open WebUI's retrieval status endpoint handed out RAG chunking and embedding config with no authentication"
filed: "2026-08-13"
filedDisplay: "13 Aug 2026"
firstObserved: "10 May 2026"
severity: medium
category: "Disclosure failure"
status: "Patched"
affectedSystems: "Open WebUI (pip package, < 0.9.5)"
cve: "CVE-2026-45397"
readTime: "3 min read"
related: ["063", "011", "030"]
---

## Summary

Open WebUI's retrieval router exposes a status endpoint, `GET /api/v1/retrieval/`, alongside admin-only endpoints for reading and changing RAG configuration. The status endpoint was the odd one out: every neighboring endpoint on the same router required an admin session, but `get_status()` required nothing at all. Any unauthenticated caller who could reach the instance got back the live embedding model, reranking model, RAG prompt template, and exact chunking parameters. Fixed in 0.9.5.

## What was observed

The retrieval router's `/embedding` and `/config` endpoints both depend on `get_admin_user`, correctly gating configuration reads behind administrative access. The `/` status endpoint, handled by `get_status()`, took no such dependency — it accepted a bare request and returned a JSON object built directly from `request.app.state.config`, including `CHUNK_SIZE`, `CHUNK_OVERLAP`, `RAG_TEMPLATE`, `RAG_EMBEDDING_ENGINE`, `RAG_EMBEDDING_MODEL`, and `RAG_RERANKING_MODEL`.

```
# GET /api/v1/retrieval/  — no Depends(get_admin_user), unlike /embedding and /config
# returns: chunk size, chunk overlap, RAG prompt template,
#          embedding engine + model, reranking model
```

None of this required a session cookie, an API key, or an Authorization header — a single unauthenticated GET request returned the full response. The value to an attacker isn't the config values in isolation; it's what they enable. Knowing the exact chunk size and overlap lets an attacker calculate precisely where document boundaries fall, which is the input a RAG-poisoning payload needs to guarantee it lands inside a single retrievable chunk rather than being split across two and diluted. Knowing the embedding model and engine fingerprints the deployment's AI stack for further targeting. None of it is a credential or a document, but all of it is reconnaissance a poisoning or targeting attempt would otherwise have to guess at.

## Mitigation

Upgrade to Open WebUI 0.9.5 or later, which adds the same `get_verified_user` dependency already present on the router's other endpoints. Where upgrading isn't immediate, restrict network access to Open WebUI instances so unauthenticated clients can't reach `/api/v1/retrieval/` directly. The broader pattern, consistent with case 063's tool-source disclosure on the same product, is that Open WebUI's routers get their access control right endpoint by endpoint rather than at the router level — which means a single omitted dependency on one handler is enough to leak what every adjacent handler was built to protect.
