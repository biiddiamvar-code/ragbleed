---
caseId: "132"
title: "LightRAG's API server shipped listening on all interfaces with authentication off, then echoed raw exception text to whoever reached it"
filed: "2026-09-24"
filedDisplay: "24 Sep 2026"
firstObserved: "07 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "LightRAG API server, PyPI lightrag-hku (<=1.5.4); default-open configuration mitigated in 1.5.5rc1, raw-exception disclosure fixed in 1.5.5"
cve: "CVE-2026-61808 (GHSA-mmg5-8x8q-v934, default unauthenticated API); CVE-2026-85709 (GHSA-hrmj-7rvj-4hg8, raw exception disclosure)"
readTime: "4 min read"
related: ["037", "013", "003"]
---

## Summary

LightRAG's bundled API server, `lightrag-server`, bound to 0.0.0.0 with authentication disabled unless the operator set it up explicitly. Every route — document upload and deletion, knowledge-graph edits, pipeline control, cache clearing, and retrieval over indexed content — was reachable by any network client. A companion report, published 22 September, found that the same routes returned Python exception strings verbatim in HTTP error bodies, so an unauthenticated caller could also read internal paths, database connection targets, and LLM provider errors by triggering failures.

## What was observed

The first issue, CVE-2026-61808 (CWE-306, CVSS 9.8), was a default. Authentication in LightRAG is opt-in, configured through `LIGHTRAG_API_KEY` or through `AUTH_ACCOUNTS` together with `TOKEN_SECRET`. When neither was set, the server started normally, listened on every interface, and served its full API without a credential check. The CVE record lists what that exposed: reading indexed document content, uploading or deleting documents, modifying the knowledge graph, cancelling pipelines, clearing caches, and running up LLM usage on the operator's provider keys. For a RAG server, that covers the whole corpus. An attacker could read it, and could also write to it, planting documents that later retrieval would return to legitimate users. The project's own README noted that the Ollama-compatible `/api/*` routes stay open by default for client compatibility even after authentication is configured, unless `WHITELIST_PATHS` is narrowed.

The second issue, CVE-2026-85709 (CWE-209), was in error handling. The advisory counted about 33 handlers across every router file (`document_routes.py`, `graph_routes.py`, `query_routes.py`, `ollama_api.py`, and the health endpoint in `lightrag_server.py`) that caught an exception and returned `str(e)` as the response detail. No global handler sanitized these messages before they reached the client.

```
# pattern repeated across ~33 route handlers
except Exception as e:
    raise HTTPException(status_code=500, detail=str(e))
# -> "[Errno 13] Permission denied: '/app/data/rag_storage/default/kv_store_full_docs.json'"
```

What leaked depended on the storage backend and on which call failed. The reporters confirmed filesystem path disclosure on the default JSON storage. On PostgreSQL, asyncpg errors could reveal host, port, user, and database name, but not the password. On MongoDB, which is configured through a URI, a malformed-URI or configuration error could return the connection string, including any credentials embedded in it. Errors from OpenAI, Gemini, and Bedrock could pass back model names and account context. The advisory scored the issue at 5.3 on its own. Its unauthenticated reach came from CVE-2026-61808, which is why this entry covers both.

## Mitigation

Upgrade to lightrag-hku 1.5.5 or later. That release routes every 500 handler through a generic response with a correlation ID, logs full detail on the server only, and registers a last-resort global exception handler (HKUDS/LightRAG#3422). The CVE record describes the default-open issue as "mitigated" in 1.5.5rc1, not fixed. The current README still says the server binds to 0.0.0.0 by default and that "without auth every endpoint is public". Upgrading therefore does not add authentication. Operators need to set `LIGHTRAG_API_KEY` or `AUTH_ACCOUNTS` with `TOKEN_SECRET`, set `WHITELIST_PATHS=/health` so the Ollama-compatible routes also require credentials, and bind to 127.0.0.1 or put the server behind an authenticating proxy. Any instance that was reachable without credentials should have its corpus checked for inserted documents, and its LLM provider keys rotated.

The lesson is about the default, not the upgrade. A retrieval server that accepts writes should not start in a mode where anyone who can reach the port can change what it retrieves.
