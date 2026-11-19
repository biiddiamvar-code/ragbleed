---
caseId: "214"
title: "pgEdge RAG Server returned raw LLM provider error text to unauthenticated query callers, exposing a fragment of the operator's API key"
filed: "2026-11-19"
filedDisplay: "19 Nov 2026"
firstObserved: "3 Sep 2026"
severity: low
category: "Disclosure failure"
status: "Patched"
affectedSystems: "github.com/pgEdge/pgedge-rag-server (Go module, v1.0.0 and all 1.0.0 alpha/beta pre-releases; fixed in 2.0.0 / pseudo-version 1.0.1-0.20260729022402-72e0785a6d7c)"
cve: "CVE-2026-125326 (GHSA-68g8-gh8f-7rhg, CWE-209 / CWE-522, CVSS 3.1 5.8)"
readTime: "3 min read"
related: ["111", "065", "063"]
---

## Summary

pgEdge RAG Server, a retrieval service that answers questions over PostgreSQL/pgvector data through a configured LLM provider, passed the text of failed provider calls straight back to API clients. When the provider rejected the operator's key, its error message could contain a masked form of that key, and the server relayed it to an unauthenticated caller. The exposed value was a fragment, not a working credential. Version 2.0.0 stops provider error text from reaching clients.

## What was observed

The maintainers published GHSA-68g8-gh8f-7rhg in the pgedge-rag-server repository on 3 Sep 2026; CVE-2026-125326 was published to NVD on 10 Nov 2026 and the advisory entered the GitHub Advisory Database on 12 Nov 2026.

The query handler in `internal/server/handlers.go` returned `err.Error()` to the client whenever pipeline execution failed. The query endpoint had no authentication in affected versions. The error it returned was built by `parseError` in `internal/llm/openai/client.go`, which disclosed data on both of its branches: if the provider's response body could not be parsed as JSON, the entire raw body was embedded in the error; if it parsed, the provider's own message was used. For OpenAI, an authentication-failure message can include the key's `sk-proj-` prefix and its last four characters.

```
# unauthenticated client -> RAG server query endpoint
POST <query endpoint>  { "query": "<anything>" }
# server -> OpenAI with operator key   -> 401, message quotes masked key
# server -> client: 5xx with err.Error() = provider message
#                   "... sk-proj-****...<last 4 chars> ..."
```

The leak therefore surfaced when the configured key was being rejected, which the advisory's own workaround reflects: keeping provider credentials valid prevents the authentication failure that carries the fragment. The raw-body branch had no such bound; any non-JSON error page returned by a provider or an intermediate proxy was forwarded verbatim.

Severity is rated low, below the CVSS 5.8 headline. The endpoint was reachable without authentication in the default configuration, but the disclosed value was a prefix and four trailing characters of a key the provider was already refusing, not material that authenticates on its own. The finding is more significant as a pattern than as an exposure: upstream error strings were treated as safe to show the caller.

## Mitigation

Upgrade to pgedge-rag-server 2.0.0 (fix commit `72e0785`, PR #45), which adds an `internal/safeerr` package and returns generic errors to API clients while keeping provider detail in server logs. Upgrading does not undo prior exposure; rotate any provider key that was configured on an affected version while the endpoint was reachable by untrusted callers, particularly if the provider was rejecting it at the time. Where upgrading is delayed, place the server behind a proxy that rewrites 5xx response bodies and restrict who can reach the query endpoint.

Error text from an upstream model provider is data about the operator's account, and a RAG service that forwards it unedited has made the provider's message format part of its own disclosure surface.
