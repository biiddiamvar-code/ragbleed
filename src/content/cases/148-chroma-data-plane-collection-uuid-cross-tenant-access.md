---
caseId: "148"
title: "Chroma resolved data-plane collection requests by UUID alone, ignoring the tenant and database in the URL and letting callers read and write other tenants' vectors"
filed: "2026-10-01"
filedDisplay: "01 Oct 2026"
firstObserved: "18 Jul 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Disclosed, patch guidance pending"
affectedSystems: "Chroma (chroma-core/chroma), Rust frontend server, versions through 1.5.9; data-plane endpoints add, get, query, count, update records, update_collection, fork_count and indexing_status"
cve: "CVE-2026-92782 (GHSA-j8fq-8cc8-m22c)"
readTime: "5 min read"
related: ["026", "039", "037"]
---

## Summary

Chroma's REST API places every collection operation under `/api/v2/tenants/{tenant}/databases/{database}/collections/{collection_id}/...`, but its data-plane handlers located the target collection by `collection_id` alone and never confirmed that the collection belonged to the tenant and database named in the path. A caller confined to its own tenant prefix could add, read, query, update and re-configure any other tenant's collection whose UUID it knew. Because Chroma's documented multi-tenant isolation relies on a reverse proxy enforcing exactly that path prefix, the flaw voided the recommended isolation model for vector data.

## What was observed

The issue was filed publicly as chroma-core/chroma#7462 on 18 Jul 2026, with source references against the 1.5.9 tag; the repository had no `SECURITY.md` or private reporting channel at the time. CVE-2026-92782 was published 16 Sep 2026 (CVSS 4.0 8.6, CWE-863) with a reference to a VulnCheck advisory, describing an authenticated attacker reading, modifying and updating records in foreign collections by issuing requests under their own tenant path.

The report traced the data-plane endpoints to a shared helper in `rust/frontend/src/server.rs` (lines 469-487) that called `get_cached_collection(database_name, collection_id)` and then passed the resolved collection to the authorizer. The resolver in `get_collection_with_segments_provider.rs` first consulted a cache keyed solely by `CollectionUuid` and returned any unexpired entry without an ownership check. On a cache miss on the single-node SQLite backend used by `chroma run` and the published Docker image, the lookup filtered the `collections` table by `collection_id` only; neither the tenant nor the database from the URL constrained the result. A commenter tracing `main` noted that `database_name` was threaded into the provider but not enforced against the cached or fetched row, which places the defect at the provider boundary rather than at any one caller.

```
# Illustrative, Chroma <= 1.5.9
# Proxy permits caller B only under /api/v2/tenants/B/databases/db_b/...
POST /api/v2/tenants/B/databases/db_b/collections/<uuid owned by tenant A>/query
  -> get_cached_collection(db_b, uuid)    # cache keyed by uuid; tenant never checked
  -> 200 OK, tenant A's nearest-neighbour documents and metadata
```

The sibling endpoints `GET .../collections/by-id/{id}` and `DELETE .../collections/{id}` resolved through a lookup filtered by tenant and database and returned 404 for the same foreign UUID, so the codebase already contained the correct scoping; the data-plane path did not use it. According to the report, Chroma's bundled Python authentication stack was marked legacy for 1.x and the Rust server shipped a no-op authorizer, so operators following the project's guidance placed Envoy or a similar proxy in front and restricted each token to a fixed URL prefix. That boundary held for the path string but not for the object the server actually operated on.

Exploitation required a valid caller in some tenant and knowledge of a target collection UUID. Such identifiers routinely appear in application logs, client-side code, support tickets and in the memory of former members of a multi-tenant product built on Chroma. The exposure covered both directions: retrieval of another tenant's embedded documents, and writes that inject or alter records in another tenant's retrieval corpus.

## Mitigation

As of writing no maintainer response or vendor-confirmed fixed release was recorded against #7462 or the CVE. Until one ships, do not rely on URL-prefix enforcement at a proxy as the only tenant boundary for Chroma 1.5.9 and earlier. Give each tenant its own Chroma instance or process where isolation matters, or have the application layer maintain an authoritative map of collection UUID to owning tenant and reject any request whose path tenant does not match before forwarding it. Treat collection UUIDs as secrets: keep them out of client-side code, logs and URLs exposed to end users, and rotate (recreate) collections whose identifiers have been disclosed to parties outside the owning tenant.

When a fix lands, verify it covers the cache as well as the database query, and add a regression test asserting 404 for a foreign-tenant UUID on every data-plane verb.

> An identifier that names an object is not an authorization to touch it; the path said tenant B, and the server answered for tenant A.
