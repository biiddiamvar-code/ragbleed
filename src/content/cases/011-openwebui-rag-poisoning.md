---
caseId: "011"
title: "Open WebUI let any user destroy and repopulate someone else's knowledge base"
filed: "2026-05-12"
filedDisplay: "12 May 2026"
firstObserved: "08 May 2026"
severity: high
category: "Data poisoning (ingestion-time)"
status: "Patched"
affectedSystems: "Open WebUI (all versions before 0.9.0)"
cve: "CVE-2026-44554"
readTime: "5 min read"
related: ["003", "007", "009"]
---

## Summary

Open WebUI's web-and-YouTube ingestion endpoint lets a user point it at a URL and save the extracted content into a named vector collection — with an `overwrite` flag, on by default, that deletes whatever was in that collection first. The endpoint never checked whether the caller actually owned the collection they named. Anyone who could guess or obtain another user's knowledge base ID could wipe it and refill it with content of their choosing.

## What was observed

`POST /api/v1/retrieval/process/web` is the endpoint behind a normal, useful feature: add a webpage or video transcript to a knowledge base by URL instead of uploading a file. The request takes a `collection_name` and an `overwrite` parameter that defaults to `true`. When it runs, it calls the vector store's `delete_collection()` on the target name before writing the new content — a reasonable way to let someone refresh a collection they own. What was missing was any check that the collection named in the request belonged to the account making it.

Combined with a separate, related gap — the system's internal knowledge-base index was itself readable by any authenticated user, making collection IDs across the whole instance enumerable rather than secret — this turned a convenience feature into a takeover path. Find another user's knowledge base ID, submit a web-ingestion request naming it, and the existing content is deleted and replaced with whatever the attacker's chosen URL contains.

```
POST /api/v1/retrieval/process/web
{
  "url": "https://attacker-controlled.example/poisoned-doc",
  "collection_name": "<victim's knowledge base UUID>",
  "overwrite": true
}
# no check that the caller owns collection_name
```

This is a materially different kind of harm than a read leak. A RAG system's entire value depends on the assumption that its retrieved content reflects what its owner actually put there. Once that assumption breaks, every answer the system gives — to every user querying that knowledge base — is only as trustworthy as whatever the attacker last wrote into it. Silent, targeted misinformation through a system people already trust is a harder problem to notice than a leak, because nothing looks broken from the outside.

## Mitigation

Upgrade to Open WebUI 0.9.0 or later, which adds ownership validation to the web/YouTube ingestion endpoints before allowing an overwrite. If you operate an Open WebUI instance with multiple users, audit knowledge bases for content that doesn't match what your team actually uploaded — a poisoning that happened before the patch would survive the upgrade untouched. Treat any endpoint that accepts a collection or resource identifier as a name, not as a secret; enumeration of one system (in this case, the knowledge-base index) is often the first half of an attack whose second half lands somewhere else entirely.
