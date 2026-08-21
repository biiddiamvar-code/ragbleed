---
caseId: "079"
title: "Open WebUI's knowledge-sync cleanup checked who owned the folder, not which files it deleted"
filed: "2026-08-21"
filedDisplay: "21 Aug 2026"
firstObserved: "04 Aug 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Open WebUI (pip package, >=0.9.6, <0.11.0), knowledge base sync cleanup endpoint"
cve: "CVE-2026-70488"
readTime: "4 min read"
related: ["073", "035", "011"]
---

## Summary

Open WebUI's knowledge base sync feature lets a folder of documents stay mirrored into a RAG knowledge base, with a cleanup routine that removes entries for files no longer present in the source folder. The cleanup endpoint checked that the caller had write access to the knowledge base named in the URL, then deleted whatever file and directory identifiers the caller listed in the request body — without checking that those identifiers actually belonged to that knowledge base. Any authenticated user with write access to one knowledge base could use this to delete files and embeddings out of someone else's. Fixed in Open WebUI 0.11.0 as CVE-2026-70488.

## What was observed

The sync cleanup route, `POST /knowledge/{id}/sync/cleanup`, authorized the request against a single value: the knowledge base ID in the URL path. Everything it then deleted came from a separate source — a list of file and directory identifiers submitted in the request body — and the handler never confirmed those identifiers were children of the knowledge base it had just checked access for. This is the shape of CWE-639, authorization bypass through a user-controlled key: the object being authorized and the objects being acted on aren't the same object, and only one of them got checked.

```
# illustrative: sync cleanup handler, pre-fix
require_write_access(id)                 # checks access to the URL's knowledge base
for file_id in body.file_ids:            # caller-supplied, not verified against id
    remove_file_from_knowledge_by_id(id, file_id)
```

An attacker needed write access to any single knowledge base to exploit this — not an unauthenticated path, but a low bar in any Open WebUI deployment where multiple users or teams maintain separate knowledge bases on a shared instance. By pointing the URL at their own knowledge base while naming a victim's file and directory IDs in the body, they could strip documents and their embeddings out of a knowledge base they had no legitimate access to. Nothing was disclosed in the process — the vulnerability is destructive, not read-access — but the effect lands directly on retrieval quality: targeted documents silently stop showing up in RAG results, and chat-with-file features break for the removed files, with no error visible to the knowledge base's actual owner until someone notices an answer that should have cited a document no longer citing it.

## Mitigation

Upgrade to Open WebUI 0.11.0 or later, which added an ownership check — confirming each file ID actually belongs to the target knowledge base — before allowing the cleanup routine to touch it. Deployments that can't upgrade immediately should restrict knowledge base write access to trusted accounts and consider rate-limiting or blocking the sync cleanup route at the reverse proxy for non-administrative users. The broader lesson repeats a pattern this site has flagged before in multi-tenant RAG platforms: an authorization check on the resource named in a URL says nothing about the resources named in the body, and any endpoint that accepts a batch of caller-supplied identifiers needs to verify each one against the same trust boundary, not just the one in the path.
