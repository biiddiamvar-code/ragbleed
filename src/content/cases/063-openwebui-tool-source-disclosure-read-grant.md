---
caseId: "063"
title: "Open WebUI's tool endpoints handed out source code to anyone with read-only access"
filed: "2026-08-11"
filedDisplay: "11 Aug 2026"
firstObserved: "04 Aug 2026"
severity: medium
category: "Disclosure failure"
status: "Patched"
affectedSystems: "Open WebUI (pip package, all versions before 0.11.0), workspace tool sharing"
cve: "CVE-2026-70491"
readTime: "3 min read"
related: ["020", "057", "005"]
---

## Summary

Open WebUI lets a workspace tool's Python source be shared with other users at one of two grant levels: a write grant, which permits editing, and a read grant, which is meant only to let a recipient use the tool inside a chat. The endpoints that list and fetch a shared tool's record returned the full source field regardless of which grant the caller held. Any authenticated non-admin user who had been given read access to a tool — including every user on an instance, if the tool was shared instance-wide — could pull its complete implementation, whether or not they were ever meant to see the code behind it. Fixed in 0.11.0.

## What was observed

Open WebUI's tool-sharing model treats source code as a writer-only field: the API's list response schema deliberately omits it, and exporting source sits behind a separate permission check reserved for users with write access. The two read-facing endpoints — the tool list and the per-tool get endpoint — did not enforce that same distinction. Both serialized and returned the complete stored record, `source` field included, to any caller who could read the tool at all.

```
# GET /tools/id/{id} — meant to return metadata for use in a chat
# instead returned the same record a write-grant caller would get:
{ "id": ..., "meta": ..., "source": "<full Python implementation>" }
```

A tool's source routinely contains more than its logic: hardcoded API endpoints, embedded credentials for the service it wraps, or implementation details an author had no intention of publishing alongside a "run this tool" grant. Because the read tier is the one used for ordinary, low-trust sharing — including sharing a tool with an entire workspace or instance — the practical exposure scaled to however broadly a tool had been shared, not to how sensitive its author assumed a read-only grant to be.

## Mitigation

Upgrade to Open WebUI 0.11.0 or later, which computes the caller's write access first and strips the source field from the response when that check fails. Where upgrading isn't immediate, treat any tool shared at read level as fully public to its recipients and avoid embedding secrets or non-public implementation detail in tool source, regardless of the sharing tier configured. The recurring failure mode here isn't the permission model itself — write and read tiers were correctly designed — it's that two separate endpoints returning the same underlying record diverged on which fields each was supposed to filter. A permission boundary enforced in one code path and assumed everywhere else isn't a boundary; it has to be checked at serialization, not just at the endpoint the author remembered to guard.
