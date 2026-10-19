---
caseId: "175"
title: "SuperAGI's tool controller accepted a caller-supplied tool ID without verifying organization ownership, exposing and allowing modification of other organizations' tool metadata"
filed: "2026-10-19"
filedDisplay: "19 Oct 2026"
firstObserved: "2 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Disclosed, patch guidance pending"
affectedSystems: "SuperAGI (TransformerOptimus/SuperAGI) v0.0.14"
cve: "CVE-2026-51915 (CWE-284, CVSS 3.1 9.8 per CISA ADP); sibling record CVE-2026-51914"
readTime: "3 min read"
related: ["164", "040", "166"]
---

## Summary

CVE-2026-51915 describes an access control flaw in the tool controller of SuperAGI v0.0.14. Two handlers loaded a tool record by a tool ID supplied in the URL and never checked that the tool belonged to the caller's organization. An authenticated user in one organization could therefore read or overwrite the tool metadata of another. No vendor fix or advisory was found at the time of review.

## What was observed

The CVE record and the public write-up it references place the flaw in `superagi/controllers/tool.py`, in the `get_tool` and `update_tool` functions, reachable at `/tools/get/{tool_id}` and `/tools/update/{tool_id}`. Both accept `tool_id` from the caller. The organization check that should run through the tool's parent toolkit was absent. The record uses the phrase "affected source snapshots," so the exact code state that was reviewed is not fully specified.

```
# authenticated user in organization A
# GET  /tools/get/<tool_id owned by organization B>     -> metadata returned
# POST /tools/update/<tool_id owned by organization B>  -> metadata overwritten
# missing: tool -> toolkit -> organization == caller's organization
```

A second record filed the same day, CVE-2026-51914, describes the same omission in the agent template controller: `save_agent_as_template` and `publish_template` accepted agent or execution IDs without confirming they belonged to the caller's organization. Both records were published by MITRE on 2 Oct 2026 and carry no vendor or product fields in the CNA data; the product and version come from the description text. No vendor advisory, patched release, or confirmed in-the-wild exploitation was found. The primary evidence is the CVE record and a third-party gist, and the endpoint behavior was not independently reproduced.

RagBleed rates the mechanism medium and diverges from the 9.8 score. That vector lists privileges required as none, while the record's own description requires an authenticated user. The exposed object is tool metadata, which can hold endpoint configuration, and the write path allows tampering with tools that agents in the victim organization may later invoke. The record does not state that secrets or documents are returned.

## Mitigation

No fixed version was identified. Restrict network access to `/tools/get/` and `/tools/update/`, and do not run a shared multi-organization SuperAGI deployment until an ownership check is added. A local patch should resolve the tool's toolkit and compare its organization to the caller's before any read or write, returning a not-found response on mismatch. Object identifiers are not authorization; every handler that takes an ID from the request has to bind it to the caller's tenant before touching the record.
