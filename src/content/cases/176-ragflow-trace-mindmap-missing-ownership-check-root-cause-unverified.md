---
caseId: "176"
title: "RAGFlow 0.24.0's trace_mindmap path reached task data by caller-chosen identifier without an ownership check, with the exact code path unverified"
filed: "2026-10-19"
filedDisplay: "19 Oct 2026"
firstObserved: "1 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Disclosed, patch guidance pending"
affectedSystems: "infiniflow RAGFlow 0.24.0 (a public write-up says v0.24.0 or earlier)"
cve: "CVE-2026-51893 (CWE-284, CVSS 3.1 9.8 per CISA ADP)"
readTime: "3 min read"
related: ["143", "071", "148"]
---

## Summary

CVE-2026-51893 records an incorrect access control flaw in the `trace_mindmap` path of RAGFlow 0.24.0. The handler accepts a caller-chosen identifier and performs the data lookup without checking owner, tenant, workspace or membership. No fixed release was identified, and the root cause could not be independently verified beyond the CVE record and a short third-party write-up.

## What was observed

The CVE record states that RAGFlow 0.24.0 is vulnerable to incorrect access control via `trace_mindmap`. A public write-up linked from the record places the function in `api/apps/kb_app.py` and describes a GET request carrying an identifier that resembles a mindmap task ID. Its reproduction uses two accounts: a second authenticated user retrieves a mindmap task created by the first.

```
# user B, valid session, different tenant from user A
# GET trace_mindmap with a task identifier created by user A
# observed per write-up: record returned
# missing check (per CVE text): owner / tenant / membership binding
```

The source for the handler was not included in the write-up and the request path and parameters are truncated, so the specific missing check cannot be confirmed. The scoring vector from CISA ADP lists privileges required as none, while the write-up's scenario uses a logged-in second user; the two do not agree, and the authentication requirement is unresolved. The same vector assigns high integrity and availability impact, but nothing in the record describes a write or delete operation. CISA ADP's SSVC data marks a proof of concept as available. NVD analysis was deferred.

RagBleed rates the mechanism medium. The exposure is of derived mindmap data from another user's knowledge base, which may reflect private document content, but the affected version is a single release and the reachable scope is unverified. This rating would move to high if testing showed unauthenticated access to content from arbitrary tenants.

## Mitigation

No vendor fix was documented as of 18 Oct 2026. Keep RAGFlow 0.24.0 off untrusted networks, put it behind an authenticating proxy, and block or monitor requests to the `trace_mindmap` route from unexpected sessions. Check the project's releases for a build later than 0.24.0 before treating the issue as closed. Derived artifacts such as mindmaps, summaries and traces inherit the sensitivity of their source documents, and need the same tenant binding as the documents themselves.
