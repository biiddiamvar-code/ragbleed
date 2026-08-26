---
caseId: "082"
title: "Open WebUI's inline chat models used another user's knowledge attachment without checking who owned it"
filed: "2026-08-24"
filedDisplay: "24 Aug 2026"
firstObserved: "04 Aug 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Open WebUI (pip package, >=0.8.8, <0.11.0)"
cve: "CVE-2026-70487 (GHSA-6xhv-rxhv-pwm4)"
readTime: "4 min read"
related: ["079", "065", "013"]
---

## Summary

Open WebUI lets a chat request define its model inline — a request-scoped model configuration, including which knowledge base to draw retrieval context from — instead of requiring the caller to select one of the saved, permission-checked models a workspace admin set up. The knowledge attached to an inline model was pulled and used exactly as the client specified, without confirming the requesting user could actually read the file it pointed at. Any authenticated user who obtained another user's file identifier could get that file's indexed content returned to them through the built-in knowledge tools. Fixed in Open WebUI 0.11.0 as CVE-2026-70487.

## What was observed

Open WebUI's normal path to using a knowledge base runs through a saved workspace model: an admin attaches specific knowledge to a model definition, and Open WebUI's permission checks apply to that saved object before a user can query it. The inline-model path exists as a convenience for callers, chiefly API clients, who want to specify a model's full configuration — including knowledge sources — directly on the chat request rather than referencing a pre-configured one. That configuration was trusted at face value. The knowledge metadata on an inline model definition took a file ID and passed it straight to the built-in knowledge-retrieval tools, which fetched and returned the file's indexed content without verifying that the account making the request had any relationship to that file.

```
# illustrative: inline-model chat request, pre-fix
model_config = request.body.model        # caller-supplied, not a saved/permission-checked model
knowledge_file_id = model_config.knowledge.file_id
content = knowledge_tool.get_indexed_content(knowledge_file_id)  # no owner/ACL check against caller
```

The barrier to exploitation was knowing or guessing another user's file ID, not any special privilege — the CWE classification here is CWE-862, missing authorization. File IDs in Open WebUI aren't rendered on-screen in most workflows, so this isn't a "click a visible link" bug, but they do surface in places a caller might reasonably collect them: shared workspace activity, API responses from other endpoints, or a multi-tenant deployment's own logging. Once obtained, a single crafted chat request handed back the full indexed text of a document the requester was never granted access to — the same category of exposure this site has flagged before in Open WebUI's knowledge-sync cleanup path (case 079), where an authorization check ran against the wrong object entirely. Here, the check simply never ran on the object being read.

## Mitigation

Upgrade to Open WebUI 0.11.0 or later, which the fix commit ties to the same release closing several other August 2026 Open WebUI advisories, including the DNS-rebinding SSRF bypass covered separately in case 083. The underlying fix scopes the knowledge lookup to the requesting user's own accessible files before returning content, regardless of what the inline model configuration claims. Deployments that can't upgrade immediately should treat any request-scoped or client-supplied model configuration as untrusted input with the same scrutiny given to a saved, admin-configured one — a permission model built around "the object a user selected from a list" doesn't automatically extend to "the object a client named in a request body," and any code path that lets a caller define configuration inline needs its own authorization check, not an inherited one.
