---
caseId: "146"
title: "Casdoor's /api/mcp endpoint authorized any application's clientId and clientSecret for user administration in every organization, bypassing its Casbin policy and tenant scoping"
filed: "2026-09-29"
filedDisplay: "29 Sep 2026"
firstObserved: "15 Sep 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Disclosed, patch guidance pending"
affectedSystems: "Casdoor (casdoor/casdoor), all versions through 4.4.0, built-in MCP server at /api/mcp (user-management tools in mcpself/user.go)"
cve: "CVE-2026-91998 (GHSA-jvmw-g7rg-x26f)"
readTime: "4 min read"
related: ["108", "102", "144"]
---

## Summary

Casdoor is an open-source IAM and SSO server that now markets itself as an MCP and agent gateway, and it exposes its own MCP server at `/api/mcp` so agents can administer identities through tool calls. That endpoint accepted an OAuth application's `clientId` and `clientSecret` as the caller's identity and then authorized user-administration tools without evaluating the Casbin policy or the organization the application belonged to. Holding the credentials of one application, in any organization, was enough to read, create, modify and delete users across every organization on the instance.

## What was observed

The CVE record, assigned by VulnCheck and published 15 Sep 2026 (CVSS 3.1 9.9, CVSS 4.0 9.4, CWE-863), credited the finding to researcher George Chen and pointed at three locations in the v4.4.0 source: the request-to-subject resolution in `routers/base.go` (lines 122-154), a short branch in `authz/authz.go` (lines 174-176), and the MCP user tools in `mcpself/user.go`. The researcher's write-up, as summarized by secondary trackers, described the path: a request carrying any application's client credentials resolved to an application subject, and that subject hit an unconditional allow in the authorizer before any Casbin rule or organization check ran. We did not independently review those source lines; the mechanism below follows the record and the cited code references.

```
// Illustrative flow, Casdoor <= 4.4.0
POST /api/mcp   (clientId + clientSecret of app "A" in org "X")
  -> subject resolved as application "A"
  -> authorizer: application subject => allow   // Casbin policy and org scope never evaluated
  -> tools/call user CRUD with owner = "Y"       // any organization
```

The exposed tools covered the full user lifecycle. The record listed enumeration of user records including password salts and email addresses, creation of administrator accounts, modification of existing users and deletion, in any organization. Application client secrets are routinely distributed to backend services, CI jobs and third-party integrations, so the effective privilege of the weakest-guarded integration became global user administration.

The disclosure was not coordinated. The researcher reported emailing the project on 13 Jun 2026 and opening GitHub issues around 26 Jun after no reply; the issues were deleted. CERT/CC separately published VU#889462 on 03 Sep 2026 for a different Casdoor cross-tenant flaw (CVE-2026-15630, desynchronized authorization target in `/api/add-*` and `/api/delete-*` handlers) and also recorded that it could not reach the vendor. OSV's import of the CVE lists commit `e7f27999` as a fix point in the git history, but as of writing no vendor advisory or release note confirms which tagged release carries it.

## Mitigation

Treat every Casdoor application credential as an instance-wide administrator credential until a vendor-confirmed fixed release is deployed. Block `/api/mcp` at the reverse proxy for all callers that do not need it, rotate client secrets for every application, and audit for administrator accounts or user changes that cross organization boundaries. If running from source, verify the deployed build contains commit `e7f27999` and test that an application credential from one organization cannot list users in another.

An MCP endpoint bolted onto an identity server inherits the server's most powerful operations; the authorization path in front of it has to be the same one the rest of the API uses, not a shortcut for machine callers.
