---
caseId: "200"
title: "mcp-go OAuth client used the unvalidated resource from well-known metadata as the token audience"
filed: "2026-11-08"
filedDisplay: "08 Nov 2026"
firstObserved: "05 Nov 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "mark3labs/mcp-go (>=0.48.0, <1.2.1), OAuthHandler.fetchServerMetadata"
cve: "CVE-2026-123272 (GHSA-xf6j-693p-wqxx; CWE-346; CVSS 4.0 5.1, CVSS 3.1 8.0)"
readTime: "3 min read"
related: ["147", "187", "142"]
---

## Summary

The OAuth client in mcp-go read the `resource` value from an MCP server's well-known Protected Resource Metadata and used it, unchecked, as the RFC 8707 resource indicator in every later token request. A malicious or compromised MCP server could therefore name a different MCP server as the resource and receive a token minted for that server. Version 1.2.1 fixes the issue.

## What was observed

RFC 9728 section 3.3 requires a client to confirm that the `resource` declared in Protected Resource Metadata identifies the resource it actually addressed. The advisory states that mcp-go applied this check only to metadata advertised through the `resource_metadata` parameter of a `WWW-Authenticate` response. Metadata fetched from the well-known path in `OAuthHandler.fetchServerMetadata` skipped the check.

The unchecked value then propagated. According to the advisory, the client passed the declared `resource` as the RFC 8707 `resource` parameter in dynamic client registration, the authorization request, the token exchange and token refresh. The authorization server issued a token with the audience the server had chosen, and the server holding that token could replay it against the named resource.

```
# Illustrative flow (no exploit code)
# client -> evil-mcp.example : GET /.well-known/oauth-protected-resource
# evil-mcp.example -> client : { "resource": "https://victim-mcp.example", ... }
# client -> auth server      : token request with resource=https://victim-mcp.example
# evil-mcp.example           : holds a token whose audience is victim-mcp.example
```

The advisory rates the issue High; the CVE record carries two scores, CVSS 4.0 at 5.1 and CVSS 3.1 at 8.0. The attack needs a user to connect the client to an attacker-controlled or compromised server, and the record lists no observed exploitation. Medium is assigned here on that precondition, since the token theft itself bypasses audience binding for any resource the user has authorized.

## Mitigation

Upgrade mcp-go to 1.2.1 or later. The fix, in commit 90d247e (PR #1053), rejects metadata whose declared resource does not bind to the addressed MCP server on the well-known path. The advisory lists no workaround. Until upgraded, connect OAuth-enabled mcp-go clients only to MCP servers under the operator's control, and configure resource servers to reject tokens whose audience is not their own.

An authorization server cannot tell a legitimate resource indicator from a forged one; the client is the only party that sees both the address it dialed and the identity the server claimed.
