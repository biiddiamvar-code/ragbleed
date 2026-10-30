---
caseId: "187"
title: "MCP Python SDK server bearer authentication had no audience check, accepting valid tokens issued for other services"
filed: "2026-10-30"
filedDisplay: "30 Oct 2026"
firstObserved: "27 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "mcp (PyPI, MCP Python SDK) 1.10.0 through 1.29.1 and 2.0.0 through 2.1.1, server-side bearer authentication"
cve: "CVE-2026-116684 (GHSA-w4fh-qvv9-3v23, CWE-863)"
readTime: "3 min read"
related: ["186", "147", "178"]
---

## Summary

The server-side bearer authentication in the MCP Python SDK had no mechanism for checking the audience of an access token. A token that was validly issued for a different service was accepted by an MCP server built on the SDK. Versions 1.30.0 and 2.2.0 add the check, but it is disabled by default and must be switched on by the operator.

## What was observed

The GitHub advisory GHSA-w4fh-qvv9-3v23, published on 27 Oct 2026, describes the flaw as an authorization error (CWE-863) in the SDK's bearer-token handling for MCP servers. The server could verify a token through the application's `TokenVerifier`, but the SDK provided no step that bound the token to the server that received it. The `aud` claim, which names the intended recipient of a token, was never compared against the identity of the MCP server.

The consequence is token reuse across resource servers. A token issued by the same authorization server to another application, or for another MCP server, was sufficient to call tools on a vulnerable server. The advisory scores the issue 6.8 (CVSS 3.1, AV:N/AC:H/PR:L), with high confidentiality and integrity impact; the elevated attack complexity reflects the need to first obtain a token from a shared issuer. The advisory credits no reporter in the material reviewed, and no exploitation was reported.

The fix is not effective on upgrade alone. The patched releases introduce a `validate_token_resource` setting that defaults to off, and the advisory states it becomes the default in version 3.0.

```python
# Sketch of the required configuration after upgrading (comments only describe intent)
# AuthSettings(
#     resource_server_url="<audience your authorization server issues>",
#     validate_token_resource=True,
# )
# TokenVerifier.verify_token() must also return the token's audience
# as AccessToken.resource, otherwise every request fails with 401.
```

Severity is rated medium: the attacker needs a valid token from the same issuer, but the SDK is the base for many MCP servers and the access gained is the full tool surface of the receiving server.

## Mitigation

Upgrade `mcp` to 1.30.0 or 2.2.0 or later, then enable `validate_token_resource=True` with `resource_server_url` set to the audience used by the authorization server, and return the audience from `verify_token()`. Setting only the flag, without returning `AccessToken.resource`, rejects all requests. Deployments whose `TokenVerifier` already checks the audience should set the flag to `False` explicitly to suppress the deprecation warning. Where upgrading is not possible, reject any token whose `aud` does not include the server inside `verify_token()`; this works on all versions. The same omission appeared in the AWS API MCP Server (case 186) within the same week: a signature establishes who issued a token, and the audience establishes who it was for.
