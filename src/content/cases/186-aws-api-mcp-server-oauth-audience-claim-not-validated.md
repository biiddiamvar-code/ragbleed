---
caseId: "186"
title: "AWS API MCP Server validated OAuth token signature, issuer and expiry but not audience, accepting tokens issued to other applications"
filed: "2026-10-28"
filedDisplay: "28 Oct 2026"
firstObserved: "27 Oct 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "awslabs.aws-api-mcp-server (>=1.3.0, <1.6.0), streamable-http transport with AUTH_TYPE=oauth"
cve: "CVE-2026-115413 (GHSA-4prq-p2x5-w9fh, CWE-346; AWS Security Bulletin 2026-152-AWS)"
readTime: "3 min read"
related: ["146", "178", "157"]
---

## Summary

The AWS API MCP Server, when run over streamable-http with OAuth authentication, did not check the audience claim of incoming bearer tokens. A token issued by the same identity provider to a different application in the same tenant was accepted. A holder of such a token could make AWS API calls using the credentials configured on the host. Version 1.6.0 fixes the check.

## What was observed

AWS published Security Bulletin 2026-152-AWS, rated Important, on 27 Oct 2026. Per the bulletin, the server verified the token's signature, issuer and expiry, and omitted the audience check that binds a token to the application it was issued for. The server therefore treated any validly signed token from the trusted issuer as authorization to use it.

The exposure is limited to deployments that use the streamable-http transport with `AUTH_TYPE=oauth`. The default stdio transport was not affected. The attacker precondition is possession of a token from the same identity provider and tenant, issued for some other application; this is a lower bar than it sounds in organizations where many internal applications share one tenant, and a higher bar than an unauthenticated flaw. The bulletin does not report exploitation, and the public record available in this run gave no further root-cause detail or reporter credit. The third-party CVSS 3.1 vector of 7.8 with local attack vector, shown by one tracker, conflicts with the network-reachable transport described and was not relied on.

Severity is rated medium: the transport is opt-in and a token from the same tenant is required, but the resulting access runs with the host's configured AWS credentials.

## Mitigation

Upgrade `awslabs.aws-api-mcp-server` to 1.6.0 or later, and patch forks or derivative code separately. Operators using OAuth should set `AUTH_AUDIENCE`; for providers whose access tokens carry no audience claim, such as Amazon Cognito, set `AUTH_CLIENT_ID` instead. If upgrading is not immediately possible, switch to the stdio transport. A signature proves who issued a token, not who it was meant for; resource servers must check both.
