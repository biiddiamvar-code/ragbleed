---
caseId: "057"
title: "LiteLLM concatenated the Bearer token straight into a SQL query, exposing every connected provider's credentials"
filed: "2026-08-08"
filedDisplay: "08 Aug 2026"
firstObserved: "20 Apr 2026"
severity: high
category: "Disclosure failure"
status: "Patched"
affectedSystems: "LiteLLM Proxy (>=1.81.16, <1.83.7)"
cve: "CVE-2026-42208 (GHSA-r75f-5x8p-qvmc)"
readTime: "5 min read"
related: ["028", "005", "012"]
---

## Summary

LiteLLM is an open-source AI gateway that fronts OpenAI, Anthropic, AWS Bedrock, and other model providers behind a single OpenAI-compatible API, centralizing the provider credentials, virtual API keys, and spend controls of every team that routes traffic through it. A critical pre-authentication SQL injection in the proxy's key-verification path let any client that could reach the server extract that entire credential store without logging in. The `Authorization: Bearer` header was concatenated directly into a query against the proxy's PostgreSQL backend before authentication was decided, so the injection ran ahead of any auth check. The maintainers shipped a fix in v1.83.7 on 19 April 2026; the advisory was indexed in the GitHub Advisory Database on 24 April, and Sysdig's threat research team recorded a targeted exploitation attempt against the pattern roughly 36 hours later.

## What was observed

LiteLLM's proxy verifies each request by taking the value after `Bearer` and checking it against a `LiteLLM_VerificationToken` table. In affected versions that check built its SQL by string concatenation rather than parameter binding, so a value ending in a single quote closed the string literal early and let an attacker append arbitrary SQL:

```
-- illustrative shape of the vulnerable check (not the literal source)
SELECT * FROM "LiteLLM_VerificationToken" WHERE api_key = '<bearer-header-value>'
-- a bearer value of  sk-litellm' UNION SELECT credential_values,... FROM litellm_credentials--
-- turns the auth check itself into an arbitrary read against the database
```

Because the query executes as part of deciding whether the caller is authenticated at all, no valid key was needed to trigger it — reachability of the proxy port was sufficient. Three tables carried the actual payoff: `LiteLLM_VerificationToken` (virtual keys, including the instance's master key), `litellm_credentials` (the stored upstream provider keys for OpenAI, Anthropic, Bedrock, and others), and `litellm_config` (proxy environment variables, typically including the database connection string and callback URLs). Sysdig's telemetry captured a real operator running exactly this sequence in production 36 hours after the advisory was indexed: column-count discovery via a standard `UNION SELECT NULL, NULL...` progression, followed by direct queries against all three high-value tables — skipping benign tables like the user or team lists entirely. The requests also retried a lowercase table name before switching to the correct Prisma-generated PascalCase form (`"LiteLLM_VerificationToken"`), indicating the operator had read LiteLLM's public schema rather than running a generic scanner. Sysdig did not observe confirmed follow-through — no authenticated calls using extracted keys — but the reconnaissance alone showed the credential store was a deliberate target, not incidental scanner noise.

## Mitigation

Upgrade to LiteLLM v1.83.7 or later (the project recommends 1.83.10+), which replaces the concatenated query with a parameterized one. Any instance that was internet-reachable on an affected version should be treated as compromised: rotate the master key, every virtual API key, and every stored provider credential, since LiteLLM does not bind keys to a source IP by default and a leaked key is trivially replayable. Restrict proxy access to an internal network or a mutually authenticated reverse proxy rather than exposing it directly, and watch logs for `Authorization` header values containing quotes or SQL keywords as a high-confidence indicator of attempted exploitation. The broader lesson applies beyond this one gateway: any service whose entire purpose is to centralize other systems' credentials turns an ordinary web-app bug class — unparameterized SQL — into a blast radius closer to a full cloud-account compromise, and should be defended, patched, and network-isolated accordingly.
