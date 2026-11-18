---
caseId: "115"
title: "Grafana's MCP server mistook a well-formed session ID for a credential, then let callers pick its next HTTP destination"
filed: "2026-09-11"
filedDisplay: "11 Sep 2026"
firstObserved: "02 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "grafana/mcp-grafana (versions prior to 1.1.0, SSE and streamable-HTTP transports); server-side request forgery via the grafana_api_request tool tracked separately as CVE-2026-19516"
cve: "CVE-2026-19516 (SSRF, CVSS 9.1); the unauthenticated tool-execution issue received no separate CVE — Grafana classified it as a hardening improvement, not a vulnerability, and shipped optional bearer-token authentication in response"
readTime: "5 min read"
related: ["018", "038", "070"]
---

## Summary

Grafana MCP, the official bridge between AI agents and Grafana's dashboards, alerts, and data sources, shipped its SSE and streamable-HTTP transports with no inbound authentication. A caller who generated a well-formed session identifier — a value the server never verified against anything, only checked for correct format — could list and invoke every tool the server exposed, including one that issued outbound HTTP requests using the server's own Grafana service-account credential. A second, independent flaw let that same tool be redirected to an arbitrary destination, turning the MCP server into a request proxy reachable by anyone who could reach its port. Grafana Labs reports the server has passed 1.9 million cumulative Docker Hub downloads.

## What was observed

MCP's HTTP transports use a session identifier to track protocol state across requests — a bookkeeping value, not an authentication token. The affected mcp-grafana releases validated only that an incoming `Mcp-Session-Id` header matched the expected format; nothing checked who had generated it or whether the server itself had ever issued it. Researchers at Pillar Security generated a syntactically valid session ID locally, with no credential of any kind, and used it to call `tools/list` and then `tools/call` successfully. One of the exposed tools, `grafana_api_request`, made requests to the configured Grafana instance using the service-account token stored in the MCP server's own environment — meaning an unauthenticated caller could act with that server's Grafana privileges.

```
# affected server: session-ID format check, no identity check
if session_id.matches_expected_format():
    accept_request()   # tools/list, tools/call all proceed
# no verification that this server issued the session ID,
# or that the caller has any prior credential
```

The second flaw compounded the first. `grafana_api_request` accepted a caller-supplied `X-Grafana-URL` header that selected the outbound request's destination, along with its method, path, body, and headers. Grafana had already closed one part of this gap: when the header pointed somewhere other than the configured Grafana instance, the server correctly withheld the service-account token from that foreign destination. What remained was still a working SSRF primitive — the server would connect to whatever destination the caller named, forward the caller's request, and return the response. In a controlled test, researchers used this to reach an internal canary and separately to walk through an IMDSv2-style token exchange: a caller-directed `PUT` request obtained a metadata session token, and a follow-up caller-directed request used it to retrieve canary credentials. This was assigned CVE-2026-19516, CVSS 9.1.

> Session IDs, Host validation, and Origin validation cannot close that gap alone. They manage protocol state or request context; they do not establish caller identity or authorize the downstream action.

Neither flaw depended on the other technically, but together they describe a single failure pattern: the MCP server holds real credentials and real network reach, and a protocol-level value that merely looks like a boundary was standing in for both authentication and destination control.

## Mitigation

Grafana shipped mcp-grafana 1.1.0 within hours of triage, adding optional bearer-token authentication for the SSE and streamable-HTTP transports — unauthenticated requests now receive a 401 before any tool runs, and the release logs a security error if an unauthenticated server is bound beyond loopback. Because this authentication is opt-in rather than default, operators must explicitly configure it; a server upgraded but left unconfigured is still exposed. CVE-2026-19516 was patched separately.

More generally: a session or connection identifier is state, not identity, and a server that accepts one without verifying who presented it has no authentication boundary at all, regardless of how well-formed the protocol traffic looks. For any tool that issues outbound HTTP requests on a caller's behalf, destination must be constrained independently of credential handling — an allowlist of approved origins, hostname resolution before the restriction is applied (not after, to avoid DNS-rebinding), and default blocks on loopback, private, link-local, and cloud-metadata ranges. Getting the credential-binding half right, as Grafana did on the first pass, is not sufficient if the request itself still reaches an attacker-chosen destination.
