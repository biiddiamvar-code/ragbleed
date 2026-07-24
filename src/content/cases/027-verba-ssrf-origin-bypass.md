---
caseId: "027"
title: "A leading single quote in an Origin header turned Verba into an open proxy"
filed: "2026-07-24"
filedDisplay: "24 Jul 2026"
firstObserved: "21 Jul 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "Weaviate Verba (all versions through 2.1.3; project archived, no fix planned)"
cve: "CVE-2026-65317"
readTime: "4 min read"
related: ["019", "010", "015"]
---

## Summary

Verba, the reference RAG chatbot built on top of Weaviate, guarded its `/api/connect` endpoint with a same-origin check meant to keep the connection-configuration API reachable only from the app's own front end. The check's string comparison was flawed: prefixing the `Origin` header with a single quote satisfied it regardless of the domain that followed. Past that gate, `/api/connect` accepted attacker-supplied host and port values and issued outbound requests to them, turning the server into an unauthenticated SSRF proxy. Verba was archived by its maintainers before the report landed, so no patch is coming.

## What was observed

The middleware's origin check was intended to reject any request whose `Origin` header didn't match the expected local host. In practice, the matching logic treated a value like `'attacker.com` — an `Origin` header beginning with a literal single quote — as satisfying the check, independent of what followed the quote or what port was specified. That's the entire bypass: no session, no token, no prior interaction with the application, just a malformed header value the parser happened to accept.

```
// what the check was supposed to reject
Origin: https://evil.example:9999

// what it actually let through
Origin: 'anything-at-all
```

With the origin gate defeated, the request reaches `/api/connect`, which takes `host` and `port` as parameters and has the server issue an outbound HTTP GET to whatever address they name. That's a textbook SSRF primitive sitting behind a broken string comparison rather than behind any deliberate access control — the server will happily probe internal services, reach cloud instance-metadata endpoints for credential theft, or relay requests to third parties, all on the attacker's behalf and from the server's network position.

The complicating factor is timing: the Weaviate team archived the Verba repository on 8 June 2026, before this report was published. There is no maintainer left to ship a fix, which means every deployed instance — however it was provisioned — is permanently exposed to this class of bypass.

## Mitigation

Because no patch will be released, treat any running Verba instance as unremediable rather than as a bug to track. If it's still needed operationally, remove it from internet-facing exposure and restrict inbound access to internal, trusted networks only; if it isn't needed, decommission it. Where the instance must stay reachable, apply egress controls at the network layer so the Verba host cannot originate arbitrary outbound connections, since the application itself can no longer be trusted to enforce that boundary. More generally: an archived or unmaintained project isn't a static risk that stays constant over time — it's a risk that increases every time a new bypass is found in code nobody is left to patch, and "has a security fix ever shipped" stops being a meaningful question once the answer is permanently no.
