---
caseId: "204"
title: "LiteLLM Enterprise proxy fetched local files on behalf of unauthenticated LLM-route requests and sent the contents to an attacker-chosen URL, exposing the master key"
filed: "2026-11-10"
filedDisplay: "10 Nov 2026"
firstObserved: "27 Oct 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "litellm proxy with an active Enterprise license (<1.103.10, <1.104.8, <1.105.6, <1.106.5; patched in 1.103.10, 1.104.8, 1.105.6, 1.106.5); unlicensed open source deployments not affected"
cve: "No CVE assigned as of writing; tracked as GHSA-w4c7-34wj-hqm8 (CWE-73 / CWE-200 / CWE-306 / CWE-918, CVSS 3.1 10.0)"
readTime: "3 min read"
related: ["183", "158", "057"]
---

## Summary

The LiteLLM proxy, when run with an active Enterprise license, accepted an unauthenticated request on an LLM route that caused the proxy to read a local file and transmit its contents to a URL chosen by the requester. Reading the process environment returned the master key and provider API keys, which converted a file-read primitive into full administrative control of the gateway. Patched releases exist on four supported lines.

## What was observed

The advisory was published on 27 Oct 2026. It credits Dylan Ong of Karmasec as original reporter and states that Cyrill Bannwart of Compass Security independently found the same flaw. Per the advisory, no authentication was required, and any LLM route could be used as the entry point. The weakness classes it lists combine external control of a file path, missing authentication on a critical function, and server-side request behavior: the proxy accepted a file reference from the caller, resolved it locally, and forwarded the content outbound.

```
# Illustrative
# unauthenticated request to an LLM route carries a local file reference
# proxy reads the file (e.g. /proc/self/environ) and posts it to a caller-supplied URL
# environ contains LITELLM_MASTER_KEY and provider API keys -> admin access
```

The advisory states that reading `/proc/self/environ` exposes `LITELLM_MASTER_KEY` and provider credentials, and that in some configurations the attacker can then execute arbitrary Python as root. The published page does not name the specific route parameter, the vulnerable code path, or a fix commit, so the precise input field that carried the file reference was not independently verified here. Only proxies with an active Enterprise license are affected.

The mechanism is rated high. The data exposed is the gateway's own root credential and every upstream provider key it holds, and the request needs no account. The Enterprise-license precondition narrows the population but is not a configuration an operator can be expected to have mitigated. The advisory's CVSS 3.1 score is 10.0.

## Mitigation

Upgrade to 1.103.10, 1.104.8, 1.105.6, or 1.106.5, according to the release line in use. The advisory also recommends defense in depth: load the master key from a secret manager rather than the process environment, set a separate `LITELLM_SALT_KEY`, and restrict the proxy's outbound traffic to known provider endpoints. Operators should rotate the master key and all provider keys on any proxy that was reachable by untrusted clients while running an affected version.

A gateway that holds every upstream credential in one process environment makes any file-read flaw a total compromise. Egress filtering is the control that makes the second half of this chain, the outbound transmission, fail.
