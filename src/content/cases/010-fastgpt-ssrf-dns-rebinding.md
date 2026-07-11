---
caseId: "010"
title: "FastGPT's SSRF protection could be defeated with a well-timed DNS change"
filed: "2026-05-12"
filedDisplay: "12 May 2026"
firstObserved: "08 May 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "FastGPT, isInternalAddress() validation (versions 4.14.11 and prior)"
cve: "CVE-2026-42344"
readTime: "4 min read"
related: ["006", "002", "004"]
---

## Summary

FastGPT agents can fetch external URLs — a plugin calling out to a webpage, an API tool retrieving live data. To stop that feature from being turned into a way to probe internal infrastructure, FastGPT checks a URL's resolved IP against private address ranges before fetching it. The problem is that the check and the fetch happen as two separate DNS lookups, and nothing stops the answer from changing in between.

## What was observed

`isInternalAddress()` does what its name suggests: resolve the hostname, check whether the resulting IP falls inside a private range (`10.x`, `192.168.x`, `127.x`, and so on), and reject the request if it does. That's a reasonable defense against SSRF — as long as the IP it checks is the IP that actually gets used.

It isn't, here. The validation step performs its own DNS resolution, and the actual outbound HTTP request performs a second, independent one. A domain the attacker controls can be configured to answer the first lookup with a harmless public IP — passing validation — and answer the second lookup, made moments later when the real request goes out, with an internal address like `169.254.169.254` or a service on the local network. This class of bug has a name: TOCTOU, time-of-check to time-of-use. The check and the use aren't atomic, so nothing keeps them consistent.

```
// isInternalAddress(url) — two independent resolutions
const ip1 = await dns.resolve4(hostname);   // check: public IP, passes
// ... later ...
const ip2 = await dns.resolve4(hostname);   // use: attacker now returns 169.254.169.254
fetch(url); // resolves ip2, not ip1
```

For a RAG or agent platform specifically, this matters because URL-fetching tools are exactly the feature that's supposed to be safe to expose to less-trusted input — a retrieved document suggesting a link, a user-provided API endpoint. An SSRF bypass here means that safety assumption doesn't hold.

## Mitigation

At time of writing, no official patch has been published for this issue — track FastGPT's repository for a fix and apply it as soon as one ships. In the meantime, the underlying pattern is fixable independently of FastGPT's code: resolve the hostname once, validate that single result, and reuse the resolved IP for the actual request rather than letting the fetch step re-resolve the hostname. If your deployment allows any agent or tool to fetch attacker-influenced URLs, treat that fetch path as exposed to your internal network until a patch lands, and restrict outbound network access from the FastGPT host at the network layer as a stopgap.
