---
caseId: "202"
title: "Langflow's URL component buffered whole HTTP response bodies with no size limit, allowing chat-triggered memory exhaustion"
filed: "2026-11-09"
filedDisplay: "09 Nov 2026"
firstObserved: "05 Nov 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "langflow (>=1.0.0a0, <1.13.0); langflow-base (<1.13.0); lfx (<1.13.0); patched in 1.13.0"
cve: "No CVE assigned as of writing; tracked as GHSA-qvqp-mxh4-f27w (CWE-400 / CWE-770, CVSS 3.1 6.5)"
readTime: "3 min read"
related: ["179", "152", "177"]
---

## Summary

Langflow's URL component fetched web pages by reading the complete response into memory, with no ceiling on size, redirect bodies, decompressed output, crawl breadth, or transfer time. When the component was attached to an Agent as a tool, the URL could be supplied by a chat message, so any user able to message the flow could direct the server to download an arbitrarily large response. Version 1.13.0 streams bodies against byte limits.

## What was observed

The advisory was published on 05 Nov 2026 and credits AgentSec as reporter. Per the advisory, the component did not stream pages and never checked `Content-Length`. The body was copied again when decoded and then parsed up to three times with BeautifulSoup and lxml, multiplying peak memory. Redirect bodies were read in full. Compressed responses were decoded without an output limit, so a small compression bomb could expand to gigabytes. Crawling could fan out to thousands of pages, all retained in memory, and the `timeout` input had no upper bound.

```
# Illustrative
# Agent flow with URL component attached as a tool
# chat message: "summarise <attacker-hosted URL>"
# server fetches response -> buffers entire body -> decodes -> parses repeatedly
# endless or compressed response -> memory grows until the OS kills the process
```

The URL reached the component through the chat input, so the Playground, public or shared flows, and `/api/v1/run` were all usable entry points. The reporter's test pointed at a private address, which the SSRF protections added in versions 1.9 to 1.12 block. Those protections restrict destination, not size, so a public host still triggered the fault. The reporter observed Langflow reaching 100 GB of RAM. The advisory reports availability impact only, affecting all users of the instance and possibly other services on a shared host.

The mechanism is rated medium. The vulnerable path requires a flow that exposes the URL component to an agent, a common RAG configuration, and no data is exposed. The advisory's CVSS vector requires low privileges.

## Mitigation

Upgrade to Langflow 1.13.0 (and `langflow-base` and `lfx` 1.13.0). The fix, PR #15436, streams bodies and rejects those above a per-response limit, rejects oversized `Content-Length` values before reading, applies a shared byte budget across crawled pages, stops reading redirect bodies, and accepts only `gzip` and `deflate` with output limits. Two settings control the caps: `LANGFLOW_URL_COMPONENT_MAX_RESPONSE_BYTES` (default 10 MiB) and `LANGFLOW_URL_COMPONENT_MAX_TOTAL_BYTES` (default 100 MiB).

Where upgrading is not possible, do not expose flows using the URL component to untrusted users, run Langflow under a container or cgroup memory limit so only the container restarts, and route outbound HTTP through an egress proxy that caps response size. A destination allowlist addresses where a fetcher may connect; a separate byte budget is needed to bound what it accepts.
