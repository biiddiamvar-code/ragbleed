---
caseId: "179"
title: "MCP Python SDK stateful Streamable HTTP transport never reclaimed session state, allowing unauthenticated memory exhaustion"
filed: "2026-10-22"
filedDisplay: "22 Oct 2026"
firstObserved: "30 Sep 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "mcp (PyPI, >=1.8.0, <1.30.0 and >=2.0.0, <2.2.0; patched in 1.30.0 and 2.2.0)"
cve: "CVE-2026-59951 (GHSA-84m7-p3x7-pcfv, CWE-400 / CWE-770 / CWE-772, CVSS 4.0 6.9)"
readTime: "3 min read"
related: ["109", "075", "100"]
---

## Summary

The MCP Python SDK's Streamable HTTP server, in its default stateful mode, kept every session it created for the life of the process. Sessions had no expiry, no cap, and several exit paths that left state registered. A client able to reach the endpoint could grow server memory without bound using ordinary short requests. Versions 1.30.0 and 2.2.0 add idle expiry, a session cap, and prompt cleanup.

## What was observed

The advisory was published to the repository on 30 Sep 2026, to the NVD on 14 Oct 2026, and to the GitHub Advisory Database on 15 Oct 2026. Per the advisory, five conditions combined in stateful mode: sessions never expired; a client `DELETE` ended a session but left its entry registered; a session whose first request was refused kept a running task; each session retained its parsed `initialize` parameters; and the number of sessions was unlimited. Only a process restart released the memory.

```
# Illustrative
# loop: POST initialize  -> new session registered, params retained
#       DELETE session   -> session ended, entry not removed
# no authentication step required; memory grows per iteration
```

Affected servers were those using the stateful Streamable HTTP transport: `FastMCP` in 1.x, `MCPServer` and `Server.streamable_http_app()` in 2.x, and `StreamableHTTPSessionManager` directly. Servers running with `stateless_http=True` (available from 1.12.0), and servers using only stdio or SSE, were not affected. The advisory scores impact as low availability with no confidentiality or integrity effect, and credits rharang as finder, with evilgensec, Madan301 and nickelsec as reporters. The advisory notes that authentication limits who may open sessions but not how many a token holder may open.

Rubric rating is medium. The vulnerable mode is the default of a widely used SDK, and an MCP server fronting a retrieval pipeline loses its tool surface when the process is exhausted, but no data is exposed.

## Mitigation

Upgrade to `mcp` 1.30.0 (1.x) or 2.2.0 (2.x). The fix adds `session_idle_timeout` (default 1800 seconds), `max_sessions` (default 10000, excess requests receive `503`), and removal of sessions that end by `DELETE`, expiry, or a refused opening request. Setting these options to `None` disables them. On small hosts, lower the three limits and `max_request_body_size`, since a live session still holds its `initialize` parameters, up to roughly twice the 4 MiB body limit. Where per-session state is unnecessary, use `stateless_http=True`. Per-session allocation reachable before or without authentication needs an explicit lifetime and a ceiling in any server, not only this one.
