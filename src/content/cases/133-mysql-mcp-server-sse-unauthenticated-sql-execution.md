---
caseId: "133"
title: "mysql_mcp_server's SSE transport bound to all interfaces with no authentication and DNS-rebinding protection off, exposing raw SQL execution"
filed: "2026-09-25"
filedDisplay: "25 Sep 2026"
firstObserved: "11 Sep 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "mysql-mcp-server (PyPI, designcomputer/mysql_mcp_server, all versions < 0.4.2) when run with MCP_TRANSPORT=sse; default stdio mode not affected"
cve: "CVE-2026-59971 (GHSA-rqfv-2mw9-78g2)"
readTime: "4 min read"
related: ["086", "087", "132"]
---

## Summary

mysql_mcp_server gives an LLM agent an `execute_sql` tool that passes the model's query straight to a MySQL connection. When run over the SSE transport, the server listened on 0.0.0.0, required no credentials on any route, and built its MCP transport without the SDK's DNS-rebinding protection. Anyone who could reach the port, or any web page able to rebind a hostname to the victim's loopback address, could call `execute_sql` directly and read, change, or delete the configured database. Fixed in 0.4.2.

## What was observed

The GitHub advisory traced the flaw to five settings in `src/mysql_mcp_server/server.py`, each with an insecure value. `SseServerTransport` was created without a `security_settings` argument, and the MCP Python SDK leaves `enable_dns_rebinding_protection` set to `False` unless a caller turns it on. As a result, the server never checked `Origin` or `Host` headers. The Starlette application had no CORS or TrustedHost middleware. None of its three routes (`/`, `/sse`, `/messages/`) required authentication. The default bind address was `0.0.0.0`. At the end of that chain, the `execute_sql` tool handed a caller-supplied string to `cursor.execute(query)` without changing it.

```
# server.py, illustrative
transport = SseServerTransport("/messages/")   # no security_settings -> no Origin/Host check
app = Starlette(routes=[...])                  # no auth, no TrustedHost, no CORS
uvicorn.run(app, host="0.0.0.0", ...)          # every interface
# execute_sql -> cursor.execute(query)         # query taken verbatim from the tool call
```

The advisory described two ways in. In the first, a network attacker called the tool directly over the exposed port. In the second, the operator had bound the server to localhost and assumed it was private. An attacker lured the operator's browser to a page, rebound the attacker's domain to 127.0.0.1, and used the browser as a same-origin proxy to issue `tools/call` requests. Either path gave the attacker the full rights of the configured MySQL account: they could dump data, modify it, or drop tables. If that account held the `FILE` privilege, `LOAD_FILE` and `SELECT ... INTO OUTFILE` also let the attacker read and write files on the database host, which could be used to plant a web shell. The reporters found 25 SSE instances of the project reachable from the public internet.

The default stdio transport was not affected. We rated this high, in line with the CVSS 10.0 score, even though SSE is opt-in. Once an operator chose SSE, the only thing between an anonymous caller and the whole database was the network, and in the rebinding case not even that.

## Mitigation

Upgrade to mysql-mcp-server 0.4.2 or later. That release passes `TransportSecuritySettings(enable_dns_rebinding_protection=True)` to `SseServerTransport` and changes the recommended bind address to `127.0.0.1`. The advisory lists no authentication change in that release, so any SSE deployment reachable beyond the local machine still needs an authenticating reverse proxy. Run the server under a MySQL account limited to the schemas the agent needs. Never grant that account `FILE`, `SUPER`, or DDL rights, and grant it write access only when the use case requires it. Operators who ran an exposed SSE instance should review the MySQL general or audit log for queries the agent did not issue.

Every MCP server built on the Python SDK's SSE transport inherits the same default. If the code does not pass `security_settings`, the server has no Origin or Host checking, no matter what it exposes.
