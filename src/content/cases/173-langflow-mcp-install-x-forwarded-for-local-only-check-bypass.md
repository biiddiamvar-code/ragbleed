---
caseId: "173"
title: "Langflow's MCP install endpoint trusted the client-supplied X-Forwarded-For header for its local-only check, letting a remote user write MCP entries into the server's IDE config files"
filed: "2026-10-17"
filedDisplay: "17 Oct 2026"
firstObserved: "13 Aug 2026"
severity: low
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "langflow (>=1.5.0, <1.10.3)"
cve: "CVE-2026-105741 (GHSA-4f6c-2vvp-gw82, CWE-290 / CWE-345, CVSS 3.1 7.1)"
readTime: "3 min read"
related: ["166", "167", "052"]
---

## Summary

Langflow's MCP project install endpoint restricted itself to local callers by reading the client IP, and the helper that derived the IP trusted the leftmost X-Forwarded-For entry. An authenticated remote user who sent `X-Forwarded-For: 127.0.0.1` passed the local-only check. The flaw shipped in langflow 1.5.0 and was fixed in 1.10.3.

## What was observed

The affected route was `POST /api/v1/mcp/project/{project_id}/install`. It was intended to run only from the machine hosting Langflow, since its function is to write an MCP server entry into the IDE configuration files of the user running the server (Cursor, Windsurf or Claude Desktop). The `get_client_ip` helper used for that check took the first value of the X-Forwarded-For header without verifying that a trusted proxy had set it. The header is fully controlled by the client.

```
# POST /api/v1/mcp/project/<project_id>/install    (authenticated, remote)
# X-Forwarded-For: 127.0.0.1
# get_client_ip() -> "127.0.0.1"   (leftmost header value, no proxy trust check)
# local-only check passes -> MCP entry written to config file in server user's home
```

The advisory corrects its own original report on impact. The caller could not choose an arbitrary file path; writes were limited to the fixed IDE and MCP configuration locations in the server user's home directory. The realistic consequence was injection or corruption of an MCP server entry in those files, which a desktop client running on the same host could later load. Exploitation required a valid account. The CVSS 3.1 score of 7.1 reflects the high integrity rating; this entry rates the mechanism low because the writable surface is a fixed set of files that only matter when an IDE client runs on the Langflow host.

The fix (pull request #13915, backported as #14071) made `get_client_ip` use the TCP peer address by default and ignore X-Forwarded-For unless the operator sets `rate_limit_trust_proxy` to true, in which case the rightmost entry is used. A narrower bypass that needs that setting enabled behind a proxy sending repeated header lines was fixed separately in 1.11.3 (#14425).

## Mitigation

Upgrade langflow to 1.10.3 or later; 1.11.3 or later also closes the repeated-header variant. Leave `rate_limit_trust_proxy` at its default unless a proxy that overwrites X-Forwarded-For sits in front of the service. Strip the header at the edge for external traffic. A network location check built on a forwarded header is a client-controlled value and cannot serve as an authorization boundary.
