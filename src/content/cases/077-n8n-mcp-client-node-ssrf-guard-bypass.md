---
caseId: "077"
title: "n8n's MCP Client node sent user-supplied server URLs around the platform's own SSRF guard"
filed: "2026-08-20"
filedDisplay: "20 Aug 2026"
firstObserved: "22 Jul 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "n8n (>=2.32.0, <2.32.1; and all versions <2.31.5), MCP Client node"
cve: "CVE-2026-72768 (GHSA-vhf8-cg2h-cg3p)"
readTime: "4 min read"
related: ["009", "050", "010"]
---

## Summary

n8n maintains a central SSRF-protection layer that resolves a target host, checks the resolved address against a blocklist of internal and link-local ranges, and pins the connection to that checked address before letting a workflow node make an outbound HTTP call — the standard defense against a workflow author, or data a workflow ingests, redirecting the server at itself. The MCP Client node, which lets an n8n workflow connect to an external Model Context Protocol server and call its tools, never routed its own outbound connection through that layer. Any authenticated user able to create or edit a workflow could point the node at an internal address and read the response back through the workflow, unfiltered by the protection the rest of the platform relies on.

## What was observed

n8n's SSRF guard is built to close the usual bypass in this class of defense: check a hostname, then let a subsequent DNS lookup return a different address than the one that was checked. It does this by resolving the address once, validating that resolved IP, and pinning the outbound request to it. The MCP Client node — added to let workflows, and by extension AI agents built on those workflows, talk to arbitrary MCP servers — took its server URL from node configuration and handed it directly to the HTTP client, skipping both the resolution check and the pin.

```
# illustrative: MCP Client node request path, pre-fix
server_url = node_config.mcp_server_url        # workflow-author controlled
response = http_client.request(server_url)     # bypasses n8n's SSRF resolver/pin entirely
```

The node's purpose — dialing out to whatever MCP endpoint a workflow names — put it on the same trust boundary the platform's SSRF guard exists to police everywhere else: a workflow author (or, indirectly, data a workflow processes and feeds into the node's configuration) could name an internal service, a metadata endpoint, or any other address the guard was meant to block, and get its response back in the workflow output. As n8n workflows increasingly serve as the orchestration layer connecting AI agents to internal tools and data sources, the MCP Client node is exactly the kind of connector attackers would expect to reach furthest into a deployment's internal network — which made it a conspicuous gap that the platform's own protection simply didn't cover.

## Mitigation

Fixed in n8n 2.31.5 and 2.32.1, which route MCP Client node requests through the same SSRF protection applied to other outbound-request nodes. Deployments on 2.32.0 up to but not including 2.32.1, or any version before 2.31.5, should upgrade immediately. Where upgrading isn't immediate, n8n's advisory recommends restricting instance access to trusted users, disabling the MCP Client node via its `NODES_EXCLUDE` environment variable, and restricting network egress from the n8n host — all explicitly framed as temporary, since none of them close the gap the way the fix does. The recurring failure mode here isn't the SSRF bug itself but its scope: a platform can build a correct, centralized SSRF defense and still ship vulnerable if every new connector isn't independently verified to route through it — protection that exists elsewhere in the codebase provides no guarantee about the node added last week.
