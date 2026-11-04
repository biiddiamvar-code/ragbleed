---
caseId: "193"
title: "AWS Serverless MCP Server built deployment-status paths from the project name without confining them, allowing JSON file reads and writes outside the status directory"
filed: "2026-11-04"
filedDisplay: "04 Nov 2026"
firstObserved: "02 Nov 2026"
severity: low
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "awslabs.aws-serverless-mcp-server (pip, <0.2.1; fixed in 0.2.1); write path requires the --enable-write flag"
cve: "CVE-2026-116635 (GHSA-r6mm-377j-qg8m, CWE-23 / CWE-36, CVSS 3.1 6.1; AWS Security Bulletin 2026-164-AWS)"
readTime: "3 min read"
related: ["110", "172", "004"]
---

## Summary

The deployment status component of the AWS Serverless MCP Server derived a file path from the serverless project name and did not confine that path to its intended directory. A relative traversal sequence or an absolute path in the project name pointed the component at JSON files elsewhere on the host. Version 0.2.1 fixes the confinement; the advisory lists no workaround.

## What was observed

The GitHub advisory, published 2 Nov 2026 and credited to a coordinated disclosure, states that the pathname built from the project name was not restricted to the deployment status directory. Both relative traversal (CWE-23) and absolute path (CWE-36) inputs were accepted.

The attacker precondition is influence over the agent, such as content that steers which project name the model passes to the tool. On the read side, the agent opened a JSON file outside the directory and its contents entered the agent's context. On the write side, enabled only when the server runs with `--enable-write`, the same input allowed JSON files outside the directory to be overwritten, which the advisory describes as clobbering deployment metadata.

```
# project name supplied by the agent (illustrative)
projectName = "../../other/dir/target"   # or an absolute path
# status path = <status_dir>/<projectName>.json  -> resolves outside <status_dir>
```

The advisory does not name the specific tool, the vulnerable code location, or a proof of concept, and none was independently verified here. Exploitation is not reported.

Severity is rated low, below the medium CVSS 3.1 score of 6.1. The reachable files are limited to JSON, the write path is opt-in, and the trigger depends on steering the agent rather than a direct network request.

## Mitigation

Upgrade `awslabs.aws-serverless-mcp-server` to 0.2.1 or later; the advisory states upgrading is the only fix. Until then, leave `--enable-write` off and avoid exposing the agent to untrusted content that could supply project names. Tool parameters that become filesystem paths must be resolved and checked against their base directory on the server side, regardless of what the model is expected to send.
