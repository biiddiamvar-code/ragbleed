---
caseId: "174"
title: "Langflow's MCP stdio transport passed the user-supplied server command through a shell wrapper with no validation, giving code execution on the host under default AUTO_LOGIN"
filed: "2026-10-17"
filedDisplay: "17 Oct 2026"
firstObserved: "5 Oct 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "langflow (<1.10.3); langflow-base (<0.10.3); lfx (<1.10.3)"
cve: "CVE-2026-105697 (GHSA-w794-rj3p-xv45, CWE-78, CVSS 9.9 per secondary databases)"
readTime: "3 min read"
related: ["052", "155", "166"]
---

## Summary

Langflow allowed users to register MCP servers that run as local subprocesses over stdio. The command and arguments were passed to a shell wrapper without validation or an allowlist, so the configured string executed on the Langflow host. Because `LANGFLOW_AUTO_LOGIN` defaults to true, the path was reachable without credentials in default deployments. The flaw was fixed in langflow 1.10.3.

## What was observed

The stdio transport in `src/lfx/src/lfx/base/mcp/util.py` launched the configured server command through `bash -c` on Linux and macOS and `cmd /c` on Windows. The command was accepted through `POST` and `PATCH /api/v2/mcp/servers/{server_name}` and through the Add MCP Server dialog in the settings UI. Shell metacharacters, and manipulation of variables such as IFS and BASH_ENV, were passed through to the shell.

```
# PATCH /api/v2/mcp/servers/<name>
# command: "<arbitrary shell string>"      (no allowlist, no validation)
# any later connect attempt -> bash -c "<arbitrary shell string>"
# triggers: list servers, load tools, run a flow; server need not start successfully
```

Execution occurred on the first connection attempt, so listing servers, loading tools or running a flow was sufficient, even when the configured server then failed to start. With `LANGFLOW_AUTO_LOGIN=true`, `GET /api/v1/auto_login` issued a token without credentials, which made the chain unauthenticated. With auto login disabled, any authenticated non-admin user could still register a server. Scoring varied between sources: one database rated confidentiality impact low while its own CVSS vector indicated high, so the figures here are taken from the vector and not the label. Root cause detail comes from secondary vulnerability databases summarizing the NVD record and the fix commits; the primary advisory page could not be retrieved during this review.

The fix (commits eba285edf1 and efbc4a16e, pull requests #12290 and #14036) added `validate_mcp_stdio_config`, an allowlist-based command policy, and validation of arguments and environment variables.

## Mitigation

Upgrade langflow and lfx to 1.10.3 or later, and langflow-base to 0.10.3 or later. Set `LANGFLOW_AUTO_LOGIN=false` and keep the service off untrusted networks until the upgrade is applied; review registered MCP servers for commands outside the expected set. Any feature that stores a command line and executes it later is a code execution interface, and requires the same allowlisting as a shell.
