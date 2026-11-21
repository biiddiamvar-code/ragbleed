---
caseId: "217"
title: "mcp-ssh-manager concatenated unescaped tool arguments into remote shell commands for its backup tools, and ssh_backup_list skipped the policy check that readonly mode relied on"
filed: "2026-11-21"
filedDisplay: "21 Nov 2026"
firstObserved: "28 Aug 2026"
severity: medium
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "mcp-ssh-manager (npm, bvisible/mcp-ssh-manager, <= 3.8.4; fixed in 3.8.5)"
cve: "CVE-2026-129995 (GHSA-qwwm-vrm9-4mw8, CWE-78, CVSS 3.1 8.8)"
readTime: "3 min read"
related: ["098", "056", "085"]
---

## Summary

mcp-ssh-manager, an MCP server that lets agents manage remote hosts over SSH, built the shell commands for its four `ssh_backup_*` tools by concatenating caller-supplied tool arguments with no shell escaping. Any value reaching those arguments, including one placed there by indirect prompt injection, executed as arbitrary commands on the managed server as the configured SSH user. One of the four tools, `ssh_backup_list`, also bypassed the server's policy layer entirely, so the injection remained reachable on servers hardened to readonly or restricted mode.

## What was observed

The maintainer published GHSA-qwwm-vrm9-4mw8 on 28 Aug 2026, crediting reporter Woojisoo0425; CVE-2026-129995 was published on 20 Nov 2026. The advisory describes the issue as a parallel to CVE-2026-77383 (GHSA-4jx9-2fwj-pg4j), whose earlier fix added shell quoting to `src/database-manager.js` but did not reach the backup command builders in `src/backup-manager.js` and the inline backup handlers in `src/index.js`.

Those builders appended values such as database names, paths and schedule fields directly into a command string, which was then passed to `ssh.execCommand()` and interpreted by the remote login shell. Shell metacharacters in any of those fields terminated the intended command and started a new one.

```
// backup command builder (illustrative of the advisory's excerpt)
command += ` ${database}`;        // fully unquoted, caller-controlled
ssh.execCommand(command);         // run by the remote login shell
// database = "prod; <arbitrary command>"  -> second command runs as the SSH user
```

In the default `unrestricted` mode all four tools were reachable, and `ssh_backup_schedule` could install the injected command into cron for persistence. Operators who switched to `readonly` or `restricted` mode were not protected: `ssh_backup_list` was absent from `READONLY_BLOCKED_TOOLS`, and its handler never called `applyServerPolicy`, so it ran with no mode enforcement at all. The advisory states that no exploitation occurred when a fully trusted operator supplied only benign values; the realistic delivery path was a compromised MCP client or tool arguments steered by content the agent had read.

Severity is rated medium, below the CVSS 3.1 score of 8.8. Exploitation required control over tool arguments, which in practice meant a successful prompt injection or a compromised client, and in the default unrestricted mode the agent already held broad command authority over the managed hosts. The finding that changes the risk picture is the readonly bypass: an operator who deliberately restricted the server lost that boundary without any signal.

## Mitigation

Upgrade mcp-ssh-manager to 3.8.5 or later. Review crontabs on every managed host for entries created through `ssh_backup_schedule` during the affected period. Run the server with an SSH account scoped to the minimum privileges each host requires, and do not expose it to agents that process untrusted content (web pages, tickets, email) without human approval on tool calls.

A readonly mode is only as strong as the one tool handler that forgot to ask for it.
