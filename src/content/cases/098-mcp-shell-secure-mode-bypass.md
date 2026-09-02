---
caseId: "098"
title: "mcp-shell shipped secure mode off by default, and its allowlist let shell interpreters and git aliases through anyway"
filed: "2026-09-02"
filedDisplay: "02 Sep 2026"
firstObserved: "25 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "mcp-shell (all versions <0.6.0)"
cve: "CVE-2026-55580 (insecure-by-default config + shell-interpreter allowlist bypass); CVE-2026-55582 (git shell-alias allowlist bypass, GHSA-74hp-mggr-hv58)"
readTime: "5 min read"
related: ["085", "042", "096"]
---

## Summary

mcp-shell is an MCP server that gives a connected LLM a `shell_exec` tool for running commands on the host. Its "secure mode" was meant to restrict that tool to an allowlist of approved executables. Two disclosures published together on the same day showed the restriction didn't hold anywhere it mattered: the from-source install path shipped with security disabled and no warning, and the Docker image's own example allowlist included `/bin/bash` and `/usr/bin/python3` — interpreters that swallow the allowlist's metacharacter filtering whole. A third path let an attacker reach an interactive shell through a Git command-line flag the validator didn't know to block. All three converge on the same outcome: an LLM connected to mcp-shell, whether by a malicious tool description or a prompt-injected document, could reach arbitrary OS command execution with no additional privilege.

## What was observed

The bare mcp-shell binary initialized its `SecurityConfig` with `Enabled: false`, and the validator's own debug log made the consequence explicit — a disabled config caused every command to pass with no allowlist check at all. The README's documented from-source install path (clone, `make install`, run) set no environment variable and pointed to no config file, so anyone following the quick-start ran an unrestricted shell-execution server without knowing it. The documented MCP client config block had the same gap: it passed a log-level variable but never the one that loads `security.yaml`.

Docker users who did follow the security guidance fared little better. The image's shipped `security.yaml` allowlisted `/bin/bash` and `/usr/bin/python3` alongside safer utilities. Secure mode's validator split the submitted command on whitespace, checked the resulting executable against the allowlist, and rejected known shell metacharacters (`| & ; < > ( ) { } [ ] $` and backtick) in the arguments — but a call like `shell_exec(command="/bin/bash -i")` parsed to an allowlisted executable and a flag containing none of the blocked characters:

```
# secure-mode command parsing, illustrative
executable, args := parseCommand(command)   // "/bin/bash", ["-i"]
if executable not in allowlist: reject()
if containsDangerousShellConstructs(args): reject()   // "-i" trips nothing
spawn(executable, args)   // interactive bash now owns the MCP stdin channel
```

Once `/bin/bash -i` or `/usr/bin/python3 <script>` launched, the interpreter — not mcp-shell's validator — decided what ran next, and interpreters read whatever they're handed. A separate flaw in the same allowlist covered Git specifically: the validator blocked shell metacharacters but not `!`, the prefix Git uses to run a configured alias as a shell command. `/usr/bin/git -c alias.pwn=!<command>` passed every check on the executable name and produced arbitrary command execution, again with Git sitting in the allowlist by default and the Docker image running as a non-root user with Git installed.

## Mitigation

Upgrade to mcp-shell 0.6.0 or later, which flips the default to security-enabled and removes shell interpreters (`/bin/bash`, `/bin/sh`, `/usr/bin/python3`) from the example allowlist in favor of narrow utilities that can't themselves spawn processes (`ls`, `cat`, `grep`, `head`, `wc`). Operators who customize `security.yaml` should treat any interpreter or version-control binary in an executable allowlist as equivalent to disabling the allowlist, since both absorb attacker-controlled arguments the validator never sees. As with case 085's Chainlit finding, an allowlist that checks the program name and filters known-bad characters in the arguments is not the same as constraining what the program can be made to do — interpreters and tools with their own command-execution flags defeat that model regardless of how thorough the character blocklist is.
