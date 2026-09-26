---
caseId: "138"
title: "CodeWhale's js_execution tool skipped the environment scrubber, returning shell-exported secrets to the model's context"
filed: "2026-09-26"
filedDisplay: "26 Sep 2026"
firstObserved: "16 Jul 2026"
severity: medium
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "codewhale / codewhale-tui (>=0.8.41, <0.8.64); deepseek-tui npm (>=0.8.32, <0.8.41) and crate (>=0.8.32, <=0.8.41, no patched crate release)"
cve: "CVE-2026-75915 (GHSA-h539-c7r8-3xq4)"
readTime: "4 min read"
related: ["051", "033", "092"]
---

## Summary

CodeWhale, a terminal coding agent formerly published as deepseek-tui, gave the model a `js_execution` tool that ran model-written JavaScript in a local Node.js process. Every other process-spawning path in the agent passed through a `child_env` scrubber that cleared the environment and re-admitted only an allowlist of non-secret variables; `js_execution` did not. Any API key, cloud credential, or forge token exported in the user's shell was readable through `process.env`, and the tool returned that output to the transcript, where it became part of the next request sent to the LLM provider. Fixed in 0.8.64.

## What was observed

In early May 2026 the project added `child_env.rs`, a helper that calls `env_clear()` on a child command and then re-installs only variables passing `is_allowed_parent_env_key` — `PATH`, `HOME`, locale, temp-directory, proxy, and terminal settings. The shell tool, the Python REPL, and the MCP launcher were rewritten to use it. Four days later, `js_execution` was added in a separate commit that built its `node` command directly with `tokio::process::Command::new` and never called the helper. The child inherited the full parent environment.

```
// crates/tui/src/tools/js_execution.rs (vulnerable shape)
let mut cmd = tokio::process::Command::new(&node);
cmd.arg(&script_path);
cmd.current_dir(workspace);
// missing: child_env::apply_to_tokio_command(&mut cmd, ...)
// node inherits OPENAI_API_KEY, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, ...
```

The approval prompt described the tool as running model-provided code "in local Node.js execution sandbox." Apart from a 120-second timeout, no sandbox was applied: the process had full filesystem and network access in addition to the inherited environment. A snippet as short as `console.log(JSON.stringify(process.env))` returned every exported value as tool stdout. That stdout was appended to the conversation and shipped to the configured provider on the next turn, so secrets left the machine even when the model had no network tool and no intent to exfiltrate — they became provider-side log data.

The model did not have to be malicious. Instructions planted in a repository README, a fetched web page, or MCP server output were enough to make it issue the call. With a single user approval of what the prompt called a sandboxed snippet, or with no approval at all in auto-approve ("YOLO") mode, the environment was disclosed.

The advisory scored the issue CVSS 4.0 8.7 (high), modelling it as network-reachable with no user interaction. This file rates it medium: the disclosure required either a user approving the tool call or the non-default auto-approve mode, and the injected instruction had to reach the agent through content it was already processing.

## Mitigation

Upgrade to CodeWhale 0.8.64 or later, which routes `js_execution` through the same `child_env` scrubber as the other tools. The `deepseek-tui` crate line has no patched release; users on it should migrate to `codewhale-tui`. Independently of version, do not run coding agents from shells that export long-lived provider keys or cloud credentials, and keep auto-approve off for any tool that executes code.

The failure was a missed call site, not a design gap: the control existed and was applied everywhere except the newest spawn path. Any agent that centralizes process hardening in a helper needs a check — a lint, a test that enumerates spawners, or a wrapper that makes the raw constructor unreachable — so that the next tool added inherits the control by construction rather than by memory.
