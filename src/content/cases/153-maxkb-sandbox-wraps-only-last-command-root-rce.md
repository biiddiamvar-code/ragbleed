---
caseId: "153"
title: "MaxKB's agent sandbox wrapped only the last command in a chain, so crawled web content could run commands as root"
filed: "2026-10-07"
filedDisplay: "07 Oct 2026"
firstObserved: "08 Jul 2026"
severity: high
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "MaxKB (FIT2CLOUD), versions up to and including 2.10.4-lts; fixed in 2.10.5-lts"
cve: "CVE-2026-77521 (\"MaxKBypass\")"
readTime: "3 min read"
related: ["002", "041", "034"]
---

## Summary

MaxKB agents can execute shell commands through a sandbox helper. The helper applied its privilege-dropping wrapper only to the final command in a model-supplied string, so any separator placed before it ran in the outer root shell. Because MaxKB can crawl public websites into its knowledge base, an attacker who controlled page content could plant instructions that reached this tool during an ordinary user conversation. Lasso Research reported a CVSS score of 10.0.

## What was observed

Lasso Research reported the flaw to FIT2CLOUD on 08 Jul 2026. The vendor acknowledged it the next day, received a reproducible container proof of concept on 10 Jul 2026, and released 2.10.5-lts on 06 Aug 2026. The CVE was disclosed publicly on 02 Sep 2026.

The root cause sat in `sandbox_shell.py`. The module prefixed the command string with a `gosu` wrapper that drops privileges, but it treated the model's output as a single opaque string. Shell metacharacters (`;`, `|`, `$(...)`, `>`) in that string split it into several commands, and only the last one inherited the wrapper. Everything before it executed in the parent shell with root privileges.

```
# Illustrative, MaxKB <= 2.10.4-lts
# model-supplied command:   <payload> ; harmless-looking-command
# executed as:              <payload> ; gosu sandbox harmless-looking-command
#                           ^ runs as root, outside the sandbox
```

The delivery path required no access to the MaxKB instance. An attacker published instructions on a web page, an operator crawled that page into a knowledge base, and a later retrieval placed the text in a victim's agent context. The model then emitted the chained command as a tool call. Retrieval of the poisoned chunk was the only trigger.

The rubric rating is high and agrees with the CVSS headline: the vulnerable tool ships as part of the agent feature, the injection source is public web content, and the outcome is root command execution on the host.

## Mitigation

Upgrade MaxKB to 2.10.5-lts or later. The fix parses the model-supplied command and applies the sandbox prefix to every component, rather than prepending it to the concatenated string. Deployments that cannot upgrade immediately can disable agent shell tools and avoid crawling untrusted sites into knowledge bases that feed tool-enabled agents.

A sandbox that wraps a string rather than a parsed command isolates only what the shell parser lets it see.
