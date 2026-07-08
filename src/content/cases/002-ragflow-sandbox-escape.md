---
caseId: "002"
title: "RAGFlow sandbox escape lets low-privileged users run commands on the host"
filed: "2026-01-05"
filedDisplay: "05 Jan 2026"
firstObserved: "31 Dec 2025"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "RAGFlow (Docker and source-code deployments, versions prior to 0.23.0)"
cve: "CVE-2025-68700"
readTime: "5 min read"
related: ["003", "001", "004"]
---

## Summary

RAGFlow's Canvas CodeExec component runs user-submitted code inside a sandbox and returns the result. The code responsible for handling that return value passed the sandbox's own output straight into Python's `eval()` — turning a value the sandbox was supposed to contain into a second, unsandboxed execution path controlled entirely by the calling user.

## What was observed

Canvas, RAGFlow's workflow builder, includes a code-execution node intended for lightweight scripting inside a pipeline. The design assumes the sandbox is the trust boundary: whatever the user submits runs inside it, and only the sandbox's stdout comes back out. The flaw was in what happened to that stdout afterward — a single line fed it directly into `eval()`.

```
# agent/tools/code_exec.py — prior to 0.23.0
rt = eval(body.get("stdout", ""))
# "stdout" is fully controlled by the submitting user
```

Since stdout is exactly what the submitting user controls, this collapsed the entire sandbox boundary into an implementation detail. A normal, low-privileged authenticated account — not an admin, not an API key holder, just a regular login — could submit code whose output happened to be a second payload, and have that payload executed with the privileges of the host process, outside the sandbox entirely.

The estimated CVSS score for this issue was 9.9 — close to the ceiling — reflecting that no special access, no user interaction from anyone else, and no unusual configuration were required beyond having any account on the instance.

## Mitigation

Upgrade to RAGFlow 0.23.0 or later, which removes the `eval()` call on sandbox output. Until upgraded, disable or restrict access to the Canvas CodeExec component for any account tier below full trust, and treat any RAGFlow deployment where regular users can create or edit Canvas workflows as equivalent to giving them shell access to the host.
