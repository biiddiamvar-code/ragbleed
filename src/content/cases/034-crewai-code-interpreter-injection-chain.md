---
caseId: "034"
title: "A prompt injection into CrewAI's Code Interpreter chained into sandbox escape and host RCE"
filed: "2026-07-28"
filedDisplay: "28 Jul 2026"
firstObserved: "30 Mar 2026"
severity: high
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "CrewAI / crewai-tools — CodeInterpreterTool (Docker-fallback sandbox), JSON loader tool, RAG search tools; all four issues fixed in current releases as of PR #4791, #5309, #5310, #5315"
cve: "CVE-2026-2275, CVE-2026-2285, CVE-2026-2286, CVE-2026-2287"
readTime: "6 min read"
related: ["002", "006", "001"]
---

## Summary

Researcher Yarden Porat of Cyata found four vulnerabilities in CrewAI, the open-source multi-agent orchestration framework, that chain together into remote code execution on the host. An attacker who can inject text into a CrewAI agent's context — directly or through a retrieved document — could get the agent to invoke its own Code Interpreter tool, land in an under-restricted Python sandbox instead of the intended Docker container, and escape it. Two further bugs in the framework's file-loading and RAG search tools turned the same injection into arbitrary file read and SSRF, giving an attacker credential theft as a fallback even where the RCE path was blocked. CERT/CC coordinated the disclosure as VU#221883.

## What was observed

CrewAI's `CodeInterpreterTool` is documented to run agent-generated Python inside a Docker container. If Docker isn't reachable at the moment code execution is requested, the tool silently falls back to a local, non-containerized sandbox called SandboxPython rather than refusing to run. That fallback sandbox restricted certain built-in functions but never added `ctypes` to its blocked-module list (CVE-2026-2275), so code running inside it could call arbitrary C functions and step outside the sandbox entirely. A second gap (CVE-2026-2287) meant CrewAI didn't re-check that Docker was still available during execution, only at the start, so a agent could be steered into the same insecure fallback mid-run.

None of this requires a developer to be careless in an unusual way — it requires the ordinary case where `allow_code_execution=True` is set, or the Code Interpreter tool is attached to an agent, which is precisely what that tool is for. The attacker's entry point is prompt injection: text embedded in a document, a webpage, or any other input the agent retrieves and treats as data can instruct the agent to write and run code, or to invoke tools in a sequence the developer didn't anticipate.

```
# intended path: CodeInterpreterTool → Docker container → isolated execution
# actual path when Docker is unreachable:
#   CodeInterpreterTool → SandboxPython fallback → ctypes available →
#   arbitrary C function calls → sandbox escape → host RCE
```

The other two CVEs didn't need the sandbox at all. CVE-2026-2285 was an arbitrary local file read in CrewAI's JSON loader tool, which read whatever path it was given with no validation — usable for credential and config theft on its own. CVE-2026-2286 was an SSRF in the RAG search tools, which fetched attacker-supplied URLs at runtime without checking whether they pointed at internal services or cloud metadata endpoints. Chained with the sandbox issues, an attacker with prompt-injection access to an agent using these tools had a path to RCE where Docker was absent or misconfigured, and file read plus SSRF as a fallback everywhere else — enough on its own to pull credentials or reach internal infrastructure.

CrewAI's own response, recorded in the CERT/CC vendor statement, was candid about the design tradeoff: the sandbox fallback was "documented behavior," not a bug in isolation, but the company acknowledged users would reasonably expect Docker isolation to be enforced rather than silently downgraded.

## Mitigation

CrewAI's fix for CVE-2026-2275 and CVE-2026-2287 was to remove the CodeInterpreterTool and its sandbox fallback entirely, deprecating `allow_code_execution` in favor of external sandboxing services (E2B, Daytona, or similar) that don't degrade silently when unavailable. For CVE-2026-2285 and CVE-2026-2286, CrewAI added centralized `validate_file_path()` and `validate_url()` checks, now enforced across the JSON loader, RagTool, and more than twenty other tools, blocking path traversal and requests to private, internal, or cloud-metadata addresses by default.

Update to a current CrewAI release before re-enabling any code-execution tool, and treat every tool an agent can invoke as reachable by prompt injection, not just by the developer who wired it in — a tool that's safe when called deliberately is not safe by default when an agent can be talked into calling it by untrusted input. Silent fallback from a hardened execution path to a weaker one, on any resource unavailability, is a pattern worth auditing for beyond this one framework.
