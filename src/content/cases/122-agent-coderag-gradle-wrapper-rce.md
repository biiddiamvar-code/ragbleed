---
caseId: "122"
title: "agent-coderag's default sync flow executes a repository-controlled Gradle wrapper"
filed: "2026-09-16"
filedDisplay: "16 Sep 2026"
firstObserved: "18 Jun 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "agent-coderag / CodeRAG (PyPI package, versions <=1.3.0)"
cve: "CVE-2026-57586 (GHSA-wg5p-8h9p-3mr7); advisory first published 19 Jun 2026, formal CVE ID assigned 15 Sep 2026"
readTime: "4 min read"
related: ["024", "103", "107"]
---

## Summary

CodeRAG (distributed as the `agent-coderag` PyPI package) is a semantic code search and distillation tool that AI coding agents call to index a repository before answering questions about it. Its default `sync` command, run automatically as part of indexing, executed the target repository's own `gradlew` wrapper script whenever a `build.gradle` or `build.gradle.kts` file was present, with no check on what that script actually contained. Anyone who could get a victim, or an automated pipeline, to point `agent-coderag sync` at a directory they controlled — a cloned repository, a pull-request checkout — could plant a malicious `gradlew` and obtain code execution as that victim. No authentication, no flags, and no elevated privileges were required; the flaw fired on the tool's ordinary, documented invocation.

## What was observed

The vulnerability (CWE-78, OS command injection) sat in a four-step call chain inside `agent-coderag`'s dependency-discovery logic. The `sync` entry point in `cli.py` called `sync_dependencies()` unconditionally for any indexed path — there was no opt-in flag gating this behavior. `manager.py` then treated the mere presence of a `build.gradle` or `build.gradle.kts` file as sufficient grounds to invoke `_sync_gradle()`. That function chose which Gradle binary to run: if a repository-local `gradlew` or `gradlew.bat` existed, it was preferred unconditionally over the system-installed `gradle`, with no signature check, content inspection, or integrity verification. The resolved path was then passed straight to `asyncio.create_subprocess_exec()`, with the repository root as the working directory. A separate `validate_path` helper constrained where on disk the indexed directory could live, but it validated location only — never what the executable at that location actually did.

```
# illustrative: what the target repository needed to contain
# build.gradle        -> triggers Gradle-project detection
# gradlew (executable) -> executed directly, unvalidated, by "agent-coderag sync <path>"
```

Because `agent-coderag`'s entire purpose is to read repositories rather than run them, the trust violation extended past the tool itself: a developer indexing an untrusted clone, or a CI pipeline that automatically ran `agent-coderag sync` against incoming pull-request branches, would execute attacker-supplied code with the full privileges of whatever indexed the repository. The CVSS vector (`AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`, 8.6) marks the attack as local with required user interaction, but the "interaction" required was simply running the tool as documented against a path an attacker influenced — a routine step for a tool built to index arbitrary codebases.

## Mitigation

The fix, shipped in 1.3.1, is not documented in detail in the public advisory beyond the version bump; operators should upgrade past 1.3.0 and, in the interim, treat any Gradle-based repository as untrusted input before indexing it — running `agent-coderag sync` inside a container or otherwise isolated environment with no access to credentials or the host filesystem removes the blast radius even if the wrapper executes. CI pipelines that auto-index pull-request branches from external contributors are the highest-risk deployment pattern here and should not run indexing tools with standing access to secrets. The broader lesson generalizes past this one tool: any pipeline that treats "read this repository" and "execute what this repository tells you to execute" as the same operation has already lost the trust boundary it was trying to keep.
