---
caseId: "061"
title: "Open WebUI's knowledge-search let any user pin a worker with a catastrophically backtracking regex"
filed: "2026-08-10"
filedDisplay: "10 Aug 2026"
firstObserved: "04 Aug 2026"
severity: medium
category: "Denial of service / resource exhaustion"
status: "Patched"
affectedSystems: "Open WebUI (pip package, >=0.9.6, <0.11.0)"
cve: "CVE-2026-70493"
readTime: "4 min read"
related: ["029", "035", "011"]
---

## Summary

Open WebUI's built-in knowledge-base search tool lets a chat participant supply the pattern used to grep files in a knowledge collection. That pattern was compiled with Python's standard backtracking `re` engine and run synchronously against every line of every reachable file, with no complexity screening and no execution timeout anywhere on the path. A single request carrying a pattern built from nested quantifiers, matched against one short line of text, pinned a CPU core indefinitely; because the search ran inside the async event loop rather than off it, that worker stopped serving every other request while it spun. Fixed in 0.11.0.

## What was observed

The knowledge-search feature exists so a model or user can query documents already ingested into a knowledge base by pattern rather than by semantic similarity. The pattern parameter accepted arbitrary regex metacharacters and was handed directly to `re.compile()` and then repeated `re.search()` calls over file contents, with no check for constructs known to cause catastrophic backtracking — nested quantifiers such as `(a+)+` or `(a|a)+` — and no timeout wrapping the match call.

```
# grep_knowledge_files compiled the caller's pattern as-is
# and ran it synchronously inside the event loop
pattern = re.compile(user_supplied_pattern)   # e.g. "(a+)+$"
for line in file_contents:
    pattern.search(line)   # exponential blow-up on adversarial input, no timeout
```

Because Python's `re` module backtracks exponentially on patterns like this against a crafted input line, a payload only a few dozen characters long was enough to occupy a worker for well over a minute per request, and repeatable at will. The search running synchronously inside the asyncio event loop — rather than in a thread pool or subprocess — meant the stall wasn't confined to the requesting user's own connection: in Open WebUI's common single-worker deployment default, one authenticated user's crafted query froze the entire instance for every concurrent user.

## Mitigation

Upgrade to Open WebUI 0.11.0 or later, which fixes the underlying compilation path. Where upgrading isn't immediate, restrict knowledge-base search access to trusted users, or front the deployment with a request-level timeout that can kill a stalled worker before it exhausts a full request cycle. The broader pattern matches case 029's vLLM regex DoS: any feature that compiles a caller-supplied pattern, grammar, or expression needs its own resource budget — a timeout and a complexity screen — enforced independently of the language runtime's own execution semantics, because Python's backtracking engine will run an adversarial pattern for as long as the process lets it.
