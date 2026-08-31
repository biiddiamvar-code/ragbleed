---
caseId: "094"
title: "PraisonAI's MCP server joined attacker-supplied filenames onto a rules directory with no containment check"
filed: "2026-08-31"
filedDisplay: "31 Aug 2026"
firstObserved: "03 May 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "PraisonAI (pip package, <= 4.6.33; fixed in 4.6.34)"
cve: "CVE-2026-44336"
readTime: "5 min read"
related: ["085", "045", "042"]
---

## Summary

PraisonAI's MCP server registers four file-handling tools the moment `praisonai mcp serve` starts, with no flag to disable them. Each tool takes a filename or path string from the incoming `tools/call` arguments and writes, reads, or deletes a file built from that string without checking whether the result stays inside the intended directory. Because the JSON-RPC dispatcher passes those arguments straight into the handler without validating them against the tool's own advertised schema, a traversal sequence in the filename walked the operation out of `~/.praison/rules/` and onto any path the running user could touch — and a Python `.pth` file dropped that way runs as code the next time the user starts any Python interpreter.

## What was observed

The dispatcher resolved a tool by name and called its handler with the raw arguments dictionary unpacked as keyword arguments, skipping the schema check that was built for exactly this purpose:

```
# tool.handler(**arguments)   <- arguments come straight from tools/call,
#                                 never validated against tool.input_schema
```

Downstream, the `rules.create`, `rules.show`, and `rules.delete` handlers built a filesystem path by joining the rules directory with the caller-supplied `rule_name` using ordinary string interpolation, and a fourth tool, `workflow.show`, accepted an absolute path outright. None of the four canonicalized the result or checked that it still began with the rules directory, so a `rule_name` of `../../<target>` escaped containment at `open()` time exactly as written. Writing a `.pth` file into the user's Python site-packages directory turned that arbitrary-write primitive into code execution, since CPython imports any line beginning with `import` from every `.pth` file present at interpreter startup — meaning the payload didn't have to run inside PraisonAI itself, only inside whatever Python process the user happened to start next. The realistic delivery path didn't require a compromised operator at all: an MCP-connected LLM (Claude Desktop, Cursor, Continue.dev) reading a web page or document containing hidden instructions could be induced to emit the malicious `tools/call` on the model's own initiative, since many MCP clients auto-approve a tool named `rules.create` as sounding benign. Separately, `praisonai mcp serve --transport http-stream` shipped with no API key by default, so the same unvalidated dispatcher was also reachable from any other process sharing the loopback interface.

## Mitigation

Upgrade to PraisonAI 4.6.34 or later, which adds containment checks to the file-handling tools and enforces the advertised input schema before dispatch. Operators who cannot upgrade immediately should set an API key on any HTTP-stream deployment and avoid running the MCP server on hosts shared with untrusted processes or containers. The broader lesson holds across most of the MCP path-traversal cases in this archive: an MCP tool's JSON schema describes what a well-behaved client will send, not what the server will accept, and a dispatcher that skips schema enforcement turns every file-handling tool into an open filesystem primitive the moment an LLM — trusted or prompt-injected — decides to call it.
