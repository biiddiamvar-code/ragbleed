---
caseId: "134"
title: "ContextForge's python_sandbox_server left raw getattr in RestrictedPython's builtins and filtered dunders by literal string, allowing escape to subprocess.Popen"
filed: "2026-09-25"
filedDisplay: "25 Sep 2026"
firstObserved: "24 Aug 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "IBM mcp-context-forge (PyPI mcp-contextforge-gateway, <= 1.0.1), python_sandbox_server sub-project; core gateway and proxy not directly affected"
cve: "CVE-2026-53710 (GHSA-xm98-3vcf-fph7, PYSEC-2026-3862)"
readTime: "4 min read"
related: ["084", "070", "053"]
---

## Summary

ContextForge, IBM's open-source MCP gateway, ships a `python_sandbox_server` sub-project. It exposes an `execute_code` MCP tool that runs model- or user-supplied Python under RestrictedPython. That sandbox exposed Python's raw `getattr` builtin, and its pre-execution validator matched dangerous dunder names only as literal strings. Code that assembled those names at runtime passed validation, walked the class hierarchy to `subprocess.Popen`, and ran OS commands as the server process. If the tool was served over HTTP/SSE, which had no authentication layer, anyone who could reach the endpoint could do this. Fixed in 1.0.2.

## What was observed

The advisory named three weaknesses that combined into the escape. The first was in `server_fastmcp.py`, which placed the unmodified `getattr` builtin in the sandbox's `safe_builtins`. RestrictedPython normally rewrites attribute access so that it passes through a policy hook, `_getattr_`. A direct call to the real `getattr` skips that hook, so the sandbox's attribute policy never saw the lookup.

The second was `validate_code`, which scanned submitted source text for known-dangerous substrings such as literal dunder attribute names. A payload that concatenated or otherwise built those names at runtime never contained the literal string, so the validator returned `valid: True`.

```
# illustrative, not a working payload
# validator scans source text for "__subclasses__" etc. -> nothing found
name = "_" + "_sub" + "classes_" + "_"         # built at runtime
# raw getattr (not _getattr_) resolves it without policy mediation
# -> walk object hierarchy -> locate subprocess.Popen -> spawn a command
```

The third was deployment. The `execute_code` tool could be served over HTTP/SSE with no authentication on `tools/call`. ContextForge's documentation describes registering MCP servers like this one as gateways behind a running instance. The reporter's proof of concept ran against the pinned sandbox code: validation reported `Code passed validation`, and the transcript showed `subprocess.Popen` located and a marker command executed.

The advisory scored this CVSS 10.0, but that score assumes the sandbox server is reachable over HTTP without authentication. We rated it medium. The flaw sits in an optional sub-project, not in the core gateway. Reaching it requires an operator to deploy that server and expose it over a network transport, and stdio-only deployments sharply reduce the attack surface. Where it was exposed, the result was command execution on the host, plus whatever that host could reach through mounted volumes or its internal network.

## Mitigation

Upgrade mcp-contextforge-gateway to 1.0.2 or later (fix commit 63a2900). The advisory's recommended remediation was to remove raw `getattr` and `setattr` from `safe_builtins`, to allow dynamic attribute access only through policy-controlled wrappers, to replace substring filtering with a stricter RestrictedPython policy pipeline, and to require authentication on every HTTP `tools/call`. Operators should check that the version they deploy includes the authentication step rather than assuming it does. Until an instance is patched, run `python_sandbox_server` over stdio only, or put its HTTP transport behind authentication and network restrictions. In either case, run it in a container with no host mounts and no route to internal services.

Case 084 found that ContextForge's fix for prompt-template SSTI added validation that scans for dunder patterns. This case shows how that kind of check fails: a denylist of source-code substrings does not stop code that builds the forbidden name while it runs. A sandbox is only as strong as its narrowest builtin, and one unmediated `getattr` was enough to break this one.
