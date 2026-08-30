---
caseId: "092"
title: "Context7's Custom AI Instructions fed unsanitized text into every coding agent that queried a poisoned library"
filed: "2026-08-31"
filedDisplay: "31 Aug 2026"
firstObserved: "18 Aug 2026"
severity: high
category: "Prompt injection (direct or indirect)"
status: "Disclosed, patch guidance pending"
affectedSystems: "Context7 (Upstash), @upstash/context7-mcp MCP server, Custom AI Instructions feature (advisory affected range: through 2.1.2; status of the current 4.0.x line undocumented)"
cve: "CVE-2026-75130"
readTime: "6 min read"
related: ["033", "055", "069"]
---

## Summary

Context7 is Upstash's MCP documentation server, installed inside Cursor, Claude Code, Windsurf, and other coding agents to pull up-to-date, version-specific library documentation on request. NVD published CVE-2026-75130 on 18 Aug 2026: Context7's Custom AI Instructions feature can inject unsanitized content into a connected coding agent's context when the agent makes an ordinary library-documentation request, and the advisory documents credential exfiltration from environment files and destructive local file deletion as consequences. No GitHub Security Advisory, patched version, or vendor statement is on record for this specific CVE as of this writing. The confirmed technical mechanism below comes from Noma Security's first-hand research into the same feature under an earlier disclosure; whether the August CVE describes a fresh regression of that exact flaw or a related-but-distinct gap in the same feature is not established in the public record, and this file says so rather than guessing.

## What was observed

Context7 lets library maintainers attach "Custom AI Instructions" (also documented as "Custom Rules") to their library's entry through a dashboard, intended to help a coding agent use that library correctly. The MCP server itself is minimal by design — it exposes exactly two read-only tools, `resolve-library-id` and `query-docs`, and cannot execute code, write files, or make network requests on its own. The problem, per Noma Security's first-hand technical writeup of the underlying vulnerability class, is that those custom instructions were served verbatim alongside real documentation through the same MCP channel, with no sanitization and no signal distinguishing attacker-supplied text from vendor-authored docs. A connected coding agent — which does hold file, shell, and network access — has no protocol-level way to tell the two apart, and treats both as trusted context.

```
# illustrative sequence, not exploit code
1. attacker publishes/claims a library entry on Context7's public registry
2. attacker attaches poisoned Custom AI Instructions to that entry
3. a developer asks their coding agent a routine question about the library
4. the agent's query-docs call returns real documentation plus the poisoned instructions, undifferentiated
5. the agent, trusting its own MCP context, acts on the poisoned instructions with its own tool access
```

In Noma's documented proof of concept against this feature, three chained instructions were sufficient: one directed the agent to read local `.env` files, a second directed it to post their contents to an attacker-controlled endpoint, and a third directed it to delete local files under a "cleanup" pretense — all triggered by what looked to the victim like a routine documentation lookup, with no separate malicious link or file for the developer to open.

> The attack surface isn't what the MCP server can do. It's in what it can make the AI agent do.

That February-era research was reported to Upstash on 18 Feb 2026 and patched in production by 23 Feb, with public disclosure following on 5 Mar. The detail that keeps this case open rather than closed: the npm registry shows `@upstash/context7-mcp@2.1.2` was published on 23 Feb 2026 — the same date Noma's timeline places the fix — and CVE-2026-75130's affected range is stated as "through 2.1.2," meaning the version that shipped the original fix sits inside the new CVE's affected range. That is a date correlation, not a confirmed root-cause match; no source states the same code path regressed, and none states that the 4.0.x line Context7 had already shipped by 18 Aug 2026 remains vulnerable either. The honest status, as of publication, is that no fix is documented for the affected range and no source clears later versions.

The advisory's own severity scoring illustrates why a single CVSS number undersells this class: CVSS 3.1 reads the cross-machine jump from documentation server to developer workstation as a Scope change and returns 9.0 (critical), while CVSS 4.0 replaces that flag with separate vulnerable-system and subsequent-system metrics, scores the MCP server itself as unharmed, and returns 6.4 (medium) for the identical facts. This file rates the underlying mechanism high: reaching it costs an attacker nothing more than the ability to publish or claim a library entry, no privileged account or special configuration is needed on the victim side, and the documented impact — credential theft plus destructive deletion on a developer's own machine — lands on whichever machine holds the organization's source code and secrets.

## Mitigation

No patched version or GitHub Security Advisory exists for CVE-2026-75130 at the time of writing, so version-pinning alone cannot resolve it. Treat any MCP server that aggregates third-party or user-generated content — which describes most documentation, registry, and package-lookup servers — as an untrusted instruction source rather than a trusted tool: require approval for shell, file-write, and network actions taken by a connected coding agent, deny agent file access to `.env` and other plaintext credential files, and keep production secrets in a manager the agent cannot read directly rather than in files on the same disk it operates on. Inventory which MCP servers are installed across development machines and which version of each is actually resolved, since a floating `latest` tag on a package like this one currently means riding an undocumented patch status rather than a confirmed fix. The structural lesson outlives this one CVE: the MCP specification's own security-best-practices guidance, as of this writing, names only authorization- and transport-layer attack classes — confused-deputy OAuth proxying, token passthrough, SSRF during OAuth discovery, and similar — and has no section addressing untrusted content injected through a channel the agent already trusts. Until that changes, the content-trust boundary is the operator's problem to enforce, not the protocol's.
