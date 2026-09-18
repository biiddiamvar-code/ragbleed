---
caseId: "126"
title: "git-mcp-server passed ref and object parameters straight to the git CLI, letting a leading dash rewrite arbitrary files"
filed: "2026-09-18"
filedDisplay: "18 Sep 2026"
firstObserved: "04 Sep 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "git-mcp-server (npm @cyanheads/git-mcp-server, through 2.15.3; no fixed release at time of writing), git_log, git_diff, and git_show tools"
cve: "CVE-2026-85626"
readTime: "4 min read"
related: ["094", "110", "098"]
---

## Summary

git-mcp-server exposes `git_log`, `git_diff`, and `git_show` tools so an AI agent can inspect repository history without shelling out itself. All three forward a `ref` or `object` parameter into the underlying `git` command line without checking whether that value begins with a dash. A caller — or a repository whose branch names, tags, or commit references an agent is instructed to inspect — can supply a value that git itself interprets as a command-line option rather than a ref, including `--output=`, which redirects git's output to a file path of the attacker's choosing. No authentication is required to reach the tools, and as of this writing no patched release exists.

## What was observed

The three affected tools build a git invocation by concatenating the caller-supplied `ref` or `object` string into the argument list passed to the git binary, the same pattern that had already been patched for other git-mcp-server tools in an earlier command-injection advisory. That earlier fix moved the server off shell string concatenation and onto `execFile`-style argument arrays, which closes off shell metacharacter injection — but an argument array offers no protection against a value that git's own CLI parser treats as a flag rather than data. git does not distinguish "this string starts a ref name" from "this string starts an option" unless the caller inserts a `--` separator or the value is otherwise validated before reaching the argument list, and git-mcp-server did neither for `ref` or `object`.

```
tool: git_log
ref: --output=/home/user/.ssh/authorized_keys
# git interprets --output as a flag, not a ref, and writes wherever it points
```

Because `git log`, `git diff`, and `git show` all accept an `--output=<path>` option that redirects their result to a file, an attacker who controls what value lands in `ref` or `object` can direct that write to any path the server process can reach — not limited to the repository being inspected. The practical trigger doesn't require a human typing malicious arguments directly: an agent that resolves `ref` from a branch name, tag, or other string sourced from a repository under attacker control can be steered into supplying the payload on its own, the same indirect-injection path documented for this server's earlier command-injection flaw.

> A tool built to let an agent read git history became, with one unvalidated parameter, a tool that lets anything readable-as-a-ref write files outside the repository.

## Mitigation

No fixed release was available as of September 18, 2026; track the upstream issue and VulnCheck advisory for a patched version. Until one ships, treat `git-mcp-server` as unsafe to point at any repository whose branch names, tags, or other ref-adjacent strings aren't fully trusted, and consider wrapping tool calls with a check that rejects any `ref` or `object` value beginning with a dash before it reaches the server. The underlying lesson generalizes beyond this server: passing a caller-supplied string as a git ref requires either a leading `--` separator ahead of it in the argument list or an explicit rejection of leading-dash values — an argument array alone, without that check, still leaves the target CLI free to reinterpret data as options.
