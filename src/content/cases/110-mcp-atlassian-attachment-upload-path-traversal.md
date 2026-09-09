---
caseId: "110"
title: "mcp-atlassian's attachment-upload tool read any file the server process could reach"
filed: "2026-09-09"
filedDisplay: "09 Sep 2026"
firstObserved: "10 Jul 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "mcp-atlassian (PyPI package, < 0.22.0), confluence_upload_attachment tool"
cve: "CVE-2026-73498 (GHSA-g5r6-gv6m-f5jv)"
readTime: "4 min read"
related: ["018", "045", "004"]
---

## Summary

mcp-atlassian, one of the most widely deployed Atlassian MCP servers, shipped a `confluence_upload_attachment` tool that took a caller-supplied file path and opened it with no validation at all. Any authenticated MCP client — or an AI agent whose tool arguments were steered by prompt injection — could point the tool at an arbitrary file on the server and have its contents uploaded back as a Confluence attachment, credentials and environment variables included. Fixed in 0.22.0.

## What was observed

The tool exists so an agent can attach a local file — a downloaded document, a generated report — to a Confluence page. Its implementation passed the `file_path` argument straight to Python's `open(file_path, "rb")` with no check that the resolved path stayed inside any expected directory. A relative path built from `../` sequences, or a bare absolute path, was honored exactly as supplied.

```
tool: confluence_upload_attachment
file_path: /proc/self/environ   # or any other file the process can open
# contents returned to the caller as the uploaded "attachment"
```

The read primitive came with its own built-in exfiltration channel: the same call that opens the file also ships its bytes to Confluence as an attachment, so the attacker never needed a separate way to get the data out. Because the tool ran with whatever privileges the MCP server process held, files holding that process's own secrets — environment variables commonly storing `CONFLUENCE_API_TOKEN`, `JIRA_API_TOKEN`, and adjacent credentials — sat in the same reach as any other file on disk.

The advisory is explicit that the trigger doesn't require a malicious human operator: an agent using the tool for its intended purpose can have `file_path` populated from content it's processing, making this reachable through indirect prompt injection as well as direct API misuse.

## Mitigation

Upgrade to mcp-atlassian 0.22.0 or later, which adds path validation ahead of the file open. Until patched, treat every credential available to the mcp-atlassian process as exposed to anyone who can reach the tool — directly or through content an agent might ingest. The broader pattern here repeats across this catalogue: an MCP tool that accepts a file-path argument needs that path resolved and confirmed to sit inside an allowed root before anything touches disk, not validated by convention or by assuming callers are well-behaved.
