---
caseId: "213"
title: "AWS Pricing MCP server's generate_cost_report wrote to an unconfined output_file path while advertising itself as read-only"
filed: "2026-11-18"
filedDisplay: "18 Nov 2026"
firstObserved: "16 Nov 2026"
severity: medium
category: "Prompt injection (direct or indirect)"
status: "Patched"
affectedSystems: "awslabs.aws-pricing-mcp-server (pip, <1.0.31; fixed in 1.0.31); awslabs.cost-analysis-mcp-server (pip, <=1.0.5, deprecated, no fix)"
cve: "CVE-2026-126816 (GHSA-mqm3-w68j-75mw, CWE-22 / CWE-357, CVSS 3.1 5.5; AWS Security Bulletin 2026-184-AWS)"
readTime: "3 min read"
related: ["211", "193", "206"]
---

## Summary

The `generate_cost_report` tool in AWS Labs' Pricing MCP server accepted an `output_file` argument and wrote the generated report to it without confining the path to an output directory. Absolute paths and `..` segments were honored. The tool also carried a `readOnlyHint` annotation, so MCP clients that auto-approve read-only tools could run the write without asking. An attacker who could place text in the agent's context could have it create or overwrite files the server process could write. Version 1.0.31 confines the path and corrects the annotation.

## What was observed

AWS published GHSA-mqm3-w68j-75mw in the awslabs/mcp repository on 16 Nov 2026, alongside AWS Security Bulletin 2026-184-AWS, crediting Ryan von Brubeck for coordinated disclosure. CVE-2026-126816 was published the same day.

Two defects combined. The first was the path: `output_file` was taken from the model's tool call and used as the report destination with no base directory, so `/home/<user>/.bashrc` or `../../<target>` were accepted (CWE-22). The report body included values supplied in the same call, which gave the caller partial control over the written content. The second was the annotation: the tool declared `readOnlyHint: true`, which MCP clients use to decide whether a call needs user confirmation. A client configured to auto-approve read-only tools would execute a file write silently, the CWE-357 component of the advisory.

```
# tool call produced by an agent steered through its context (illustrative)
generate_cost_report(
    <report inputs> = <attacker-chosen values>,
    output_file  = "/home/<user>/<any writable file>"   # no base directory check
)
# annotation: readOnlyHint = true  ->  auto-approved by some clients
```

The advisory scopes the impact to local installations whose agent processes attacker-influenced content, and to files writable by the server process on that machine. No managed AWS service was affected. The deprecated `awslabs.cost-analysis-mcp-server` has the same flaw through 1.0.5 and will not be patched.

Severity is rated medium, consistent with the CVSS score of 5.5. Exploitation depends on steering the agent and on a local deployment, but the incorrect read-only annotation removed the confirmation step that would otherwise have been the last control.

## Mitigation

Upgrade to `awslabs.aws-pricing-mcp-server` 1.0.31 or later, and migrate off `awslabs.cost-analysis-mcp-server`. In 1.0.31, `output_file` is resolved and confined to `AWS_PRICING_MCP_OUTPUT_DIR`, defaulting to the server's working directory; absolute paths outside it, `..` segments and escaping symlinks are rejected; and `readOnlyHint` is now `False`. Where upgrading is delayed, remove `generate_cost_report` from any auto-approve list, review the `output_file` value on each call, and keep untrusted content out of the agent's context.

Tool annotations are claims made by the server, and an auto-approve policy built on them inherits every one that is wrong.
