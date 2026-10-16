---
caseId: "172"
title: "NotebookLM MCP's batch-to-vault tool wrote files wherever the caller pointed it, and the fix is opt-in"
filed: "2026-10-16"
filedDisplay: "16 Oct 2026"
firstObserved: "23 Jun 2026"
severity: low
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "@roomi-fields/notebooklm-mcp (1.6.0 through 2.0.2; fixed in 2.0.3, containment requires NOTEBOOKLM_VAULT_ROOT)"
cve: "CVE-2026-61647 (GHSA-jjhp-8crj-mppq; CWE-22, CWE-73)"
readTime: "3 min read"
related: ["110", "126", "094"]
---

## Summary

The notebooklm-mcp server accepted a caller-supplied `vault_dir` in its `vault_batch` tool and `POST /batch-to-vault` endpoint and wrote files there with no containment check. A caller, or a model steered by prompt injection, could create directories and write `.md` and `.json` files anywhere the server process could write. Version 2.0.3 fixes this, but only when an environment variable is set.

## What was observed

The `vault_batch` MCP tool (1.7.0 and later) and the HTTP endpoint (1.6.0 and later) passed `vault_dir` to `path.resolve()` and `fs.mkdir()` without comparing the result against a root. A second weakness concatenated `slug_prefix` into output filenames unsanitized, so path separators or `..` sequences escaped the vault directory even when `vault_dir` was honest.

The advisory states that the written files are not executable by themselves. The stated risk is planting files in sensitive locations such as autostart folders or shell startup files for later exploitation, most relevant when an LLM that reads untrusted content drives the tool or when the HTTP endpoint is shared between users.

```
# vault_dir  = "../../home/user/.config/autostart"   (no containment check)
# slug_prefix = "../x"                              (concatenated into filename)
# result: attacker-influenced .md/.json written outside the vault
```

The advisory was published on 23 Jun 2026 and credits the reporter @mcfly-zzh; the CVE record followed in September. Scoring varies by source (a CVSS 4.0 score of 7.1 appears in an aggregator that itself flags internal inconsistencies); the GitHub advisory rates it moderate. RagBleed rates the mechanism low: the file formats are constrained to non-executable types, the product is a niche single-user tool, and the fix's behavior depends on configuration.

## Mitigation

Upgrade to 2.0.3 and set `NOTEBOOKLM_VAULT_ROOT`. Without that variable the legacy unrestricted behavior remains, and the upgrade alone does not close the issue. The `slug_prefix` sanitization (separators, `..` and NUL bytes stripped, 64-character cap) applies unconditionally. If upgrading is not possible, bind the HTTP listener to loopback, run the server as an unprivileged account with write access only to the vault directory, and validate `vault_dir` before forwarding tool arguments. A security fix that ships disabled leaves every existing deployment exactly as exposed as before.
