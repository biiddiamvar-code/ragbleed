---
caseId: "150"
title: "MCP Atlassian wrote its fallback OAuth token file with default permissions, leaving access and refresh tokens readable by other local users"
filed: "2026-10-05"
filedDisplay: "05 Oct 2026"
firstObserved: "10 Jul 2026"
severity: low
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "mcp-atlassian (< 0.22.0), OAuth fallback token storage in OAuthConfig._save_tokens()"
cve: "CVE-2026-77250 (GHSA-g5xv-mhgm-v5f6)"
readTime: "3 min read"
related: ["110", "018", "111"]
---

## Summary

When the system keyring was unavailable, MCP Atlassian persisted its OAuth access and refresh tokens to a plaintext JSON file created with the process's default file mode. On common umask settings the file was group-readable, so any other local account or container sharing the home directory could read credentials for the connected Atlassian site. The flaw requires local access and a configuration that reaches the fallback path, which bounds its severity.

## What was observed

The GitHub advisory GHSA-g5xv-mhgm-v5f6 was published on 10 Jul 2026, and CVE-2026-77250 was issued on 22 Sep 2026 (CVSS 6.1, CWE-312, cleartext storage of sensitive information). Versions before 0.22.0 were affected.

According to the advisory, `OAuthConfig._save_tokens()` created the directory `~/.mcp-atlassian` and then wrote `oauth-<client_id>.json` with a plain `open(token_path, "w")` call. No restrictive mode was set at creation. The advisory reports the resulting file mode as 0o664 rather than owner-only 0o600. The file held both the access token and the refresh token in plaintext JSON.

```
# Illustrative, mcp-atlassian < 0.22.0, keyring unavailable
~/.mcp-atlassian/oauth-<client_id>.json   # mode 0664, plaintext access + refresh token
# any local user in the owning group can read it and call the Atlassian API
```

Because the refresh token was stored alongside the access token, a reader could obtain persistent API access beyond the access token's lifetime. The advisory identifies shared hosts, containers with shared volumes and CI/CD runners as the exposed environments. Exploitation required a local account with read access to the file; the advisory records a low EPSS probability.

The rubric rating is low: a privileged or co-located local position is required and the fallback path is not the primary storage route. The CVSS score of 6.1 overstates remote exposure that does not exist.

## Mitigation

Upgrade mcp-atlassian to 0.22.0 or later. On systems that ran an affected version through the fallback path, revoke the OAuth grant in Atlassian, delete the stored token file, and re-authorize so that tokens issued before the fix are invalidated. Restrict the permissions of `~/.mcp-atlassian` to the owning user, and do not mount a shared home directory into MCP server containers.

Credential files should be created with owner-only permissions at open time, not tightened afterwards.
