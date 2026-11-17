---
caseId: "211"
title: "Kubeshark MCP server's download_file tool wrote Hub API responses to an unvalidated local path and fetched unrestricted Hub endpoints"
filed: "2026-11-17"
filedDisplay: "17 Nov 2026"
firstObserved: "13 Aug 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Kubeshark CLI, kubeshark mcp subcommand (Go module github.com/kubeshark/kubeshark, v53.1.0 through releases before v53.4.0; fixed in v53.4.0)"
cve: "CVE-2026-129235 (GHSA-gj7r-p794-hhq5, CWE-22, CVSS 3.1 5.3)"
readTime: "4 min read"
related: ["193", "126", "172"]
---

## Summary

Kubeshark's MCP server, which exposes Kubernetes traffic captured by the Kubeshark Hub to AI agents, registered a `download_file` tool that took a Hub API path and a local destination from the caller and validated neither. The path was appended to the Hub base URL without an allowlist, and the destination was passed straight to file creation. An attacker able to steer the agent's tool arguments could write Hub responses to arbitrary user-writable files and read any Hub endpoint. Version 53.4.0 confines both.

## What was observed

The maintainers published GHSA-gj7r-p794-hhq5 in the kubeshark repository on 13 Aug 2026, the same week v53.4.0 shipped, crediting novice-22 through coordinated disclosure. The advisory entered the GitHub Advisory Database with CVE-2026-129235 on 16 Nov 2026. It traces the flaw to commit `eb7dc42b` of 4 Mar 2026, first released in v53.1.0.

Two caller-supplied arguments reached sinks unchecked. The destination was not cleaned, not confined to a directory, and absolute paths and `../` sequences were accepted; the file was created with `os.Create`, which also followed an existing symlink. The Hub path was concatenated onto the Hub base URL, so the tool was not limited to the `/api/mcp` routes it was meant to serve. The tool was registered unconditionally and was not gated behind the server's `--allow-destructive` flag.

```
# download_file arguments chosen by the model (illustrative)
path = "<any Hub API route, including ../ segments>"   # no allowlist
dest = "/home/<user>/<any writable file>"               # absolute or ../ accepted
# GET <hub_base> + path  ->  os.Create(dest)  ->  response body written
```

The stated attack path was prompt injection: Kubeshark's purpose is to show an agent captured network traffic and logs, which are themselves attacker-influenceable inputs. The written content was the Hub's HTTP response body rather than arbitrary bytes, and the advisory states reliable code execution was not demonstrated. On default installs where Hub authentication is disabled, the read side gave the agent, and whoever steered it, access to Hub endpoints including captured traffic.

The same fix series also corrected a separate argument issue in the `start_kubeshark` tool: `pod_regex` had been appended to the `kubeshark tap` command line without a `--` separator, so a value beginning with `-` would have been parsed as a flag. The advisory itself covers only `download_file`.

Severity is rated medium, consistent with the CVSS 3.1 score of 5.3. The tool is on by default and the Hub commonly runs without authentication, but exploitation depends on steering the agent, and the write primitive is limited to Hub response content.

## Mitigation

Upgrade the Kubeshark CLI to v53.4.0 or later. The fix (commit `a76a1920`, PR #1957) confines destinations to a base directory, the working directory by default or `KUBESHARK_MCP_DOWNLOAD_DIR` if set, rechecks containment after resolving symlinks, opens files with `O_NOFOLLOW` where the platform supports it, and rejects `..` in the Hub path. The maintainers list residual gaps: Windows has no `O_NOFOLLOW` equivalent, an intermediate-directory swap remains a narrow race, and a strict prefix allowlist for Hub paths is still pending. Until upgrading, run the MCP server as an unprivileged user in an isolated directory, enable Hub authentication (`tap.auth.enabled`), and avoid pairing the server with agents that read untrusted content.

An MCP server whose input is captured traffic should assume its caller is reading attacker-written text.
