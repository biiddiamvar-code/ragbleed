---
caseId: "129"
title: "gitlab-mcp's default Docker deployment left its file-upload tool reachable with no login, and no path checks either"
filed: "2026-09-21"
filedDisplay: "21 Sep 2026"
firstObserved: "16 Sep 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "@zereight/mcp-gitlab (npm, a.k.a. gitlab-mcp; versions < 2.1.27), SSE transport (SSE=true), users toolset (enabled by default)"
cve: "CVE-2026-61560 (GHSA-cv3r-c5h8-f4g5)"
readTime: "5 min read"
related: ["128", "047", "096"]
---

## Summary

The same GitLab MCP server covered in the companion case to this one shipped a second, independent path to full account takeover — this one requiring no header trick at all. Its reference Docker deployment ran the SSE transport with zero authentication on any tool, and one of those tools, built to upload a local file to a GitLab project, read whatever file path it was given with no validation. Chained together, an attacker who could merely reach the port held the server's GitLab access token within a handful of HTTP requests.

## What was observed

gitlab-mcp's `docker-compose.yaml` — the deployment path the project's own documentation walks users through — starts the server in SSE mode, binding the `/sse` and `/messages` endpoints to every network interface with no authentication middleware attached to either. The project's own per-request auth option is documented as incompatible with SSE mode, so there was no configuration flag that closed this gap; a network-reachable SSE deployment was unauthenticated by construction. Any client could open a session and invoke all of the server's roughly one hundred tools using the credentials the server itself held.

One of those tools, `upload_markdown`, takes a `file_path` argument, reads that file from local disk, and uploads it to a GitLab project as an attachment. The parameter's schema defined it as a bare string, with no check that the path stayed inside an expected directory:

```
# illustrative: the read primitive behind upload_markdown
def upload_markdown(project_id, file_path):
    contents = read_file(file_path)          # no path validation, no sandboxing
    return gitlab_api.upload(project_id, contents)
# called with file_path="/proc/self/environ" returns the process's own
# environment variables, including the configured GitLab PAT
```

Because the container's `Dockerfile` had no `USER` directive, the process ran as root, so the read primitive reached anything on the filesystem, not just files the server's own operator should have been able to see: `/proc/self/environ` for the token itself, `/etc/shadow` for system password hashes, the application's own source under `/app`. The most immediate target was the environment block, which held `GITLAB_PERSONAL_ACCESS_TOKEN` in plaintext. The exfiltration path was, in its own way, unremarkable: the stolen file was uploaded to a GitLab project the token could write to, then retrieved back over an ordinary HTTPS request to that project's upload URL — traffic that looks, to anything watching network egress, like normal use of the company's own GitLab instance. From the recovered token, an attacker holds the token owner's full API access: every repository it can reach, CI/CD secrets, and the ability to push code or rotate pipeline configuration.

## Mitigation

Upgrade to gitlab-mcp 2.1.27 or later. The fix does not attempt to sanitize `upload_markdown`'s file path; instead it closes the transport gap the read primitive depended on — SSE endpoints now require a bearer token (`SSE_AUTH_TOKEN`) when set, the server refuses to start in SSE mode on a non-loopback host without one, and the reference Docker deployment now runs as an unprivileged user and binds to loopback rather than every interface. If you operate any version of this server, treat a network-reachable SSE deployment as equivalent to an admin panel with no login — because that is what it was — and rotate the configured PAT regardless of whether you can confirm exploitation, since the exfiltration path leaves no trace outside routine-looking GitLab upload activity. Rated high, matching the CVSS 9.8 score: this was the project's own documented reference deployment, required no authentication and no configuration mistake beyond following the setup instructions, and yielded a credential with the token owner's full scope.
