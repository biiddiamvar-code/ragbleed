---
caseId: "046"
title: "Dify's Plugin Daemon proxy let an unauthenticated request reach internal endpoints"
filed: "2026-08-03"
filedDisplay: "03 Aug 2026"
firstObserved: "22 Jun 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Dify (Plugin Daemon architecture; all versions before 1.15.0)"
cve: "CVE-2026-41948 (part of the \"DifyTap\" disclosure; CVSS 9.4)"
readTime: "5 min read"
related: ["008", "003", "007"]
---

## Summary

Dify's API Service proxies plugin requests — icon fetches, task cancellations — to an internal Plugin Daemon, building the daemon-side URL from a client-supplied path segment and a client-supplied tenant ID. Neither value was validated before being spliced into the internal request path. An unauthenticated caller could inject directory-traversal sequences into that segment and reach arbitrary endpoints inside the daemon's internal API, or simply supply a different tenant's ID to pull that tenant's plugin assets directly. Zafran Labs reported the flaw as part of a four-vulnerability "DifyTap" disclosure that also produced the tenant-isolation bug covered in case 008; this is a separate root cause in a different subsystem, patched in the same 1.15.0 release.

## What was observed

Fetching a plugin icon sends a client request to `/console/api/workspaces/current/plugin/icon?tenant_id=<UUID>&filename=<UUID>.svg`, which the API Service converts into an internal call to the Plugin Daemon:

```
# client-controlled values dropped straight into an internal URL, unvalidated
# GET plugin/icon?tenant_id=<UUID>&filename=<UUID>.svg
#   → http://<PLUGIN_DAEMON_HOST>:5002/plugin/<TENANT_ID>/asset/<FILENAME>
# filename = "../../../debug/pprof" walks the request to an arbitrary
# internal endpoint; the daemon's response is streamed straight back
```

The endpoint enforced no login at all — any host with network access to the Dify instance could reach it — and accepted `?`-containing input as literal path text rather than a query delimiter, since the traversal payload was injected before any query string was appended. A second primitive in the plugin task-deletion endpoint reached the same daemon over POST using URL-encoded traversal sequences; it returned no response body, but the daemon still processed the request. Because `tenant_id` was also taken from the client rather than derived from the caller's session, an attacker didn't need traversal at all to pull another tenant's plugin icons — supplying that tenant's ID was sufficient, a plain tenant-isolation failure riding on the same unauthenticated path.

The practical blast radius at disclosure time was narrower than the 9.4 CVSS implies: most internal daemon routes weren't reachable through either primitive's constraints (no query parameters, no request body on the POST path, GET-only response passthrough), leaving `debug/pprof` profiling data as the main confirmed exposure. That's why this file rates the mechanism medium rather than matching the vendor-assigned score — the flaw is a structural one (an unauthenticated, unvalidated proxy into an internal service) rather than one that handed over sensitive data at the time it was found. Zafran's own writeup flags the same concern from the other direction: any new or modified Plugin Daemon endpoint added later inherits this exposure automatically, with no additional bug required to turn it into something worse.

## Mitigation

Upgrade to Dify 1.15.0 or later, which fixes the traversal and tenant-ID validation in the plugin proxy path. Operators who can't upgrade immediately should front the instance with a WAF rule blocking traversal sequences (`../`, URL-encoded equivalents) in the `plugin/icon` and `plugin/tasks/*/delete/*` routes. The general lesson: an internal microservice reachable only through a proxy is not implicitly safe just because it isn't exposed directly — any handler that assembles a backend request from client-supplied path segments needs the same path-canonicalization discipline as a public-facing file server, and any value used to select a tenant's data must come from the authenticated session, never from the request itself.
