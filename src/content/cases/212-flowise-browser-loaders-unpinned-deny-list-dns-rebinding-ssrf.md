---
caseId: "212"
title: "Flowise's Playwright and Puppeteer loaders checked a resolved address against the deny list, then let headless Chromium resolve the hostname again"
filed: "2026-11-18"
filedDisplay: "18 Nov 2026"
firstObserved: "17 Nov 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "Flowise (FlowiseAI/Flowise, through 3.1.4), Playwright and Puppeteer web document loaders; repository archived, no fixed release"
cve: "CVE-2026-130615 (VulnCheck advisory; CWE-367, CVSS 3.1 7.1, CVSS 4.0 7.6)"
readTime: "4 min read"
related: ["165", "070", "053"]
---

## Summary

Flowise's Playwright and Puppeteer document loaders guarded outbound fetches with `checkDenyList()`, which resolved the target hostname with `dns.lookup` and compared the answers against a deny list of loopback, private, link-local and cloud-metadata ranges. The resolved address was then discarded, and headless Chromium performed its own resolution when it loaded the page. A DNS-rebinding hostname could pass the check with a public address and serve an internal one to the browser, and the page content came back to the user as loaded documents. The project was archived in August 2026 and no fix has been published.

## What was observed

VulnCheck published the advisory on 17 Nov 2026, crediting N3st1c, and CVE-2026-130615 entered NVD the same day. It covers Flowise through 3.1.4, the last release line before the project's archival.

The deny list itself was present and on by default. `getHttpDenyList()` merged `HTTP_DENY_LIST` with a built-in list covering `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `169.254.169.254`, `fd00:ec2::254` and the IPv6 loopback and link-local ranges, unless `HTTP_SECURITY_CHECK=false` was set. The weakness was in how the result was used. `checkDenyList()` resolved the hostname, checked every returned address, and returned nothing. The Playwright loader called it on the configured URL and again inside a `page.route('**')` handler for every request the page made; the Puppeteer loader did the same through request interception. In both cases the request then continued inside Chromium, which resolved the name independently.

```
# Playwright / Puppeteer loader flow, through 3.1.4 (simplified)
checkDenyList(url)        # dns.lookup(host) -> public IP -> allowed
route.continue()          # Chromium resolves host again -> 169.254.169.254
page.content()            # metadata response returned as document text
```

Flowise's HTTP client paths did not have this gap. `secureAxiosRequest` and `secureFetch` in the same `httpSecurity.ts` file resolved the target once and passed the result to `createPinnedAgent`, so the address that was checked was the address that was connected to. The browser-based loaders could not use that agent and were left with check-only validation, a time-of-check/time-of-use split (CWE-367).

Exploitation required an authenticated account able to create or edit a chatflow containing either loader, and a rebinding domain whose TTL and answer ordering won the race, which the CVSS vector reflects as high attack complexity. On a host in a cloud VPC, a successful rebind reached the instance metadata service and any internal HTTP service the Flowise server could route to, with responses returned in full as document content rather than blind.

Severity is rated high, matching the CVSS headline. The deny list is the default configuration and the loaders are standard nodes; the reachable data includes cloud instance credentials. The chatflow-builder requirement is a normal user role in multi-user Flowise deployments, not a privileged one.

## Mitigation

No patched Flowise release exists. The maintainers froze the codebase on 29 Jul 2026 and archived the repository on 10 Aug 2026, with end of life on 31 Aug 2026, and the sunset notice directs teams to fork. Operators still running Flowise should remove or disable the Playwright and Puppeteer loader nodes, or restrict chatflow editing to trusted administrators. At the network layer, block the Flowise host's egress to link-local and private ranges and require IMDSv2, which a plain page navigation cannot satisfy. Teams maintaining a fork should send the loaders' browser traffic through an egress proxy that resolves each hostname once and applies the deny list to the address it actually connects to.

A deny-list check that does not own the connection is advisory only.
