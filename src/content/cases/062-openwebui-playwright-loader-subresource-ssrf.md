---
caseId: "062"
title: "Open WebUI's Playwright web loader checked the page it fetched, not what that page fetched next"
filed: "2026-08-11"
filedDisplay: "11 Aug 2026"
firstObserved: "04 Aug 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Open WebUI (pip package, >=0.9.6, <0.11.0), Playwright web loader"
cve: "CVE-2026-70479"
readTime: "4 min read"
related: ["030", "060", "036"]
---

## Summary

Open WebUI can be configured to fetch web pages for RAG and web-search retrieval using a real headless browser (Playwright) instead of a plain HTTP client, so that JavaScript-heavy pages render correctly before their content is ingested. The SSRF guard that validates a requested destination against internal and cloud-metadata address ranges ran only against that initial, top-level page URL. Every subsequent request the loaded page made on its own — scripts, XHR calls, iframes, redirects triggered from inside the page — went out from the Open WebUI server unchecked. Because the loader hands the rendered page's final DOM back to the requesting user as retrieval content, anything read from those unchecked destinations came back as ordinary RAG or web-search output. Fixed in 0.11.0.

## What was observed

Open WebUI's SSRF protection exists to stop a server-side fetch from being redirected at internal services or cloud instance metadata — the same class of risk addressed for the plain HTTP path in earlier fixes (see case 030, case 060). The Playwright loader sits on a different code path: instead of one HTTP request, it opens the target URL in a browser context and lets the page execute normally, then serializes the resulting DOM. The validation logic that reused the address-filtering guard was wired in only at the point where the browser first navigated to the caller-supplied URL.

```
# validate_url() ran once, against the top-level navigation target
browser.goto(user_supplied_url)   # checked
# but everything the loaded page's own JS then requested was not:
# fetch("http://169.254.169.254/latest/meta-data/...")
# fetch("http://internal-service.local:8080/admin")
```

A page under attacker control — or a legitimate page carrying attacker-supplied script, per typical SSRF-to-injection chaining — could issue its own requests to addresses the guard was built to block, and those requests carried none of the top-level check's restrictions. Because Open WebUI returns the fully rendered DOM as the loader's output, any response text a blocked address would have returned was available to read back through the normal RAG ingestion or web-search result path, no separate exfiltration channel required.

## Mitigation

Upgrade to Open WebUI 0.11.0 or later, which applies the destination check to sub-resource requests made from within the loaded page, not just the initial navigation. Where upgrading isn't immediate, disable the Playwright web loader in favor of the plain HTTP fetcher, or run the Playwright browser instance in a network-isolated context with its own egress allow-list rather than depending on application-level validation alone. We rate this medium rather than matching the advisory's CVSS 7.7 HIGH: the Playwright loader is an opt-in retrieval mode, not Open WebUI's default fetch path, so the exposure applies only to deployments that have specifically enabled it — a real but non-default configuration. The broader lesson repeats a pattern this site keeps logging: an SSRF guard bolted onto one entry point of a multi-request feature protects only that entry point. When a browser, not an HTTP client, is doing the fetching, the page it renders can issue requests the validation layer never sees.
