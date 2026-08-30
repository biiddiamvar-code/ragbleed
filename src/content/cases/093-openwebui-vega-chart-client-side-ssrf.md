---
caseId: "093"
title: "Open WebUI rendered Vega chart specs in the viewer's browser with no restriction on what they could fetch"
filed: "2026-08-31"
filedDisplay: "31 Aug 2026"
firstObserved: "04 Aug 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Open WebUI, Vega/Vega-Lite chat code-block renderer (versions 0.6.34 through 0.10.x; fixed in 0.11.0)"
cve: "CVE-2026-70480 (GHSA-rffm-9q57-q649)"
readTime: "4 min read"
related: ["030", "062", "083"]
---

## Summary

Open WebUI renders `vega` and `vega-lite` fenced code blocks that appear in chat content by building a live chart directly in the viewer's own browser. The Vega and Vega-Lite libraries can pull remote data into a chart at render time, and Open WebUI's renderer built that chart without configuring a restricted resource loader — Vega's own mechanism for scoping which URLs a chart is permitted to fetch. Any chat content that reaches a browser could therefore carry a chart specification that made the viewer's browser issue an outbound request to an attacker-chosen destination and read the response back into the rendered page, entirely outside the reach of the server-side SSRF protections the project has repeatedly hardened elsewhere.

## What was observed

Vega and Vega-Lite chart specifications support a `data.url` field, among other constructs, for loading a dataset at render time. Open WebUI's chat pipeline renders fenced `vega`/`vega-lite` code blocks by constructing a Vega `View` from the block's contents in the client's browser; the advisory states this was done without a restricted loader, so nothing scoped which URLs a chart's `data.url` — or other resource-loading fields — could point to.

```
# illustrative, not exploit code
chat message contains:
  ```vega-lite
  { "data": { "url": "http://169.254.169.254/..." }, ... }
  ```
victim opens the conversation, browser renders the chart,
browser (not the Open WebUI server) issues the fetch,
response is read back into the rendered chart data
```

Because the browser — not the Open WebUI backend — makes the request, it runs from the viewer's own network position and, where CORS allows, can read back the response. That puts internal services reachable from the viewer's machine, cloud metadata endpoints on the viewer's network segment, and same-origin Open WebUI API paths in scope, none of which the server-side SSRF guards this database has already logged against Open WebUI (cases 030, 062, 083) were built to see — those guards inspect requests the backend makes on the server's behalf, not requests a rendered chart makes from inside a colleague's open browser tab. Reaching the flaw needs only that an attacker holds an account able to place content somewhere another user will view it (chat, a shared conversation) and that the victim opens it — a bar most shared or team-hosted Open WebUI deployments clear by default, which is why the advisory rates this exploitable with low privileges and required user interaction rather than none at all.

## Mitigation

Upgrade to Open WebUI 0.11.0 or later, which applies a restricted Vega loader constraining what a rendered chart can fetch, per the linked fix commit. Deployments unable to upgrade immediately should treat rendered chat content — chart specifications, embedded markup, anything a browser interprets rather than just displays as text — with the same suspicion as script injection, since a client-side fetch primitive sits entirely outside server-side SSRF controls no matter how thorough those controls are. This is the fourth distinct SSRF-shaped gap this database has logged against Open WebUI's content-rendering surface (cases 030, 062, 083, and this one), each in a different code path — IPv6/NAT64 address parsing, the Playwright web loader, DNS-rebinding timing, and now client-side chart rendering. The recurrence across independent renderers argues that "does this feature fetch a URL" needs to be a standing question asked of every new content type Open WebUI learns to render, not a lesson relearned per feature.
