---
caseId: "047"
title: "AnythingLLM's default install left its entire HTTP and WebSocket API unauthenticated"
filed: "2026-08-03"
filedDisplay: "03 Aug 2026"
firstObserved: "12 Mar 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disputed"
affectedSystems: "AnythingLLM (<=1.11.1; no confirmed patched version in the advisory)"
cve: "CVE-2026-32617"
readTime: "5 min read"
related: ["006", "013", "035"]
---

## Summary

AnythingLLM's authentication middleware contained a blanket bypass: if an administrator hadn't explicitly set both `AUTH_TOKEN` and `JWT_SECRET`, every protected HTTP endpoint let requests through unchecked, and the same was true whenever the app ran with `NODE_ENV=development` — the default when running from source. A separate agent WebSocket endpoint had no authentication middleware at all, checking only that a session UUID existed. Both the main server and its file-collector service also reflected any request origin back in their CORS headers, so any website a victim's browser could reach was able to make authenticated-looking cross-origin calls into a reachable instance. The reporter's proof of concept chained these into a drive-by browser attack that exfiltrated workspace data and hijacked the AI agent's tool-calling flow with no credentials and, in the CORS scenario, no direct network access from the attacker at all.

## What was observed

The bypass sat in the request-validation middleware that gates nearly every protected route:

```
# server/utils/middleware/validatedRequest.js
if (
  process.env.NODE_ENV === "development" ||
  !process.env.AUTH_TOKEN ||
  !process.env.JWT_SECRET
) {
  next();   // request proceeds unauthenticated
  return;
}
```

A fresh installation where the administrator hadn't finished configuring both environment variables satisfied this condition by default, opening admin endpoints, system configuration, and the chat-invocation route that spawns agent sessions to anyone who could reach the port. The agent WebSocket at `/api/agent-invocation/:uuid` compounded this: it carried no auth check of its own, and since the endpoint that mints invocation UUIDs was itself unauthenticated, an attacker could open the socket and stream a live agent session without ever presenting credentials. Layered on top, `app.use(cors({ origin: true }))` on both the main server and the collector process reflected whatever `Origin` header a request carried, so a victim's browser — not just a network-adjacent attacker — became a viable delivery path: visiting a malicious page was enough to trigger cross-origin reads of workspace contents, chat history, and system settings, followed by an agent invocation prompting the model to surface prior conversation contents.

AnythingLLM's security team disputed the reporter's initial CVSS 10.0 score down to 7.1 after replication testing, on the grounds that AnythingLLM Desktop binds to loopback by default, that Chromium-based browsers block the cross-origin request via Private Network Access protections, and that the published proof of concept required manually editing `/etc/hosts` to simulate a local origin — conditions the vendor argued don't hold in ordinary deployments. That dispute is fair as far as the specific drive-by browser scenario goes, but it doesn't reach the underlying default-state problem: any self-hosted or Docker deployment bound to a LAN-reachable interface without both environment variables set — a common pattern for a shared team tool — has zero authentication on its entire API and agent surface by design, not by misconfiguration. That's why this file rates the mechanism high rather than adopting the vendor's revised score: the dispute concerns how easily a browser can be tricked into delivering the exploit, not whether the exposed surface is dangerous once reached.

## Mitigation

Configure `AUTH_TOKEN` and `JWT_SECRET` before exposing any AnythingLLM instance beyond localhost, and never run a network-reachable instance with `NODE_ENV=development`. The GitHub advisory does not list a confirmed patched version — treat this as configuration guidance rather than a version to upgrade to, and verify against the current release notes before assuming any given version has closed the gap. Independent of that, restrict AnythingLLM instances to a firewalled network segment and put a reverse proxy with its own authentication in front of anything reachable outside a single trusted host. The broader pattern: an authentication check that's opt-in rather than mandatory on first run will eventually meet a deployment that skipped the opt-in step, and a permissive CORS policy turns that gap into something any website can reach, not just something on the local network.
