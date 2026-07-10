---
caseId: "008"
title: "Dify's tracing feature let anyone wiretap another tenant's conversations"
filed: "2026-06-25"
filedDisplay: "25 Jun 2026"
firstObserved: "22 Jun 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Dify (cloud multi-tenant service; self-hosted instances affected where applications are shared across users). Fixed in 1.14.2"
cve: "CVE-2026-41947 (part of the \"DifyTap\" disclosure)"
readTime: "5 min read"
related: ["003", "007", "005"]
---

## Summary

Dify lets application owners connect a "tracing" integration — a way to forward every message and model response to an external observability provider for monitoring. The endpoint that configures tracing never checked whether the person configuring it actually owned the application. Anyone who could reach a public Dify application could quietly attach their own tracing endpoint to it and start receiving a live copy of every conversation anyone else had with it.

## What was observed

Tracing is meant to be a workflow-owner feature: point your application's logs at your own observability backend so you can debug and monitor it. The configuration endpoint accepted a tenant-scoped application ID and a destination — but never verified that the tenant making the request matched the tenant that owned the application.

That gap turned a monitoring feature into an interception channel. Dify accounts are free to create. Once registered, an attacker could enumerate or simply visit any publicly accessible application on the instance, submit a tracing configuration pointing at infrastructure they controlled, and enable it — with no ownership check rejecting the request. From that point forward, every message sent to that application and every response the model generated was mirrored to the attacker's endpoint, silently and continuously, for as long as the tracing configuration stayed active.

```
# what should have been checked, and wasn't
POST /console/api/apps/{app_id}/trace-config
# app_id belongs to Tenant A
# request is authenticated as Tenant B
# → accepted anyway
```

The severity here isn't a one-time data grab — it's a standing wiretap. Unlike a single exposed file or a leaked credential, a misconfigured trace destination keeps collecting every new conversation until someone notices and removes it, which is a meaningfully different risk profile for anything a RAG application handles: customer conversations, retrieved private documents, internal business context passed through prompts.

## Mitigation

Upgrade to Dify 1.14.2 or later, which adds tenant-ownership validation to the tracing configuration endpoint. If you operate a Dify instance — cloud or self-hosted with multiple users — audit existing trace configurations on every application for destinations you don't recognize; a persistent exfiltration channel set up before the patch would survive the upgrade unless it's found and removed manually. Treat any application that was publicly accessible before this fix as a candidate for that audit, not just ones you suspect were targeted.
