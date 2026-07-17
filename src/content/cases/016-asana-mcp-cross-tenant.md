---
caseId: "016"
title: "Asana's MCP server let one company's AI agent see another company's projects"
filed: "2026-07-17"
filedDisplay: "17 Jul 2026"
firstObserved: "14 Jul 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Asana MCP server (opt-in feature, live 01 May 2025 – 04 Jun 2025 before being taken offline)"
cve: "No CVE assigned; disclosed directly by Asana"
readTime: "5 min read"
related: ["008", "003", "014"]
---

## Summary

Asana's MCP server lets an AI agent read and act on a workspace's projects, tasks, and comments on a user's behalf. A flaw in how the server checked tenant identity meant that, under certain conditions, an agent connected to one organization's Asana instance could retrieve project data belonging to a completely different organization. Around 1,000 customers were potentially affected before the feature was taken offline.

## What was observed

Asana's incident writeup doesn't publish the exact code-level cause, which is itself worth noting — not every case here comes with a reproducible snippet, and we're filing this one on the strength of Asana's own disclosure and independent confirmation from multiple security outlets rather than a technical writeup we could verify line by line. What's well corroborated: the MCP server's tenant-isolation check had a logic flaw that let an authenticated MCP user's agent surface objects — project names, task descriptions, comments, and associated metadata — from organizations other than their own.

The exposure was limited to data types the requesting user already had *some* form of access to within their own org (it wasn't an unrestricted dump of every tenant's data), but the boundary that was supposed to stop at the organization's edge didn't. The feature had been live since May 1, 2025; Asana discovered the issue on June 4 and took the MCP server offline the same day, restoring it on June 17 after a fix — requiring every customer to manually reconnect rather than resuming silently, specifically so affected organizations could review what their agents might have seen first.

Asana's own response is worth citing as a model here: direct notification to the roughly 1,000 potentially affected customers, guidance to review MCP access logs and AI-generated outputs for anything that looked like it came from outside their own org, and a public postmortem — even though there was no evidence the bug had actually been exploited by an attacker, only that it could have been.

## Mitigation

If you operate or connect to any multi-tenant MCP server — not specific to Asana — the durable lesson is architectural: tenant identity needs to be enforced as a mandatory filter at every layer the agent's request passes through, not assumed to be handled correctly by an upstream authentication step. If your organization used Asana's MCP integration during the exposure window, Asana's own recommendation still applies retroactively: review historical MCP access logs and AI-generated summaries for data that doesn't belong to your organization, and treat any of that data as something to delete rather than retain.
