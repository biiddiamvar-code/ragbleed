---
caseId: "014"
title: "Kong Konnect's MCP server could be tricked into acting as a confused deputy"
filed: "2026-07-06"
filedDisplay: "06 Jul 2026"
firstObserved: "03 Jul 2026"
severity: high
category: "Prompt injection (indirect)"
status: "Patched"
affectedSystems: "Kong Konnect MCP server (versions prior to 1.0.0)"
cve: "CVE-2026-13341"
readTime: "5 min read"
related: ["001", "009", "004"]
---

## Summary

Kong Konnect's MCP server exposes API-gateway operations as tools an LLM agent can call, executing them with its own credentials on the agent's behalf. It had no reliable way to tell the difference between an instruction the user actually gave and one that arrived embedded in data the agent happened to read along the way — letting injected content steer the server into making API requests nobody asked for.

## What was observed

This is the classic confused-deputy shape, just instantiated through an LLM instead of a traditional program. The MCP server holds real privileges against the Kong gateway API. The agent it serves is supposed to only invoke those privileges on behalf of the user's actual request. But once an agent has ingested content from an external source — a fetched document, a support ticket, a webpage, anything that ends up in its context window — it can no longer perfectly distinguish "the user's instruction" from "text that looks like an instruction, sitting inside data the user asked it to process."

An attacker doesn't need direct access to the MCP server or the gateway at all. They need to get text in front of the agent that the agent will read as part of its normal task — the same indirect-injection pattern that shows up across RAG pipelines generally, just aimed here at a server that happens to hold API-gateway privileges instead of a database connection. Once the injected content is in context, the agent can be steered into calling gateway operations the user never intended, and the MCP server carries them out — because from its perspective, a validly authenticated agent asked for them.

This case is worth filing specifically because it demonstrates that "prompt injection" and "access control failure" aren't really two separate categories once an LLM sits in the authorization path. The MCP server didn't have a broken permission check in the traditional sense — it had no mechanism at all for verifying that the request it received reflected the user's actual intent rather than intent injected by whatever the agent last read.

## Mitigation

Upgrade to Kong Konnect MCP server 1.0.0 or later. Beyond the patch, the durable lesson applies to any MCP server that executes privileged operations on an agent's behalf: don't rely on "the agent is authenticated" as a proxy for "this specific request reflects the user's intent." Where possible, require explicit user confirmation for state-changing operations, scope the server's credentials to the minimum the workflow actually needs, and treat any content the agent ingests from outside the immediate conversation — retrieved documents very much included — as untrusted input capable of influencing which tools get called next.
