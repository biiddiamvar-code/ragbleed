---
caseId: "136"
title: "IBM Financial Transaction Manager's AI agent server accepted unauthenticated runbook upserts into its vector store, letting injected runbooks steer MCP tool calls"
filed: "2026-09-26"
filedDisplay: "26 Sep 2026"
firstObserved: "23 Sep 2026"
severity: medium
category: "Data poisoning (ingestion-time)"
status: "Patched"
affectedSystems: "IBM Financial Transaction Manager (FTM) for Red Hat OpenShift 4.0.6.0 through 4.0.10.0 (including iFix6 Refresh), AI agent server component"
cve: "CVE-2026-18875"
readTime: "3 min read"
related: ["011", "114", "092"]
---

## Summary

IBM Financial Transaction Manager for Red Hat OpenShift includes an AI agent server that retrieves operational runbooks from a vector database and uses them as context for MCP tool calls. The endpoint that inserted or updated runbooks in that store required no authentication. Anyone who could reach it over the network could plant runbook content, and the agent would later retrieve that content as trusted guidance. IBM disclosed the flaw on 23 Sep 2026 in a bulletin covering 47 vulnerabilities in FTM.

## What was observed

The CVE record, assigned by IBM, placed the flaw in the AI agent server at `api.vectordb.runbooks.js:51` and classified it as CWE-74. It described the mechanism as an unauthenticated runbook upsert. A network attacker could write arbitrary runbook documents into the agent's vector database with no credentials.

The agent treated retrieved runbooks as instructions for how to act. Once a poisoned runbook ranked highly enough to be retrieved for a relevant query, its text entered the agent's context and shaped the tool calls the agent issued through MCP. The record stated that this could lead to unauthorized payment actions or to exfiltration of payment data. FTM is payment-processing middleware, so those tools sit close to money movement.

> The write path to the knowledge base was the control plane for the agent, and it was left open.

IBM's public description stopped at the endpoint and the impact. It did not say whether the AI agent server is enabled in a default FTM deployment, which MCP tools the agent exposes, or whether any human approval step sits between an agent decision and a payment action. We could not independently verify those details. The CVSS 3.1 vector IBM assigned (AV:N/AC:L/PR:N/UI:N, with low confidentiality, integrity and availability impact, 7.3) suggests IBM itself scored the downstream impact as limited. We rated the case medium on that basis. Reaching the endpoint is trivial, but the component is optional in a niche enterprise product and the exploit depends on retrieval and agent behavior that the record does not describe. An operator who runs the agent with payment-capable tools and no approval gate should treat this as high.

## Mitigation

Upgrade FTM for Red Hat OpenShift to 4.0.11.0, which IBM's bulletin 7288641 lists as the remediated release. Until then, block network access to the AI agent server's vector-store API from anything except trusted administrative hosts. Review the runbook collection for entries that no administrator created.

The broader lesson applies to every RAG-backed agent. Ingestion endpoints need the same authentication and authorization as the actions the agent can take, because anyone who can write to the retrieval corpus can instruct the agent. Record the author of every document in the store, restrict which sources may supply instruction-like content such as runbooks, and require human confirmation before any tool call that moves funds or exports records.
