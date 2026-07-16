---
caseId: "015"
title: "MarkItDown's document-fetching tool could be pointed at cloud credentials instead of a document"
filed: "2026-01-22"
filedDisplay: "22 Jan 2026"
firstObserved: "20 Jan 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "Microsoft MarkItDown MCP server (all versions at time of writing; most consequential on cloud-hosted deployments using IMDSv1)"
cve: "No CVE assigned; disclosed by BlueRock Security"
readTime: "5 min read"
related: ["010", "014", "013"]
---

## Summary

MarkItDown's MCP server exposes a tool, `convert_to_markdown`, built to turn a document at a given URL into Markdown for an LLM to read — the kind of ingestion step a RAG pipeline runs constantly. It accepts any URL with no restriction on the target. Pointed at a cloud provider's internal metadata address instead of a document, it fetches and returns whatever is sitting there, credentials included.

## What was observed

Cloud instances commonly expose an internal metadata service — on AWS, at `169.254.169.254` — that the instance itself can query for configuration details and, if an IAM role is attached, temporary access credentials. That address is never supposed to be reachable by anything outside the instance's own processes. `convert_to_markdown` doesn't distinguish between "a document a user wants converted" and "an internal address that happens to respond to the same HTTP request."

Sending the tool that metadata address instead of a real document URL returns the metadata service's response as if it were the document content. On an EC2 instance with an IAM role and the older IMDSv1 metadata protocol active, appending `/latest/meta-data/iam/security-credentials/` to that request reveals the role name; appending the role name to that returns the access key, secret key, and session token outright.

```
tool: convert_to_markdown
url: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# returns AWS access key, secret key, and session token as "document content"
```

From there, an attacker holds working credentials for whatever that IAM role can reach — which, depending on configuration, can mean broad access across S3, DynamoDB, and other AWS services well beyond the MCP server itself. Microsoft was notified and classified the finding as low-risk, declining to patch it as of this writing. We rate it differently: an unauthenticated path from "convert this document" to "here are your cloud account's temporary credentials" is a high-severity finding under any configuration where the server runs on cloud infrastructure with an attached role — which describes a large share of real deployments, not an edge case. A subsequent scan of over 7,000 MCP servers found the same missing-validation pattern in roughly a third of them, meaning this isn't unique to MarkItDown either.

## Mitigation

No patch has been published for MarkItDown's MCP server at time of writing. If you run it — or any MCP server whose tools accept an LLM- or user-supplied URL — on cloud infrastructure, treat the fix as your own responsibility until upstream ships one: reject requests targeting private, loopback, and link-local address ranges (including `169.254.169.254` and its IPv6 equivalent) at the network or application layer, and migrate any EC2 instances still using IMDSv1 to IMDSv2, which requires a session token and closes this specific exfiltration path even if the URL validation gap remains open.
