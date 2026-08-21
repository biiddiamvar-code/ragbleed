---
caseId: "078"
title: "Splunk MCP Server's credential store deserialized stolen data straight into command execution"
filed: "2026-08-21"
filedDisplay: "21 Aug 2026"
firstObserved: "19 Aug 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Splunk MCP Server app (versions below 1.2.1)"
cve: "CVE-2026-76404"
readTime: "4 min read"
related: ["028", "042", "025"]
---

## Summary

Splunk MCP Server exposes Splunk's search, alerting, and administrative capabilities to AI agents over the Model Context Protocol. Its credential management component — the part responsible for storing and retrieving the connection secrets those agents use to reach Splunk — deserialized stored data without first checking that the data was of the expected type. A Splunk user holding the platform's 'admin' role could plant crafted data in that store and have the app reconstruct it into arbitrary command execution on the host when it was next read back. Splunk assigned this CVE-2026-76404, CVSS 9.1, and fixed it in version 1.2.1.

## What was observed

The flaw sits in the credential management component of the MCP Server app: a piece of the app whose job is to hold the API tokens and connection details an MCP-connected agent needs to act on a Splunk instance. When that component read a stored credential back out, it deserialized the bytes into an object without validating that the object's type matched what a credential record should look like — the pattern tracked as CWE-502, deserialization of untrusted data. An attacker able to influence what got stored there could substitute a different kind of serialized object, one whose reconstruction triggers arbitrary code as a side effect of being rebuilt, rather than a benign credential.

```
# illustrative: credential read path, pre-fix
raw = credential_store.get(key)          # attacker-influenced content
credential = deserialize(raw)            # no type check before reconstruction
# a crafted payload here executes as it is rebuilt, not when it is "used"
```

Exploitation required the attacker to already hold Splunk's 'admin' role — this was not a reachable-by-anyone bug. That precondition is the reason this case is filed at medium rather than the critical the CVSS headline implies: the rubric this site applies rates the mechanism a working exploit needs, and a privileged-account requirement narrows the population that can trigger it to users who already sit close to the top of Splunk's own permission model. What the flaw actually does is convert that in-application privilege into something categorically worse — arbitrary command execution on the underlying operating system, stepping outside whatever Splunk's role-based access controls were meant to contain. For a deployment where the MCP Server app connects an AI agent to production Splunk data, an admin account being phished, reused, or otherwise compromised now buys an attacker the host underneath it, not just the app.

## Mitigation

Upgrade the Splunk MCP Server app to version 1.2.1 or later. Splunk's guidance for organizations that can't patch immediately includes reviewing privileged account activity, MCP Server access logs, and application logs for signs of anomalous deserialization or execution behavior. More broadly: any component that stores and later reconstructs application state — credential stores very much included — needs to validate the type of what it's about to deserialize before rebuilding it, regardless of how privileged the account writing that state is assumed to be. Trusting a privileged caller is not the same as trusting the bytes that caller submits.
