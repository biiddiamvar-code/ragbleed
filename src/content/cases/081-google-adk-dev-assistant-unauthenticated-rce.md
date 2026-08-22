---
caseId: "081"
title: "Google ADK's hidden development assistant wrote and ran attacker code with no login required"
filed: "2026-08-22"
filedDisplay: "22 Aug 2026"
firstObserved: "05 Aug 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Disputed"
affectedSystems: "Google Agent Development Kit (ADK), built-in development-assistant HTTP API; default local configuration and default `adk deploy cloud_run` deployments as audited by Check Point Research through mid-2026"
cve: "No CVE assigned. Google initially assessed the finding as not a bug; after Check Point Research argued the impact, Google paid a $3,133.70 bounty and shipped a partial fix. Disclosed by Check Point Research (Shahar Tal, Yarden Porat) at Black Hat USA 2026"
readTime: "4 min read"
related: ["058", "052", "047"]
---

## Summary

Google's Agent Development Kit ships a built-in development assistant capable of writing and executing files, intended for local use while building an agent. Check Point Research found that this assistant's HTTP API carries no authentication by default and stays reachable even though it's hidden from ADK's normal app listing — and that the same API is published on a default `adk deploy cloud_run` deployment, meaning it can end up exposed on the public internet with no credentials required. An attacker who reaches it can have the assistant write a Python file that runs code at import time, then ask the server to run it, reaching whatever API keys and cloud service-account permissions the container holds. Google disputed that this was a bug before ultimately paying a bounty and issuing a partial fix.

## What was observed

ADK's development assistant is a convenience feature: point it at a description of the agent you want, and it writes the code for you. Check Point's researchers found two properties of its API that turned that convenience into an open door. First, it required no authentication in ADK's default configuration. Second, being absent from the visible app listing did not mean the API was unreachable — it was still live and answering requests, just not linked from the UI a developer would normally see.

The exploitation path needed no memory corruption and no unusual primitive. An attacker with network access to the API asked the assistant to write an agent whose Python module executed code at import time — a standard technique, since Python runs top-level statements in a file the moment it's imported, before any function inside it is deliberately called. The attacker then asked the server to run the newly written agent. The server imported the file, and the attacker's code executed as part of that import.

```
# illustrative: dev-assistant write-then-run flow, unauthenticated
POST /dev-assistant/write_agent   # no auth check; writes attacker's .py file
POST /dev-assistant/run_agent     # imports the file; top-level code executes on import
```

What made this severe rather than a local convenience gap was deployment defaults. Running `adk deploy cloud_run` — the documented path to putting an ADK agent into production on Google Cloud — published the same unauthenticated development-assistant API alongside the production agent. On a default Cloud Run deployment, that meant the write-and-execute path was reachable over the public internet with no credentials, and from inside that container an attacker's code could read the environment's API keys and assume the permissions of the container's own Google Cloud service account.

Google's first response, according to Check Point, was that this didn't qualify as a bug. The researchers said they had to argue impact rather than mechanism to change that assessment: code execution inside the container reaches the environment's API keys and its Google Cloud service-account credentials, which is secret theft, not a developer-experience complaint. Google ultimately paid a $3,133.70 bounty and issued a partial fix — Check Point's account does not describe the vulnerable path as fully closed, and no CVE was assigned to track what remains open.

## Mitigation

Deployments built with `adk deploy cloud_run` should not be treated as production-safe in their default form: front the deployment with authentication or a network policy that keeps the development-assistant API unreachable from outside the deployment's trust boundary, and confirm the assistant's write and run endpoints specifically are blocked, since they are absent from the app listing rather than absent from the server. Because Google's fix is described as partial and no CVE tracks the remaining exposure, teams running ADK in production should verify the current behavior of their own deployment directly rather than assume an update has closed the gap. The pattern here repeats one this site has flagged before: a feature meant for local development that ships live, unauthenticated, and reachable the moment a deploy command publishes it to the internet is a default-settings failure regardless of whether the vendor initially agrees it's a vulnerability.
