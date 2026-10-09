---
caseId: "158"
title: "LiteLLM applied its sandbox and validator to the guardrail test endpoint but not to the production create and update paths"
filed: "2026-10-09"
filedDisplay: "09 Oct 2026"
firstObserved: "08 Jul 2026"
severity: low
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "LiteLLM proxy server (versions before 1.82.0-stable), Custom Code Guardrails create and update endpoints"
cve: "CVE-2026-59821 (GHSA-72m8-9m7m-h278, CWE-94)"
readTime: "3 min read"
related: ["028", "057", "102"]
---

## Summary

LiteLLM allows administrators to define Custom Code Guardrails, Python snippets that run inside the proxy process. The test endpoint for these guardrails ran submitted code through a sandbox and validator. The production create and update paths did not, so a privileged user could store code that executed with full access to the proxy process and its environment.

## What was observed

The CVE was published on 08 Jul 2026 per NVD, with one aggregator listing 09 Jul 2026. The weakness is classified as CWE-94, improper control of generation of code. Reporting on the CVSS score is inconsistent: one source lists 2.1 with a low severity label while also describing the impact as critical, and the score should be checked against the NVD record.

The flaw was inconsistent input validation across three entry points to one feature. The test endpoint applied a sandbox and a validator that rejected unsafe constructs. The create and update endpoints, which persist a guardrail and run it on live traffic, called neither. Code submitted through those paths reached the runtime unchecked and could read secrets held in the proxy environment, such as provider API keys and database credentials.

```
# Illustrative
# privileged user submits guardrail code via create/update (not test)
# validator and sandbox are not invoked on this path
# code executes in the proxy process; process environment is readable
```

One aggregator additionally states that where no master key is configured, unauthorized users may gain proxy administrator privileges. This was not confirmed in the advisory text reviewed.

The rubric rating is low, matching the low CVSS score for a different reason. Exploitation requires a privileged account that can manage guardrails, and an actor with that role already holds broad control over the gateway. The consequence of exploitation is code execution and credential exposure, which is why the finding still warrants prompt patching. The fix, per the CVE record, is commit e50b448, which adds a shared validator module that all three paths must call.

## Mitigation

Upgrade to LiteLLM 1.82.0-stable or later. Review existing Custom Code Guardrails for imports, dangerous builtins, and dunder attribute access, and rotate any secrets reachable from the proxy environment if untrusted users held guardrail permissions. Limit guardrail administration to trusted operators, configure a master key, and disable the Custom Code Guardrail feature where it is not used.

A security control attached to the test path of a feature and not to the shared execution path protects only the path used in demonstrations.
