---
caseId: "199"
title: "vLLM let a model repository's speculators_config point the served model and tokenizer at any local directory"
filed: "2026-11-07"
filedDisplay: "07 Nov 2026"
firstObserved: "02 Nov 2026"
severity: low
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "vLLM (<0.33.0), maybe_override_with_speculators model-config handling"
cve: "No CVE assigned as of writing; tracked as GHSA-qrj2-j723-m6w8 (CWE-22 / CWE-200, CVSS 3.1 5.4)"
readTime: "3 min read"
related: ["189", "048", "163"]
---

## Summary

When vLLM loaded a model whose `config.json` contained a `speculators_config` key, it copied the `verifier.name_or_path` value into both the model path and the tokenizer path without any containment check. A crafted repository could therefore redirect the server to a directory on the host's own filesystem. Version 0.33.0 fixes the issue.

## What was observed

The advisory, published 02 Nov 2026, identifies the function `maybe_override_with_speculators`, which runs for every model not hosted on cloud storage. If the repository configuration contains a `speculators_config` key, the function assigns `speculators_config["verifier"]["name_or_path"]` to both the model and the tokenizer. The only validation confirmed that the keys exist. It did not reject absolute paths or resolve the value against a base directory.

Because an absolute path needs no traversal sequence, the advisory notes that a plain path such as a neighbouring user's model directory was sufficient. It states that `trust_remote_code` stays `False`, so no opt-in to remote code was required.

The advisory describes two consequences. An unauthenticated client of the running server could read the victim directory's tokenizer vocabulary through `/detokenize`. The victim directory's checkpoint was also loaded as the primary model, giving callers query access to a model they did not own. The advisory identifies shared and multi-tenant hosts as the highest-risk setting, since the target directories may belong to other users.

The CVSS 3.1 vector (5.4) includes user interaction, reflecting that an operator must choose to serve the untrusted repository. The mechanism is rated low here: it depends on the operator loading a repository the attacker controls, and the confirmed disclosures are a tokenizer vocabulary and model access on the same host.

## Mitigation

Upgrade vLLM to 0.33.0 or later. The fix is PR #61587; the advisory lists no workaround. Serve only model repositories from sources the operation controls, and run each model server under its own account with filesystem permissions that stop it reading other users' model directories. A path taken from a configuration file supplied with the model should be treated as input, not as server configuration.
