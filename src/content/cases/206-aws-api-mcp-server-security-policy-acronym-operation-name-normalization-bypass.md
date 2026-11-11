---
caseId: "206"
title: "AWS API MCP Server split acronyms letter by letter when normalizing operation names, so denyList and elicitList entries for those operations never matched"
filed: "2026-11-11"
filedDisplay: "11 Nov 2026"
firstObserved: "10 Nov 2026"
severity: medium
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "awslabs.aws-api-mcp-server (>=0.2.13, <1.5.1), locally run server with a custom security policy file"
cve: "CVE-2026-125271 (GHSA-4wq9-grf3-qg2p, CWE-1025 / CWE-863, CVSS 4.0 8.5; AWS Security Bulletin 2026-176-AWS)"
readTime: "4 min read"
related: ["186", "193", "159"]
---

## Summary

The AWS API MCP Server lets operators restrict what an AI assistant may run through a custom security policy holding a `denyList` and an `elicitList` of AWS CLI commands. Before comparing a requested operation against those lists, the server converted the SDK operation name to kebab case with a regular expression that inserted a hyphen before every capital letter. Operation names containing acronyms produced strings that no policy entry matched, so the deny and consent rules for those operations were silently skipped and the call proceeded under the default allow. Version 1.5.1 replaces the conversion with botocore's own name transform.

## What was observed

GitHub advisory GHSA-4wq9-grf3-qg2p and CVE-2026-125271 were published on 10 Nov 2026, alongside AWS Security Bulletin 2026-176-AWS. The advisory credits Syed Anas Mohiuddin and classifies the flaw as CWE-1025, comparison using wrong factors. Affected versions were 0.2.13 up to, but not including, 1.5.1.

A diff of the published 1.5.0 and 1.5.1 wheels confirmed the mechanism. In `core/security/policy.py`, both `determine_policy_effect` and `check_customization` built the lookup key with `re.sub('([A-Z])', r'-\1', operation).lower()`. Policy entries are written as AWS CLI commands, and the CLI derives its command names through botocore's `xform_name`, which keeps runs of capitals together. The two transforms agreed on names such as `DeleteBucket` and disagreed on any name with consecutive capitals:

```
# Key built by policy.py in versions < 1.5.1
CreateSAMLProvider   -> aws iam create-s-a-m-l-provider     # policy lists: create-saml-provider
DeactivateMFADevice  -> aws iam deactivate-m-f-a-device     # policy lists: deactivate-mfa-device
DeleteDBCluster      -> aws rds delete-d-b-cluster          # policy lists: delete-db-cluster
# No set membership hit -> falls through to PolicyDecision.ALLOW
```

The lookup was an exact set-membership test, deny before elicit before default. A miss on both lists therefore fell through to the global mode flags and then to allow. The advisory's impact examples are creating a federated identity provider, deactivating an MFA device and deleting database clusters, which are the class of operations an operator is most likely to place on a deny list and the class most often named with acronyms.

The advisory states that exploitation required a locally run server with a custom policy naming affected operations, plus an assistant session that issued the call, whether by user request or by injected instructions. The hosted remote AWS API MCP Server was not affected. Deployments relying on `READ_OPERATIONS_ONLY` or `REQUIRE_MUTATION_CONSENT` were also not affected, because those global checks run after the list lookup regardless of its result.

The rubric rating is medium rather than the vendor's High: a custom policy file is an opt-in configuration and the server runs locally, but where it is used the bypass removes the control on identity and data-destroying operations executed with the host's AWS credentials.

## Mitigation

Upgrade `awslabs.aws-api-mcp-server` to 1.5.1 or later; the advisory lists no workaround and asks that forks and derivative code be patched separately. Until upgraded, enable `READ_OPERATIONS_ONLY` or `REQUIRE_MUTATION_CONSENT`, which were unaffected, and scope the IAM credentials available to the server so that operations on the deny list are also denied by IAM policy.

A deny list is only as strong as the canonicalization in front of it. When a policy is written in one naming scheme and enforced against another, the conversion must be the same function the tool itself uses, and an unmatched sensitive operation should fail closed rather than fall through to allow.
