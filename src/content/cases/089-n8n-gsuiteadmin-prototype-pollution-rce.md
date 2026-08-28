---
caseId: "089"
title: "n8n's GSuiteAdmin node let a schema name named __proto__ pollute every object in the process"
filed: "2026-08-28"
filedDisplay: "28 Aug 2026"
firstObserved: "25 Mar 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "n8n, GSuiteAdmin and XML node custom-schema handling (n8n < 1.123.27; n8n >= 2.0.0-rc.0, < 2.13.3; n8n = 2.14.0 beta)"
cve: "CVE-2026-33696 (GHSA-mxrg-77hm-89hv)"
readTime: "5 min read"
related: ["009", "050", "077"]
---

## Summary

n8n's GSuiteAdmin node offers a "Custom Fields" section for its user-create and user-update operations, where a workflow author supplies a schema name, a field name, and a value, all read from the workflow's own configuration. The node used the schema name directly as a property key on a plain JavaScript object without excluding the special name `__proto__`. Setting it to `__proto__` wrote attacker-controlled data onto `Object.prototype` itself, corrupting every plain object created afterward in that n8n process. Chained through how the Git node's underlying library builds child-process environments, that single write reached remote code execution as the n8n process user. Researcher Simon Koeck reported the flaw privately in early 2026; n8n shipped a fix and published the advisory in March, and Koeck's public technical writeup in August, five months later, renewed wide attention to the underlying pattern — the identical gadget also existed in the XML node.

## What was observed

The vulnerable code built a nested object to group custom fields by schema, using the workflow-supplied schema name as the outer key:

```
customSchemas[schemaName] ??= {};                              // "__proto__" resolves via the prototype getter,
                                                                 // is never nullish, so this assignment is a no-op
(customSchemas[schemaName] as IDataObject)[fieldName] = value; // writes straight onto Object.prototype
```

When `schemaName` was the literal string `__proto__`, the bracket access didn't create a new property — it resolved through JavaScript's built-in accessor to the shared `Object.prototype`, which is never `undefined` or `null`, so the `??=` initializer silently did nothing and the following line wrote the attacker's `fieldName`/`value` pair directly onto the prototype every plain object in the process inherits from. From there, the path to code execution ran through an unrelated feature entirely: when the Git node's underlying `simple-git` library builds an environment object for a spawned `git` process, that object inherits from the now-polluted prototype, and Node's child-process spawning logic includes inherited properties when constructing the child's environment. Git itself respects an environment variable named `GIT_SSH_COMMAND` and executes its value as a shell command whenever an SSH-style URL is used. Polluting `Object.prototype.GIT_SSH_COMMAND` and then triggering any Git node operation against an `ssh://` URL ran that command as the n8n process user — reachable from a single webhook-triggered workflow chaining a GSuiteAdmin node into a Git node, no interactive access required. Pollution alone, without the Git chain, was independently damaging: n8n's ORM layer iterates object properties when building query filters, and a polluted prototype made every subsequent database query throw, taking the whole instance down until a restart.

## Mitigation

Upgrade to n8n 2.14.1, 2.13.3, or 1.123.27, all of which reject `__proto__`, `constructor`, and `prototype` as property keys before using workflow-supplied strings this way. Where upgrading isn't immediate, restrict workflow creation and editing to trusted accounts and disable the XML node via the `NODES_EXCLUDE` environment variable, since it carried the same gadget. On severity: the CVSS score of 9.4 reflects a network-reachable, unauthenticated-adjacent path to full compromise, but reaching it in practice required an account already holding permission to create or edit workflows — a real barrier, not the no-authentication default that made case 009's file-read exploitable to any anonymous caller. That's a meaningfully higher bar, which is why this file rates it medium rather than matching the CVSS headline; it's also a bar that erodes fast in n8n deployments where "can build automations" is handed out to a wide slice of a team by default, which is the same default posture that made the earlier n8n case exploitable in the first place. The broader lesson recurs beyond this one node: any code path that takes a user-supplied string and uses it as a bare object key needs an explicit denylist for `__proto__`, `constructor`, and `prototype` — n8n's own codebase already had that guard built into a shared utility function elsewhere; this node simply wasn't using it.
