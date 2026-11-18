---
caseId: "119"
title: "Weaviate let a user hand out admin without checking what admin could do"
filed: "2026-09-14"
filedDisplay: "14 Sep 2026"
firstObserved: "02 Jul 2026"
severity: high
category: "Access control / cross-tenant leakage"
status: "Patched"
affectedSystems: "Weaviate (all versions before 1.38.0)"
cve: "CVE-2026-59093"
readTime: "4 min read"
related: ["019", "038", "079"]
---

## Summary

Weaviate's role-based access control lets a caller assign existing roles to users or groups through `POST /authz/users/{id}/assign` and the equivalent group endpoint. Those handlers checked only that the caller held a permission letting them assign roles at all — never that the specific role being assigned didn't exceed the caller's own privileges. Role creation in Weaviate already enforced that a user can't create a role more powerful than their own; role assignment enforced no equivalent check, so a user granted nothing more than the ability to manage user-role or group-role mappings could hand the built-in admin role, or any other high-privilege role, to themselves or anyone else.

## What was observed

Weaviate's RBAC model separates several permissions that sound similar but are meant to carry very different levels of trust: creating a role, and assigning an already-created role to a user or group. The `assignRoleToUser` and `assignRoleToGroup` handlers required only `assign_and_revoke_users` or `assign_and_revoke_groups` respectively — permissions intended to let, say, a team lead manage which of their team's pre-approved roles applied to which teammates. Neither handler inspected what permissions the role being assigned actually granted, or compared them against the caller's own.

```
# caller holds only "assign_and_revoke_users" — not admin
POST /authz/users/{id}/assign
{ "roles": ["admin"] }
# handler checks: can this caller assign roles to this user? yes.
# handler does NOT check: does this caller hold every permission
# the "admin" role grants? that check exists for role *creation*,
# not for role *assignment*.
```

That asymmetry meant the safer-sounding of the two operations was actually the unguarded one: an organization that scoped a mid-level administrator to "can manage which of our custom roles apply to which users" had, without realizing it, also given that administrator a path to grant themselves or anyone else the built-in admin role, with full read, write, and administrative control over every collection in the database. The vendor's own CVSS scoring rates this 8.8 — high — reflecting that exploitation requires only the assignment permission, not the target role's own permissions, to pull off.

## Mitigation

Upgrade to Weaviate 1.38.0 or later, which requires that a caller assigning a role hold every permission contained in that role before the assignment succeeds — bringing assignment in line with the check role creation already enforced. Deployments that granted `assign_and_revoke_users` or `assign_and_revoke_groups` to any account below full admin should audit what roles those accounts assigned during the affected window; the vulnerability leaves no distinctive trace beyond an ordinary, successful role-assignment API call. The broader lesson: when a system enforces "you can't grant more than you have" in one code path, that invariant needs enforcing at every path that can end in a permission change, not just the one that happens to create the object carrying the permissions — assignment is exactly as security-relevant as creation, and often reachable through a lower-privilege permission than creation requires.
