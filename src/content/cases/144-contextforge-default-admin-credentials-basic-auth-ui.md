---
caseId: "144"
title: "ContextForge MCP Gateway shipped default values for its admin, default-user and Basic Auth passwords, which became live administrative credentials once the admin UI or API Basic Auth was switched on"
filed: "2026-09-28"
filedDisplay: "28 Sep 2026"
firstObserved: "10 Sep 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "IBM ContextForge MCP Gateway (mcp-context-forge), 1.0.0 through 1.0.7 per the CVE record; IBM's remediation table lists v1.0.0–v1.0.9 and directs upgrade to v1.0.10"
cve: "CVE-2026-78573 (CWE-1392, Use of Default Credentials)"
readTime: "3 min read"
related: ["134", "084", "070"]
---

## Summary

IBM ContextForge MCP Gateway sits between agents and upstream MCP servers, and it holds the registrations, tokens and routing for those servers. Its configuration carried default values for `platform_admin_password`, `default_user_password` and `basic_auth_password`. The defaults were not reachable on their own. They became usable credentials once an operator enabled either `api_allow_basic_auth` or `mcpgateway_ui_enabled`, and at that point anyone who could reach the login surface could sign in as the platform administrator. IBM published the CVE on 10 September 2026 and fixed it in v1.0.10.

## What was observed

The CVE record and IBM's bulletin described the flaw as use of default credentials. The three password settings shipped with values set by the project, not by the operator. Nothing at startup required them to be changed before an authentication path using them was turned on.

IBM's workaround text set the boundary of the exposure. In a default deployment both `api_allow_basic_auth` and `mcpgateway_ui_enabled` are `False`, so no active authentication path accepts the default passwords. Enabling the admin UI, a common way to manage registered servers, or enabling Basic Auth on the API, exposed a login that accepted the shipped values. A successful login gave full administrative control of the gateway. That includes the upstream MCP server entries it brokers and any credentials stored for them.

```
# configuration state that produced the exposure (illustrative)
mcpgateway_ui_enabled = True        # or api_allow_basic_auth = True
platform_admin_password = <shipped default, never changed>
# -> admin login accepts the default -> full gateway control
```

The CVE record scores this CVSS 9.8 with no privileges and no preconditions. We rated it medium. According to IBM's own workaround text, the vulnerable state needs a configuration change away from the defaults. That change is common, because operators routinely turn on the admin UI, but it is not the out-of-box state. Where it applied, the consequence was complete control of an MCP gateway and the upstream tool credentials behind it.

The advisory's version data does not agree with itself. The affected range in the record ends at 1.0.7. IBM's remediation table covers v1.0.0 through v1.0.9 and points to v1.0.10. We have treated everything below 1.0.10 as affected.

## Mitigation

Upgrade to ContextForge v1.0.10 or later. Per IBM, the fixed release removes the defaults and requires operator-set values before either authentication feature can be enabled. On any instance that ever ran with the UI or Basic Auth enabled, rotate all three passwords. Rotate every upstream credential and gateway-issued token as well, because an administrator could have read or replaced them. Check the gateway and reverse-proxy logs for administrative logins you cannot account for.

If an immediate upgrade is not possible, keep `api_allow_basic_auth` and `mcpgateway_ui_enabled` disabled until all three passwords are set to strong, operator-chosen values. Do not expose the gateway's admin surface beyond a management network in any case.

This is the fourth ContextForge filing here, after cases 070, 084 and 134. An MCP gateway concentrates the credentials for every server behind it, so a default password on its admin account exposes all of those servers at once.
