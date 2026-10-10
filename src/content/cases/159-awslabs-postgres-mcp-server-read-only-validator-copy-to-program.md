---
caseId: "159"
title: "awslabs postgres-mcp-server's read-only validator did not block COPY TO PROGRAM, allowing OS command execution on the database host"
filed: "2026-10-10"
filedDisplay: "10 Oct 2026"
firstObserved: "09 Sep 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "awslabs.postgres-mcp-server (PyPI, versions before 1.1.7), PG_WIRE_PROTOCOL connection method with a privileged database role"
cve: "CVE-2026-87911 (GHSA-fph8-pg5w-78fv, AWS Security Bulletin 2026-104-aws, CWE-78 / CWE-184, CVSS 3.1 9.6)"
readTime: "3 min read"
related: ["133", "140", "106"]
---

## Summary

The AWS Labs PostgreSQL MCP server enforces a read-only mode by validating SQL statements before they reach the database. That validator maintained a list of disallowed constructs, and the list was incomplete: a crafted `COPY ... TO PROGRAM` statement passed it. When the server connected with a role holding superuser or `pg_execute_server_program` rights, the statement executed operating system commands on the host of a self-managed PostgreSQL server. The vendor patched the validator in version 1.1.7.

## What was observed

The advisory was published on 09 Sep 2026. It maps the flaw to CWE-184, incomplete list of disallowed inputs, and CWE-78, OS command injection. The read-only mode was implemented as an application-layer blocklist over SQL text. `COPY ... TO PROGRAM` is a PostgreSQL statement that pipes query output into a shell command on the database server, so it is a system-level operation that no read-only claim can coexist with. The blocklist did not reject it, and the statement was forwarded as if it were a read.

```
# Illustrative
# agent or injected content causes a tool call whose SQL contains
#   COPY (SELECT ...) TO PROGRAM '<command>'
# validator: statement not on blocklist -> forwarded
# database: role permits program execution -> command runs on DB host
```

Exploitation was conditional. The advisory states that the PG_WIRE_PROTOCOL connection method and a role with elevated privileges, such as a superuser or a holder of `pg_execute_server_program`, were required. Where the server connected with a minimal-privilege role, the database itself denied the operation and the validator gap had no effect. The CVSS vector lists user interaction as required, and the advisory describes the trigger as content processed by an authenticated user of the MCP server. This is the usual path for indirect prompt injection into an agent that holds a database tool.

The CVSS 3.1 score is 9.6. The rubric rating here is medium. The exploit path requires a privileged database role that least-privilege deployments do not grant, and the advisory itself names role restriction as the primary control. Where the role is privileged, the consequence is host-level code execution, which is why the patch is not optional for those deployments. The advisory credits Mordehai Attia (Corsen AI) and Ryan von Brubeck.

## Mitigation

Upgrade to awslabs.postgres-mcp-server 1.1.7 or later. Connect the server with a dedicated minimal-privilege role and avoid superuser, `rds_superuser`, and cluster master credentials. For read-only use, grant only CONNECT, USAGE, and SELECT, and enforce read-only transactions at the role level. For read/write use, grant only the specific INSERT, UPDATE, or DELETE privileges required. Maintainers of forks should apply the same validator fix.

A blocklist in the tool describes what its author thought of. The database role describes what the database will do.
