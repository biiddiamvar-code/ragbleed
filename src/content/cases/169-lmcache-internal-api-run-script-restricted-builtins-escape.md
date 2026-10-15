---
caseId: "169"
title: "LMCache's /run_script endpoint executed uploaded Python behind restricted builtins, and the injected FastAPI app object led back to the real ones"
filed: "2026-10-15"
filedDisplay: "15 Oct 2026"
firstObserved: "07 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Disclosed, patch guidance pending"
affectedSystems: "LMCache internal API server (through 0.5.5; no fixed release identified at disclosure)"
cve: "CVE-2026-107204 (GitHub issue #5510; VulnCheck advisory; CWE-306)"
readTime: "3 min read"
related: ["163", "134", "025"]
---

## Summary

LMCache's optional internal API server exposed `POST /run_script`, which executed caller-uploaded Python inside the server process behind a restricted-builtins sandbox. The sandbox's globals included the live FastAPI `app` object, and the reporter showed that this object gave access to the unrestricted builtins. The endpoint required no authentication. No fixed release was identified at disclosure.

## What was observed

The internal API server is opt-in. The `internal_api_server_enabled` setting defaults to false. When enabled, the server binds to `0.0.0.0`, starting at port 6999, and applies no authentication to its routes. The reporter counted roughly fifty such routes, including `/cache/clear` and `/conf`.

`/run_script` runs the submitted script in-process. The guard consisted of a replaced `__import__` and a reduced builtins table. The globals handed to the script also contained the FastAPI application object. According to the issue and the VulnCheck advisory, the real builtins could be recovered through that object, which bypassed the guarded import. The script could then import `os` and run operating-system commands as the LMCache process user. Exploit code was withheld from the report and is not reproduced here.

```
# POST /run_script   (no credentials)
# script globals: restricted builtins + live `app` object
# app -> real builtins -> unrestricted __import__
# import os -> commands run as the LMCache user
```

VulnCheck lists the weakness as CWE-306 (missing authentication for a critical function) and the reporter suggested CWE-94. The CNA-assigned scores are CVSS 9.3 (v4) and 9.8 (v3.1 as proposed by the reporter). RagBleed rates the mechanism medium because the server is disabled by default and the exposure depends on an operator enabling it on a routable interface. Where it is enabled, the impact is full code execution on a host that holds GPU cache state for a serving fleet.

## Mitigation

No patched version was identified in the CVE record, the advisory, or the issue at the time of writing; check the LMCache releases before relying on any version. Leave `internal_api_server_enabled` off outside development. Where it is required, bind it to loopback or a private interface and restrict its port with firewall rules. The reporter recommends authentication on the server and process- or container-level isolation for script execution. A restricted-builtins table inside the interpreter is not a sandbox, and it fails faster still when the script is handed objects from the host application.
