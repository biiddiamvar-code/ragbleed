---
caseId: "053"
title: "Flowise fixed a sandbox escape by trusting three modules — one of them carried its own unpatched validation gap"
filed: "2026-08-06"
filedDisplay: "06 Aug 2026"
firstObserved: "11 Apr 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "Flowise (<=3.1.2); FlowiseAI/nodevm sandbox module, a vm2 fork (<=3.9.25)"
cve: "CVE-2026-69253"
readTime: "5 min read"
related: ["041", "007", "002"]
---

## Summary

Flowise runs user-supplied JavaScript — from Custom Function nodes, tool definitions, and similar building blocks — inside `nodevm`, an in-house fork of the long-deprecated `vm2` sandbox. After researchers escaped that sandbox once by abusing the `puppeteer` and `playwright` modules it exposed, Flowise's fix was to shrink the list of importable modules down to three: `node-fetch`, `axios`, and `moment`. One of those three, `moment`, carried its own five-year-old vulnerability whose original patch was never designed to hold up inside a sandboxed execution context — and it didn't. Flowise closed this second escape in version 3.1.3 by dropping `moment` from the allow-list rather than replacing the sandbox itself.

## What was observed

`moment.js`'s locale-loading function had previously been patched against directory traversal under CVE-2022-24785: a regex check rejects locale names containing `/` or `\` before the value is used to build a file path. That check calls `.match()` on the locale argument to test it against the regex — a design that assumes the argument is a plain string, because in ordinary use it always is. Inside Flowise's sandbox, an attacker controls the object being validated, and JavaScript doesn't enforce that `.match()` be a real regex match at all — any object with a method named `match` satisfies the call.

```
# object passed where moment expects a locale string:
# { match: function(regexp) { return true } }
#
# moment's CVE-2022-24785 patch calls locale.match(validationRegex)
# -> attacker's fake .match() always returns true
# -> the traversal check the patch exists to enforce never fires
```

Supplying an object whose `match` method unconditionally returned `true` satisfied moment's validation on every call, regardless of what path the "locale" argument actually contained. From there, a crafted string carrying directory-traversal sequences reached moment's file-loading logic unfiltered, giving code running inside the sandbox a path to `require()` an attacker-written file — including one previously staged on disk through Flowise's own document-store file upload. That closed the loop from sandboxed JavaScript to a `require()` call on attacker-controlled content, which is arbitrary code execution outside the sandbox boundary the fix was supposed to restore. Researchers reported the bypass to Flowise on 11 April 2026, roughly one day after the original `puppeteer`/`playwright` escape had been reported and reportedly fixed.

## Mitigation

Upgrade to Flowise 3.1.3 or later, which removes `moment` from the sandbox's allowed-module list. The pattern worth generalizing is narrower than "update your dependencies": a sandbox that permits `require()` of external modules is only as safe as every function those modules expose to untrusted input, and a patch written for one calling context — moment's fix assumed real string arguments from trusted callers — does not automatically hold in a different one. Restricting an allow-list is a mitigation, not a fix; the researchers' recommendation to replace `vm2`-derived sandboxing with a process-isolation approach like `isolated-vm` still stands; a full accounting of Flowise's remaining sandbox exposure is covered in this site's other Flowise entries (cases 007 and 041).
