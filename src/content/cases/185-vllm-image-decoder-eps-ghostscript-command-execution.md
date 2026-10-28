---
caseId: "185"
title: "vLLM passed request image bytes to Pillow format autodetection, letting an EPS payload reach the host's Ghostscript binary"
filed: "2026-10-28"
filedDisplay: "28 Oct 2026"
firstObserved: "26 Oct 2026"
severity: medium
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "vLLM (<0.32.0); command execution additionally requires Ghostscript 9.50 through 10.03.0 on the host"
cve: "CVE-2026-115915 (GHSA-h3rc-j82p-2c3h, CWE-20 / CWE-183, CVSS 8.1)"
readTime: "3 min read"
related: ["168", "149", "127"]
---

## Summary

vLLM's image media loader handed attacker-supplied bytes to Pillow without restricting which image decoder ran. A payload labeled as PNG but containing EPS data reached Pillow's EPS handler, which invokes the host's Ghostscript binary. On hosts with a Ghostscript release affected by CVE-2024-29510, this produced command execution with the privileges of the vLLM process. vLLM 0.32.0 limits untrusted images to raster formats.

## What was observed

The CVE record and advisory were published on 26 Oct 2026. Root cause, per the advisory text as relayed by secondary trackers: `ImageMediaIO` called `Image.open(BytesIO(data))` on request-supplied bytes, and the declared MIME type did not constrain the format Pillow selected. Both `parse_image()` and `fetch_image()` request paths reached that call.

```python
# Illustrative: no decoder allowlist on untrusted input
img = Image.open(BytesIO(data))   # format chosen from content, not from MIME label
# EPS content -> Pillow EPS plugin -> external ghostscript process
```

Code execution required a second condition. CVE-2024-29510 is a format-string flaw in Ghostscript 9.50 through 10.03.0 that bypasses the `-dSAFER` sandbox; it was fixed in 10.03.1. vLLM does not install Ghostscript, but base images that include document tooling may. The secondary write-up reports that the reporter reproduced execution with the PyPI wheel, Pillow 12.3.0 and Debian's Ghostscript 10.03.0, and traced the HTTP path in source without testing it end to end. A separate Pillow defect, CVE-2026-59203 (Pillow 12.0.0 through 12.2.0), loops indefinitely on a malformed EPS file; concurrent loads were reported to block normal requests.

Severity is rated medium rather than the 8.1 headline. The flaw is reachable by any caller who can submit images to a multimodal endpoint, but the command-execution impact depends on an outdated Ghostscript being present, which is not part of vLLM's own requirements. The advisory ID and affected range were taken from a tracker marked as pending review; the upstream GitHub advisory text was not retrieved in this run.

## Mitigation

Upgrade to vLLM 0.32.0 or later and Pillow 12.3.0 or later, then rebuild the container image. Run `gs --version` inside inference containers; remove Ghostscript where it is not needed, and require 10.03.1 or later where it is. The general lesson: format detection by content is a decoder-selection decision, and untrusted input needs an explicit allowlist before it reaches a library that shells out.
