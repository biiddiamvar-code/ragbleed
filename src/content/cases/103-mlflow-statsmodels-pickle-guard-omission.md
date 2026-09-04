---
caseId: "103"
title: "MLflow's pickle-deserialization safety flag never made it into the statsmodels flavor"
filed: "2026-09-04"
filedDisplay: "04 Sep 2026"
firstObserved: "01 Sep 2026"
severity: high
category: "Configuration / default-settings failure"
status: "Patched"
affectedSystems: "MLflow, mlflow.statsmodels model flavor (pip package, >=2.1.0, <3.15.0)"
cve: "No CVE assigned as of writing; tracked as GHSA-gqvg-gmmx-x4hm"
readTime: "5 min read"
related: ["088", "024", "043"]
---

## Summary

MLflow introduced the `MLFLOW_ALLOW_PICKLE_DESERIALIZATION` environment variable as an operator-facing kill switch after a 2024 batch of CVEs showed that loading a model could mean silently executing arbitrary pickled code. Setting it to `False` is supposed to make every model-loading path refuse pickle deserialization outright. Each model "flavor" — sklearn, pytorch, statsmodels, and others — is individually responsible for checking that flag before deserializing its own artifact format, rather than the check living in one shared place. The `mlflow.statsmodels` flavor's loader never checked it at all: it called straight through to a `pickle.load()` wrapper regardless of the flag's setting. An attacker able to register a crafted model artifact got code execution the moment anything called `mlflow.pyfunc.load_model()` against it, whether or not the operator believed pickle loading was disabled. MLflow fixed the omission in version 3.15.0.

## What was observed

The guarded pattern other flavors follow checks the flag and raises before touching the pickle payload:

```
# mlflow/sklearn/__init__.py — the pattern every flavor is expected to copy
if not MLFLOW_ALLOW_PICKLE_DESERIALIZATION.get():
    raise MlflowException("Deserializing model using pickle is disallowed...")

# mlflow/statsmodels/__init__.py — no such check anywhere in the file
def _load_model(path):
    return statsmodels.iolib.api.load_pickle(path)  # pickle.load(), unconditional
```

`statsmodels.iolib.api.load_pickle` is a thin wrapper around Python's `pickle.load`; its own docstring warns never to unpickle data from an untrusted source. The `mlflow.statsmodels` flavor called it anyway, with no gate in front. Triggering it required only an `MLmodel` YAML naming `mlflow.statsmodels` as the loader module, paired with a malicious `model.pkl` in the same artifact location — and on a default MLflow deployment run without the `basic-auth` app, registering that artifact requires no credentials at all. From there, any process that called `load_model()` against the registered model deserialized the pickle and ran the attacker's code with the calling process's privileges, regardless of how `MLFLOW_ALLOW_PICKLE_DESERIALIZATION` was set. This was not the first time a flavor had needed this exact guard restored: an earlier fix had already closed a similar bypass in the `pyfunc` flavor before the `statsmodels` gap was found.

> A safety control re-implemented independently in every flavor module is really N safety controls, each capable of being forgotten on its own.

## Mitigation

Upgrade MLflow to 3.15.0 or later, which adds the missing guard to the `statsmodels` flavor. Because the flag's protection depended entirely on this per-flavor check, treat any pre-3.15.0 deployment that accepted model artifacts from untrusted or unauthenticated sources as a likely compromise rather than a theoretical exposure, and audit the model registry for unexpected `statsmodels`-flavored entries. Longer term, a security control that requires every extension point to independently re-implement the same check is only as strong as its least-audited extension point; enforcing the guard once, at the single dispatch point every flavor already passes through, would have covered flavors not yet written as well as the ones that already shipped without it.
