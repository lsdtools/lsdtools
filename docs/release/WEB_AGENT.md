# Releasing lsdtools to PyPI: the web agent's runbook

You are a browser agent acting in the owner's signed-in GitHub and PyPI accounts. You set up trusted
publishing once, then approve each release that the owner asks for. The release itself is built,
tested and uploaded by this repository's `release.yml` workflow; you never upload anything.

## 1. Hard rules

- Never create a PyPI API token, never upload a file by hand, never edit a workflow, never delete a
  release, a tag or a file on PyPI.
- Never approve a deployment whose sha256 differs from the release issue's, or whose run is not
  `release.yml` on a `v*` tag of `lsdtools/lsdtools`.
- Stop and report on any 2FA prompt, any page you did not expect, and any error. Do not retry around it.
- Credentials, recovery codes and 2FA devices belong to the owner. Do not read, copy or store them.

## 2. What each release gives you

The owner opens an issue in `lsdtools/lsdtools` from the release template, holding:

| field | example |
|---|---|
| version and tag | `1.0.0rc1`, `v1.0.0rc1` |
| the wheel and the sdist | `lsdtools-1.0.0rc1-py3-none-any.whl`, `lsdtools-1.0.0rc1.tar.gz` |
| their sha256 | as in `release/1.0.0rc1.json` |
| the gate receipts' sha256 | as in `release/1.0.0rc1.json` |
| the workflow run | `https://github.com/lsdtools/lsdtools/actions/runs/<id>` |

## 3. Once: PyPI and TestPyPI accounts

The owner holds both accounts (pypi.org and test.pypi.org), each with 2FA by a security key or an
authenticator, and keeps the recovery codes. If an account is missing or has no 2FA, stop and report.

## 4. Once: GitHub

1. Organization `lsdtools`: Settings > Authentication security: require two-factor authentication.
2. Repository `lsdtools/lsdtools` (public). Settings > Actions > General:
   - allow only actions from GitHub and the listed repositories (`actions/*`, `pypa/gh-action-pypi-publish`);
   - workflow permissions: read repository contents.
3. Settings > Rules > Rulesets:
   - `main`: no deletion, no force push, changes by pull request only;
   - tags `v*`: no deletion, no update.
4. Settings > Environments: `testpypi` and `pypi`, each with the owner as required reviewer,
   deployment tags only (`v*`), and no secrets.

## 5. Once: pending trusted publishers

On pypi.org (Account > Publishing > Add a new pending publisher) and on test.pypi.org (same page):

| field | value |
|---|---|
| PyPI project name | `lsdtools` |
| owner | `lsdtools` |
| repository name | `lsdtools` |
| workflow name | `release.yml` |
| environment name | `pypi` on pypi.org, `testpypi` on test.pypi.org |

A pending publisher does not reserve the name; the first upload does.

## 6. Each release

1. Open the issue's run. Wait until `build`, `reproduce` and every `test` job are green. Do not
   approve anything before that.
2. Open the `build` job's "the tested release" step: its sha256 lines must equal the issue's, file by file.
3. Approve the `testpypi` deployment. Wait for `testpypi-served` to pass.
4. Approve the `pypi` deployment. Wait for `pypi-served` and `github-release` to pass.

## 7. Verify

1. `https://pypi.org/project/lsdtools/<version>/#files`, "view hashes" for each file: the sha256 is
   the issue's.
2. `https://pypi.org/pypi/lsdtools/<version>/json`: each `urls[].digests.sha256` is the issue's.
3. `https://pypi.org/integrity/lsdtools/<version>/<file>/provenance` for each file: the publisher is
   GitHub, repository `lsdtools/lsdtools`, workflow `release.yml`, environment `pypi`.

## 8. Smoke

In a fresh virtual environment (any machine you may use):

```
python -m venv smoke
smoke/bin/python -m pip install lsdtools==<version>     (Windows: smoke\Scripts\python)
smoke/bin/lsdtools version --json
smoke/bin/lsdtools doctor --json
```

`version` reports `<version>`; `doctor` reports its checks (a check that fails because no runtime is
installed yet is expected).

## 9. If something is wrong after publishing

Never delete. Yank the release on PyPI with a reason (PEP 592: Manage > Options > Yank), and tell the
owner, who ships the next version with the fix. If the repository itself may be compromised, remove
the trusted publishers on both indexes first, then report.

## 10. Report

Comment on the release issue: the run, the approvals with their times, the sha256 you compared, the
provenance you saw, and the smoke output. Then close the issue.
