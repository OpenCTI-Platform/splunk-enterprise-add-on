---
name: code-review
description: Code review checklist and conventions for Splunk Technology Add-ons (TAs) and Splunk Enterprise apps in this repo — Splunk UCC framework patterns, modular alert actions, proxy/SSL handling, AppInspect/Cloud vetting constraints, and dependency-shape mismatches.
compatibility: github-copilot-coding-agent
---

# Splunk App Code Review Skill

Use this skill whenever reviewing a diff, PR, or issue in a Splunk
Technology Add-on (TA) / Splunk Enterprise app repo (e.g.
`TA-opencti-for-splunk-enterprise`). These apps follow Splunk's UCC
(Universal Configuration Console) framework and integrate with
`splunktaucclib` / `solnlib` — most real defects in this codebase come
from mismatched assumptions between this app's code and those pinned
library versions, not from the app logic itself.

## Before reviewing: verify, don't infer

- Never assume a Splunk library function's return shape from its name.
  Read the **actual pinned version** in `requirements.txt` /
  `lib/` — behavior differs across `splunktaucclib` / `solnlib`
  releases, and functions with similar names on different call paths
  (e.g. helper-API proxy getters vs. raw conf-parsing proxy getters)
  can return **different dict shapes** for the same concept.
- If a fix touches a shared utility function (e.g. `utils.py`), check
  **every caller** of that function, not just the one in the diff.
  A fix for one caller's dict shape can silently break another
  caller that relies on a different shape from a different library
  path.
- Check open PRs/issues touching the same file/function before
  proposing a new fix — Splunk TAs often have multiple in-flight
  attempts at the same underlying defect (symptom re-reported without
  realizing an earlier "fix" only reformatted the same broken check).

## Proxy handling

- Common bug pattern: a helper's `get_proxy_settings()`-style function
  silently omits an `*_enabled` key that a separate `get_proxy_config()`
  function later checks for — the config is read correctly but never
  applied. Flag any code that checks for an `enabled` key sourced from
  a *different* function/library than the one building the settings
  dict; confirm both sides agree on key presence.
- Confirm proxy dicts intended for `requests` set **both** `"http"`
  and `"https"` keys pointing at the same proxy URI when a single
  forward proxy should carry both — an `http://`-scheme proxy value
  under the `"https"` key is the normal, correct pattern for HTTPS via
  CONNECT tunneling; don't flag it as a bug on scheme grounds alone.
- Don't assume a configured proxy is actually reachable/functional
  (e.g. supports CONNECT tunneling for port 443) — that's an
  environment/runtime concern, not something code review can verify.
  Flag it as an assumption if a fix's effectiveness depends on it.

## TLS/SSL verification

- `VERIFY_SSL` (or equivalent hardcoded cert-verification flags) being
  forced `True` is often a **Splunk Cloud Vetting / AppInspect
  requirement**, not an oversight. Do not approve a change that adds a
  way to disable certificate verification without an explicit callout
  that it may fail Cloud vetting.
- Distinguish TLS/certificate errors (`SSLError`,
  `CERTIFICATE_VERIFY_FAILED`, fails fast) from connection-level
  errors (`ConnectionError`, `ETIMEDOUT`/`Errno 110`, hangs then
  times out) when evaluating whether a fix targets the right layer of
  a reported error. They have different root causes and different
  fixes.

## Modular alert actions / `cim_actions.py` patterns

 - Alert action helpers (`alert_*_helper.py`) should be checked against the logging mechanism used by the target repo (for this repo, `ModularAlertBase` and `helper.log_*`; where `cim_actions.py` is present, preserve its structured fields).
 - Never log credentials, tokens, or full API keys—check helper functions that dump "settings" or "params" dicts for accidental secret exposure in DEBUG-level logs.

## Configuration / setup pages

- Changes to `setup_util.py` / REST handler validation should be
  checked against the corresponding `.conf.spec` / UI schema — a
  mismatch between what the setup page collects and what the spec
  file declares is a common source of "configured but ignored"
  settings bugs (the same class of bug as the proxy issue above).

## AppInspect / Splunk Cloud compatibility

- Any change to network calls, file I/O paths, subprocess use, or
  hardcoded ports/URLs should be evaluated against Splunk AppInspect
  rules if this app targets Splunk Cloud vetting — flag anything that
  looks like it would newly trip a vetting criterion (arbitrary
  outbound calls, disabling TLS verification, writing outside
  `$SPLUNK_HOME/var`, etc.).

## Dependency pinning

- `splunktaucclib` / `solnlib` versions are pinned for a reason
  (Cloud vetting compatibility). Do not recommend bumping these as a
  casual fix — cross-check the target version's changelog for
  behavior changes in any function the PR touches, since minor
  version bumps have changed dict shapes returned by helper functions
  before.

## Review output expectations

- Cite the exact file/line and, where relevant, the exact library
  version/source consulted — do not assert library behavior without
  having read it.
- Distinguish proven defects (traced in code, reproduced in logs)
  from plausible-but-unverified hypotheses (e.g. "this would probably
  fix it, assuming the proxy supports CONNECT tunneling").
- When a fix touches a function with multiple callers, explicitly
  state which callers were checked and confirmed unaffected.