#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Collect maintainer-approved vulnerability bypasses from issues.

A bypass is an open issue whose title starts with a configured prefix
and which carries a configured label, for example:

    BYPASS: CVE-2026-12345 no upstream fix yet, tracked in #42

The LABEL is the trust boundary. Opening an issue requires nothing,
but applying a label requires triage or write permission, so an
outside contributor cannot approve their own bypass.

Issue authorship is deliberately NOT used. The ``author_association``
field reports ``CONTRIBUTOR`` rather than ``MEMBER`` when organisation
membership is private, and its value depends on the token used to read
it, so it is unreliable as an authorisation signal and would either
fail closed unpredictably or, if ``CONTRIBUTOR`` were accepted, let any
previous contributor suppress a finding.

Any failure here yields an empty bypass list, so the gate stays closed.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request

# Vulnerability identifiers are whitespace-delimited tokens containing
# a hyphen: CVE-2026-1234, GHSA-xxxx-xxxx-xxxx, ALPINE-CVE-2026-1234,
# RHSA-2026:1234. Candidates are matched as whole tokens and then
# filtered, rather than anchored to a list of known prefixes: an
# earlier prefix-anchored pattern reduced ALPINE-CVE-2026-1234 to
# CVE-2026-1234, and the exact lookup in evaluate then never matched.
CANDIDATE = re.compile(r"(?<![A-Za-z0-9._:-])([A-Za-z][A-Za-z0-9._:-]{4,})")


def looks_like_identifier(token: str) -> bool:
    """Filter candidate tokens down to plausible identifiers.

    Requires a hyphen, plus either a digit (CVE-2026-1234) or three or
    more hyphen-separated parts (GHSA-xxxx-xxxx-xxxx, which carries no
    digit at all).
    """
    if "-" not in token:
        return False
    if any(character.isdigit() for character in token):
        return True
    return len(token.split("-")) >= 3


def extract_identifiers(title: str) -> set[str]:
    """Every plausible vulnerability identifier in an issue title."""
    return {
        match.group(1).upper().rstrip(".,;:")
        for match in CANDIDATE.finditer(title)
        if looks_like_identifier(match.group(1))
    }


def emit(name: str, value: str) -> None:
    """Append a step output, using the multiline form when needed."""
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    with open(out_path, "a", encoding="utf-8") as handle:
        if "\n" in value:
            delimiter = "ghadelim_bypass_end"
            while delimiter in value:
                delimiter += "x"
            handle.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            handle.write(f"{name}={value}\n")


def warn(message: str) -> None:
    print(f"::warning::{message}")


MAX_PAGES = 20


def fetch_page(
    api_url: str, repo: str, label: str, token: str, page: int
) -> list[dict]:
    """Fetch one page of open issues carrying the label."""
    from urllib.parse import quote

    url = (
        f"{api_url}/repos/{repo}/issues?state=open"
        f"&labels={quote(label)}&per_page=100&page={page}"
    )
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if not isinstance(payload, list):
        raise ValueError("unexpected response shape")
    return payload


def fetch_issues(api_url: str, repo: str, label: str, token: str) -> list[dict]:
    """Every open issue carrying the label, following pagination.

    A shared organisation-wide bypass repository can hold more than one
    page. Reading the first page alone would silently drop approved
    bypasses and gate builds a maintainer had already unblocked.
    """
    collected: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        payload = fetch_page(api_url, repo, label, token, page)
        # Pull requests also appear in the issues endpoint; drop them.
        collected.extend(item for item in payload if "pull_request" not in item)
        if len(payload) < 100:
            return collected
    warn(f"Stopped after {MAX_PAGES} pages of bypass issues; later pages were not read")
    return collected


def main() -> int:
    repo = os.environ.get("BYPASS_REPO", "")
    label = os.environ.get("BYPASS_LABEL", "")
    prefix = os.environ.get("BYPASS_PREFIX", "")
    token = os.environ.get("GH_TOKEN", "")
    api_url = os.environ.get("API_URL", "https://api.github.com")
    try:
        max_age = int(os.environ.get("BYPASS_MAX_AGE", "0") or 0)
    except ValueError:
        max_age = 0

    if not repo or not label:
        emit("bypasses", "[]")
        return 0

    try:
        issues = fetch_issues(api_url, repo, label, token)
    except urllib.error.HTTPError as exc:
        warn(
            f"Could not read bypass issues from {repo} (HTTP {exc.code}); "
            "continuing with no bypasses applied"
        )
        emit("bypasses", "[]")
        return 0
    except Exception as exc:  # noqa: BLE001 - never fail the scan
        warn(
            f"Could not read bypass issues from {repo} ({exc}); "
            "continuing with no bypasses applied"
        )
        emit("bypasses", "[]")
        return 0

    now = dt.datetime.now(dt.timezone.utc)
    collected: list[dict] = []
    for issue in issues:
        title = (issue.get("title") or "").strip()
        if prefix and not title.upper().startswith(prefix.upper()):
            continue

        if max_age > 0:
            created = issue.get("created_at")
            created_at = None
            if isinstance(created, str):
                try:
                    created_at = dt.datetime.fromisoformat(
                        created.replace("Z", "+00:00")
                    )
                except ValueError:
                    created_at = None
            if created_at is not None:
                age_days = (now - created_at).days
                if age_days > max_age:
                    warn(
                        f"Bypass issue #{issue.get('number')} is "
                        f"{age_days} days old (limit {max_age}); ignoring"
                    )
                    continue

        ids = extract_identifiers(title)
        if not ids:
            warn(
                f"Bypass issue #{issue.get('number')} has the label but "
                "no recognisable vulnerability ID in its title; ignoring"
            )
            continue

        for vuln_id in sorted(ids):
            collected.append(
                {
                    "id": vuln_id,
                    "issue": issue.get("number"),
                    "url": issue.get("html_url", ""),
                    "title": title,
                }
            )

    emit("bypasses", json.dumps(collected))

    if collected:
        listed = ", ".join(sorted({entry["id"] for entry in collected}))
        print(f"Approved bypasses in {repo}: {listed}")
    else:
        print(f"No approved bypasses found in {repo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
