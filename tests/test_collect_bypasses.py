#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for the bypass collector.

The collector decides whether a vulnerability stops gating a build, so
it is the security-sensitive half of this action. These tests stub the
HTTP layer, needing no network and no GitHub token.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import pathlib
import sys
import urllib.error
import urllib.request
from email.message import Message

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import collect_bypasses  # noqa: E402

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


def issue(number: int, title: str, days_old: int = 0, pull: bool = False) -> dict:
    created = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_old)
    entry = {
        "number": number,
        "title": title,
        "html_url": f"https://example/{number}",
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if pull:
        entry["pull_request"] = {"url": "https://example/pr"}
    return entry


class FakeHTTP:
    """Serve canned pages, recording the URLs requested."""

    def __init__(self, pages: list[list[dict]]):
        self.pages = pages
        self.urls: list[str] = []

    def __call__(self, request, timeout=None, **kwargs):  # noqa: ANN001
        url = request.full_url
        self.urls.append(url)
        # Parse '&page=' specifically: a plain 'page=' also matches
        # 'per_page=100' and would read the wrong page number.
        page = 1
        if "&page=" in url:
            page = int(url.split("&page=")[1].split("&")[0])
        body = self.pages[page - 1] if page <= len(self.pages) else []
        return io.BytesIO(json.dumps(body).encode())


def collect(pages, **env) -> list[dict]:
    """Run the collector against canned pages; return parsed bypasses."""
    import os
    import tempfile

    original = urllib.request.urlopen
    fake = FakeHTTP(pages)
    urllib.request.urlopen = fake  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "out"
            out.touch()
            saved = dict(os.environ)
            os.environ.update(
                {
                    "BYPASS_REPO": "example/repo",
                    "BYPASS_LABEL": "cve-bypass",
                    "BYPASS_PREFIX": "BYPASS:",
                    "BYPASS_MAX_AGE": "90",
                    "GH_TOKEN": "",
                    "API_URL": "https://api.github.com",
                    "GITHUB_OUTPUT": str(out),
                }
            )
            os.environ.update({k: str(v) for k, v in env.items()})
            try:
                collect_bypasses.main()
                text = out.read_text(encoding="utf-8")
            finally:
                os.environ.clear()
                os.environ.update(saved)
    finally:
        urllib.request.urlopen = original

    payload = text.partition("bypasses=")[2].strip()
    return json.loads(payload) if payload else []


print("identifier extraction")
extract = collect_bypasses.extract_identifiers
check("plain CVE", extract("BYPASS: CVE-2026-1234") == {"CVE-2026-1234"})
check(
    "composite distro ID kept whole",
    extract("BYPASS: ALPINE-CVE-2026-1234") == {"ALPINE-CVE-2026-1234"},
)
check(
    "GHSA without digits",
    extract("BYPASS: GHSA-abcd-efgh-ijkl") == {"GHSA-ABCD-EFGH-IJKL"},
)
check("prose without an ID", extract("BYPASS: please unblock us") == set())
check(
    "two IDs in one title",
    extract("BYPASS: CVE-2026-1 and GHSA-aaaa-bbbb-cccc")
    == {"CVE-2026-1", "GHSA-AAAA-BBBB-CCCC"},
)

print("collection")
found = collect([[issue(1, "BYPASS: CVE-2026-1234")]])
check(
    "labelled issue yields a bypass",
    [e["id"] for e in found] == ["CVE-2026-1234"],
    found,
)
check("issue number recorded", bool(found) and found[0]["issue"] == 1, found)

found = collect([[issue(2, "Something else entirely")]])
check("title without the prefix is ignored", found == [], found)

found = collect([[issue(3, "BYPASS: CVE-2026-1", days_old=200)]])
check("expired bypass ignored", found == [], found)

found = collect([[issue(4, "BYPASS: CVE-2026-1", days_old=200)]], BYPASS_MAX_AGE="0")
check("expiry disabled by zero", [e["id"] for e in found] == ["CVE-2026-1"], found)

found = collect([[issue(5, "BYPASS: CVE-2026-1", pull=True)]])
check("pull requests excluded", found == [], found)

found = collect([[issue(6, "BYPASS: no identifier here")]])
check("labelled issue without an ID ignored", found == [], found)

print("pagination")
page_one = [issue(n, f"BYPASS: CVE-2026-{n}") for n in range(100)]
page_two = [issue(500, "BYPASS: CVE-2026-999")]
found = collect([page_one, page_two])
ids = {entry["id"] for entry in found}
check("second page read", "CVE-2026-999" in ids, sorted(ids)[:3])
check("all entries collected", len(found) == 101, len(found))

print("failure handling")


def boom(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
    raise urllib.error.HTTPError("u", 403, "forbidden", Message(), None)


original = urllib.request.urlopen
urllib.request.urlopen = boom
try:
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "out"
        out.touch()
        saved = dict(os.environ)
        os.environ.update(
            {
                "BYPASS_REPO": "example/repo",
                "BYPASS_LABEL": "cve-bypass",
                "BYPASS_PREFIX": "BYPASS:",
                "BYPASS_MAX_AGE": "90",
                "GH_TOKEN": "",
                "API_URL": "https://api.github.com",
                "GITHUB_OUTPUT": str(out),
            }
        )
        try:
            rc = collect_bypasses.main()
            text = out.read_text(encoding="utf-8")
        finally:
            os.environ.clear()
            os.environ.update(saved)
    check("API failure does not fail the step", rc == 0, rc)
    check("API failure applies no bypasses", "bypasses=[]" in text, text)
finally:
    urllib.request.urlopen = original

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All collector tests passed ✅")
