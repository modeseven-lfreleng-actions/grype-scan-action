#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for the report evaluation logic.

These run without Grype or network access: they feed synthetic report
JSON through the evaluate script and assert on its outputs and on the
rendered step summary.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

FAILURES: list[str] = []


def match(
    package: str,
    vuln: str,
    severity: str,
    fix: str | None = None,
    risk: float | None = None,
    epss: float | None = None,
) -> dict:
    """Build a synthetic Grype match."""
    vulnerability: dict = {"id": vuln, "severity": severity}
    vulnerability["fix"] = (
        {"versions": [fix], "state": "fixed"}
        if fix
        else {"versions": [], "state": "not-fixed"}
    )
    if risk is not None:
        vulnerability["risk"] = risk
    if epss is not None:
        vulnerability["epss"] = [{"cve": vuln, "epss": epss}]
    return {
        "vulnerability": vulnerability,
        "artifact": {"name": package, "version": "1.0.0", "type": "apk"},
    }


def run(matches: list[dict], **env_overrides) -> tuple[dict, str]:
    """Run the evaluator over one synthetic report; return outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "grype-results.json"
        report.write_text(json.dumps({"matches": matches}), encoding="utf-8")
        out_file = pathlib.Path(tmp) / "out"
        summary_file = pathlib.Path(tmp) / "summary"
        out_file.touch()
        summary_file.touch()

        env = dict(os.environ)
        env.update(
            {
                "MANIFEST": f"{report}|sbom:test",
                "INPUT_FAIL_ON": "high",
                "INPUT_NAME": "",
                "INPUT_SUMMARY": "true",
                "INPUT_SUMMARY_TITLE": "Grype Vulnerability Scan",
                "INPUT_SUMMARY_MAX_ROWS": "50",
                "INPUT_SUMMARY_ON_SUCCESS": "true",
                "BYPASSES": "[]",
                "BYPASS_REPO": "example/repo",
                "GITHUB_OUTPUT": str(out_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
            }
        )
        env.update({k: str(v) for k, v in env_overrides.items()})

        env["PYTHONPATH"] = str(ROOT)
        subprocess.run(
            [sys.executable, "-m", "scripts.evaluate"],
            cwd=str(ROOT),
            env=env,
            check=True,
            capture_output=True,
        )

        outputs: dict[str, str] = {}
        raw = out_file.read_text(encoding="utf-8")
        for line in raw.splitlines():
            if "=" in line and "<<" not in line:
                key, _, value = line.partition("=")
                outputs[key] = value
        return outputs, summary_file.read_text(encoding="utf-8")


def check(label: str, condition: bool, detail: object = "") -> None:
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


print("severity threshold")
outputs, _ = run([match("a", "CVE-1", "High"), match("b", "CVE-2", "Low")])
check("high gates, low does not", outputs["gating-matches"] == "1", outputs)
check("total counts every match", outputs["total-matches"] == "2", outputs)

outputs, _ = run([match("a", "CVE-1", "Medium")], INPUT_FAIL_ON="critical")
check("below threshold does not gate", outputs["gating"] == "false", outputs)

outputs, _ = run([match("a", "CVE-1", "Critical")], INPUT_FAIL_ON="none")
check("fail-on none never gates", outputs["gating"] == "false", outputs)

print("unknown severity")
outputs, _ = run([match("a", "CVE-1", "Unknown")])
check(
    "unknown severity does not gate",
    outputs["gating"] == "false" and outputs["total-matches"] == "1",
    outputs,
)

print("bypasses")
bypass = json.dumps(
    [{"id": "CVE-1", "issue": 7, "url": "https://example/7", "title": "BYPASS: CVE-1"}]
)
outputs, summary = run(
    [match("a", "CVE-1", "Critical"), match("b", "CVE-2", "High")],
    BYPASSES=bypass,
)
check("bypassed match does not gate", outputs["gating-matches"] == "1", outputs)
check("bypass is counted", outputs["bypassed-matches"] == "1", outputs)
check("bypassed id reported", outputs["bypassed-ids"] == "CVE-1", outputs)
check("bypass shown in summary", "Suppressed by an approved bypass" in summary)
check("bypass links the issue", "https://example/7" in summary)

outputs, _ = run(
    [match("a", "CVE-1", "Critical")],
    BYPASSES=json.dumps([{"id": "cve-1", "issue": 7, "url": "", "title": ""}]),
)
check("bypass matching is case-insensitive", outputs["gating"] == "false", outputs)

outputs, _ = run([match("a", "CVE-1", "Critical")], BYPASSES="not json")
check(
    "malformed bypass data keeps the gate closed",
    outputs["gating"] == "true",
    outputs,
)

print("rendering")
outputs, summary = run(
    [
        match("pkg-a", "CVE-9", "Critical", fix="2.0.0", risk=80.5, epss=0.95),
        match("pkg-b", "CVE-8", "High", risk=10.0, epss=0.0000001),
    ]
)
check("table header present", "| Severity | Package |" in summary)
check("fix version rendered", "2.0.0" in summary)
check("unfixed state rendered", "not-fixed" in summary)
check("epss percentage rendered", "95.0%" in summary)
check("tiny epss floors to <0.01%", "<0.01%" in summary)
check("critical sorts first", summary.index("CVE-9") < summary.index("CVE-8"))

outputs, summary = run(
    [match(f"pkg{i}", f"CVE-{i}", "High") for i in range(10)],
    INPUT_SUMMARY_MAX_ROWS="3",
)
check("row cap applied", "Showing 3 of 10 findings" in summary)

outputs, summary = run([match("a|b", "CVE-1", "High")])
check("pipes escaped in cells", "a\\|b" in summary)

outputs, summary = run([], INPUT_SUMMARY_ON_SUCCESS="false")
check("clean summary suppressed on request", summary.strip() == "")

outputs, summary = run([])
check("clean scan reports success", "No vulnerabilities reported" in summary)
check("clean scan does not gate", outputs["gating"] == "false", outputs)

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All evaluate tests passed ✅")
