#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for the Grype database provenance logic.

The "Refresh the Grype DB" step decides whether a database may be
cached and, in one branch, deletes and re-downloads it. That branch is
destructive and can stop the run, so it is the part of the cache work
that most needs coverage: a regression could either delete a valid
database because a marker went stale, or fail to replace one that
genuinely belongs to another feed.

The step's script is extracted from ``action.yaml`` and run for real
against a stub ``grype``, so these tests exercise the shipped code
rather than a copy of it. No network, no Grype binary and no YAML
library are needed -- the CI job runs this file directly with python3,
and the project declares no dependencies.
"""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


def extract_run(step_name: str) -> str:
    """Return the ``run:`` script of the named step in action.yaml.

    Deliberately a small indentation-aware reader rather than a YAML
    parse: the project declares no dependencies, and the CI job invokes
    this file with a bare python3 that has no PyYAML available.
    """
    lines = (ROOT / "action.yaml").read_text().splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.strip() == f'- name: "{step_name}"'
    )
    run_at = next(
        i for i in range(start, len(lines)) if lines[i].strip() in ("run: |", "run: |-")
    )
    body_indent = len(lines[run_at + 1]) - len(lines[run_at + 1].lstrip())
    out: list[str] = []
    for line in lines[run_at + 1 :]:
        if line.strip() and (len(line) - len(line.lstrip())) < body_indent:
            break
        out.append(line[body_indent:])
    return "\n".join(out)


REFRESH = extract_run("Refresh the Grype DB")
RESOLVE = extract_run("Resolve Grype DB cache location")

# A stub Grype driven by files in its own directory, so a test can make
# the database change, an update fail, or a delete fail, without any
# real binary. 'db status' mirrors the real command in the detail that
# matters here: it prints Built: even for a database it rejects, and
# signals invalidity only through the exit status.
STUB = """#!/usr/bin/env bash
set -uo pipefail
state="${STUB_STATE}"
# Record the whole argv, so a test can assert that cache operations
# carry the same --config the scan will use.
printf '%s\\n' "$*" >> "${state}/argv"
args=("$@")
# Consume leading global options exactly as Grype's parser does, so
# the command is found whether or not a --config precedes it.
i=0
while [ ${i} -lt ${#args[@]} ]; do
  case "${args[${i}]}" in
    --config|-c) i=$((i + 2)) ;;
    --config=*|-c=*) i=$((i + 1)) ;;
    *) break ;;
  esac
done
cmd="${args[${i}]:-}"; sub="${args[$((i + 1))]:-}"
if [ "${cmd}" = "version" ]; then
  echo "Version:             0.109.1"
  exit 0
fi
if [ "${cmd}" = "config" ]; then
  # Older Grype releases have no 'config' command at all, which is
  # what no_config models: the call fails and prints nothing.
  [ -f "${state}/no_config" ] && exit 1
  cat "${state}/config"
  exit 0
fi
if [ "${cmd}" = "db" ]; then
  echo "${sub}" >> "${state}/calls"
  case "${sub}" in
    status)
      [ -f "${state}/build" ] || exit 1
      echo "Built: $(cat "${state}/build")"
      # Grype names the archive it installed, checksum included, which
      # is the database's content identity.
      [ -f "${state}/dbref" ] && echo "From: $(cat "${state}/dbref")"
      [ -f "${state}/invalid" ] && exit 1
      exit 0
      ;;
    update)
      [ -f "${state}/update_fails" ] && exit 1
      # Grype replaces the database only with a *later* build, so an
      # existing newer one survives an update. Modelled by writing the
      # new build when none is present (a download), or when the feed
      # is explicitly newer; otherwise the update is a no-op, which is
      # what leaves a foreign database in place.
      if [ ! -f "${state}/build" ] || [ -f "${state}/feed_newer" ]; then
        [ -f "${state}/new_build" ] && cp "${state}/new_build" "${state}/build"
        # A download also brings a different database, so its
        # reported identity changes with it.
        [ -f "${state}/new_dbref" ] && cp "${state}/new_dbref" "${state}/dbref"
      fi
      exit 0
      ;;
    delete)
      [ -f "${state}/delete_fails" ] && exit 1
      rm -f "${state}/build"
      exit 0
      ;;
  esac
fi
exit 0
"""


def run_refresh(
    *,
    build: str | None,
    new_build: str | None = None,
    feed_newer: bool = False,
    marker: str | None = None,
    matched_key: str = "",
    cache_db: str = "true",
    source_id: str = "B",
    delete_fails: bool = False,
    update_fails: bool = False,
    update_fails_after_prime: bool = False,
    invalid: bool = False,
    config: str = "",
    marker_symlink_to: str | None = None,
    marker_is_dir: bool = False,
    prime_source: str | None = None,
    prime_build: str | None = None,
    db_ref: str | None = None,
    db_ref_after_prime: str | None = None,
    new_db_ref: str | None = None,
) -> tuple[int, str, dict[str, str], str | None, list[str]]:
    """Run the real refresh script against the stub and report outcomes.

    ``prime_source`` runs the script once beforehand in the same
    directory, so the marker under test is one a real run wrote --
    fingerprint and all -- rather than a hand-written string that would
    drift from the implementation.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        state = root / "state"
        cache = root / "grype" / "db"
        state.mkdir(parents=True)
        cache.mkdir(parents=True)
        if build is not None:
            (state / "build").write_text(build)
        if new_build is not None:
            (state / "new_build").write_text(new_build)
        if feed_newer:
            (state / "feed_newer").touch()
        if delete_fails:
            (state / "delete_fails").touch()
        if update_fails:
            (state / "update_fails").touch()
        if invalid:
            (state / "invalid").touch()
        if marker is not None:
            (cache / ".grype-scan-action-source").write_text(marker + "\n")
        if marker_symlink_to is not None:
            (cache / ".grype-scan-action-source").symlink_to(marker_symlink_to)
        if marker_is_dir:
            (cache / ".grype-scan-action-source").mkdir()
        # A database file, so the fingerprint has something to
        # describe.
        (cache / "vulnerability.db").write_text("database-contents")
        # Grype's reported content identity for whatever is installed.
        (state / "dbref").write_text(
            db_ref
            if db_ref is not None
            else "https://feed/db.tar.zst?checksum=sha256%3Aaaa"
        )

        stub = root / "bin" / "grype"
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text(STUB)
        stub.chmod(0o755)
        out_file = root / "gh_output"
        out_file.touch()

        def invoke(source: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["bash", "-c", REFRESH],
                capture_output=True,
                text=True,
                env={
                    "PATH": "/usr/bin:/bin:/usr/local/bin",
                    "HOME": str(root),
                    "STUB_STATE": str(state),
                    "GRYPE_CMD": str(stub),
                    "PREFIX": "grype-db-v1-abc-",
                    "DIR": str(cache),
                    "SOURCE_ID": source,
                    "CACHE_DB": cache_db,
                    "INPUT_CONFIG": config,
                    "MATCHED_KEY": matched_key,
                    "GITHUB_OUTPUT": str(out_file),
                },
            )

        if prime_source is not None:
            if prime_build is not None:
                (state / "new_build").write_text(prime_build)
            invoke(prime_source)
            # The priming run's bookkeeping must not be read as the
            # run under test's.
            for name in ("calls", "argv"):
                (state / name).unlink(missing_ok=True)
            out_file.write_text("")
            if new_build is not None:
                (state / "new_build").write_text(new_build)
            else:
                (state / "new_build").unlink(missing_ok=True)
            # Applied after priming, so it models something replacing
            # the database *since* the marker was written -- which is
            # the whole point of fingerprinting it.
            # Models the database being swapped for another with the
            # same build time and the same file sizes -- only its
            # content identity differs.
            if db_ref_after_prime is not None:
                (state / "dbref").write_text(db_ref_after_prime)
            if new_db_ref is not None:
                (state / "new_dbref").write_text(new_db_ref)
            # Applied after priming, so the priming run can still
            # establish the database and marker this case needs.
            if update_fails_after_prime:
                (state / "update_fails").touch()

        proc = invoke(source_id)
        outputs: dict[str, str] = {}
        for line in out_file.read_text().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                outputs[key] = value
        marker_path = cache / ".grype-scan-action-source"
        marker_now = marker_path.read_text().strip() if marker_path.is_file() else None
        calls_file = state / "calls"
        calls = calls_file.read_text().split() if calls_file.is_file() else []
        argv_file = state / "argv"
        argv = argv_file.read_text().splitlines() if argv_file.is_file() else []
        globals()["LAST_ARGV"] = argv
        return proc.returncode, proc.stdout + proc.stderr, outputs, marker_now, calls


def run_resolve(
    *,
    cache_dir: str | None = None,
    update_url: str = "https://grype.anchore.io/databases",
    auto_update: str = "true",
    no_config: bool = False,
) -> tuple[int, str, dict[str, str]]:
    """Run the real resolve script against the stub and report outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        state = root / "state"
        state.mkdir(parents=True)
        cache = cache_dir if cache_dir is not None else str(root / "grype" / "db")
        (state / "config").write_text(
            f"  cache-dir: '{cache}'\n"
            f"  update-url: '{update_url}'\n"
            f"  auto-update: {auto_update}\n"
        )
        if no_config:
            (state / "no_config").touch()
        stub = root / "bin" / "grype"
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text(STUB)
        stub.chmod(0o755)
        out_file = root / "gh_output"
        out_file.touch()
        proc = subprocess.run(
            ["bash", "-c", RESOLVE],
            capture_output=True,
            text=True,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "HOME": str(root / "home"),
                "GITHUB_WORKSPACE": str(root / "workspace"),
                "RUNNER_TEMP": str(root / "runnertemp"),
                "STUB_STATE": str(state),
                "GRYPE_CMD": str(stub),
                "INPUT_CONFIG": "",
                "GITHUB_OUTPUT": str(out_file),
            },
        )
        outputs: dict[str, str] = {}
        for line in out_file.read_text().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                outputs[key] = value
        return proc.returncode, proc.stdout + proc.stderr, outputs


LAST_ARGV: list[str] = []

print("Grype database cache location")

# A Grype release predating `grype config --load` still scans, so an
# unavailable configuration view must cost the cache and nothing more.
# Under `set -e` an unguarded assignment would abort the whole action.
rc, log, out = run_resolve(no_config=True)
check("missing config command does not fail the run", rc == 0, rc)
check("missing config command skips caching", out.get("cacheable") == "false", out)

# A pinned database is left alone entirely rather than restored over.
rc, log, out = run_resolve(auto_update="false")
check("auto-update false skips caching", out.get("cacheable") == "false", out)
check("auto-update false keeps the run passing", rc == 0, rc)

# Without a resolvable feed there is no namespace, and a shared one
# would be the cross-feed contamination the segment exists to prevent.
rc, log, out = run_resolve(update_url="")
check("unresolvable feed skips caching", out.get("cacheable") == "false", out)

# Paths that would archive more than Grype's database. Each case also
# asserts *which* refusal fired: a tilde path that reached the
# non-absolute check instead of the home guard would otherwise pass for
# the wrong reason, which is how a guard silently stops being tested.
for label, path, reason in (
    ("home directory", "~", "contains"),
    ("non-Grype directory", "~/.ssh", "does not look like"),
    ("workspace directory", "$GITHUB_WORKSPACE", "not absolute"),
    ("glob pattern", "~/grype/**", "glob"),
    # A newline inside the scalar is caught during extraction rather
    # than by the newline guard downstream: head -n1 leaves an opening
    # quote with no closing one, which is exactly the truncation the
    # scalar validation exists to make visible.
    ("newline in scalar", "~/grype/db\netc", "unterminated"),
    ("filesystem root", "/", "too broad"),
    # Refused by the ownership test rather than the depth backstop,
    # because canonicalisation can lengthen a path - /etc resolves to
    # /private/etc on macOS. Either refusal is correct; asserting the
    # message keeps the test honest about which one ran.
    ("top-level directory", "/etc", "does not look like"),
    ("Windows path", "C:\\\\Users\\\\runner\\\\grype\\\\db", "Windows"),
    ("relative path", "grype/db", "not absolute"),
):
    rc, log, out = run_resolve(cache_dir=path)
    check(f"{label} skips caching", out.get("cacheable") == "false", (path, out))
    check(f"{label} keeps the run passing", rc == 0, rc)
    check(f"{label} is refused for the stated reason", reason in log, log[-200:])

# The ordinary case still caches, so the refusals above are attributable
# to their conditions rather than to the harness.
rc, log, out = run_resolve()
check("default layout is cacheable", out.get("cacheable") == "true", out)
check("default layout derives a source segment", bool(out.get("source-id")), out)
check(
    "default layout derives a prefix",
    out.get("prefix", "").startswith("grype-db-v0.109.1-"),
    out,
)

print()
print("Grype database provenance")

# The branch this file exists for: the marker names a different source
# AND still describes the database in hand, so the database is known to
# belong to another feed. It must be deleted and replaced, because the
# scan reads the same directory and would otherwise report results from
# the wrong vulnerability data.
rc, log, out, marker, calls = run_refresh(
    build=None,
    new_build="t9",
    prime_source="A",
    prime_build="t2",
    source_id="B",
    new_db_ref="https://feed-b/db.tar.zst?checksum=sha256%3Abbb",
)
check("foreign database is deleted", "delete" in calls, calls)
check("foreign database is replaced", rc == 0 and out.get("save") == "true", out)
check(
    "replacement is re-marked for this source",
    marker is not None and marker.startswith("B t9 "),
    marker,
)
# The marker must bind the *replacement's* identity, not the departed
# feed's, or a later run can neither recognise its own database nor
# identify a genuinely foreign one.
expected_fp = hashlib.sha256(
    b"https://feed-b/db.tar.zst?checksum=sha256%3Abbb"
).hexdigest()[:16]
check(
    "replacement is marked with the new database's identity",
    marker is not None and marker.endswith(expected_fp),
    (marker, expected_fp),
)

# A marker that names another source but no longer describes the
# database is stale, not evidence. Deleting here would destroy a valid
# database -- and during a feed outage, the failed replacement would
# fail a run that had a usable database all along.
rc, log, out, marker, calls = run_refresh(
    build="t2", marker="A t1 0000000000000000", source_id="B"
)
check("stale marker does not delete", "delete" not in calls, calls)
check("stale marker leaves run passing", rc == 0, rc)
check("stale marker does not save", out.get("save") == "false", out)
check(
    "stale marker is not overwritten",
    marker == "A t1 0000000000000000",
    marker,
)

# Deleting must be fatal rather than best-effort: a surviving foreign
# database could otherwise be marked and cached as this source's own.
rc, log, out, marker, calls = run_refresh(
    build=None,
    new_build="t9",
    prime_source="A",
    prime_build="t2",
    source_id="B",
    delete_fails=True,
)
check("failed delete stops the run", rc != 0, rc)
check("failed delete does not save", out.get("save") != "true", out)

# Once the foreign database is gone, a failed replacement leaves nothing
# usable, so the run must stop rather than scan against whatever
# remains.
rc, log, out, marker, calls = run_refresh(
    build=None,
    prime_source="A",
    prime_build="t2",
    source_id="B",
    update_fails_after_prime=True,
)
check("failed replacement deletes first", "delete" in calls, calls)
check("failed replacement stops the run", rc != 0, rc)
check(
    "failed replacement is reported as a refusal to scan",
    "refusing to scan" in log,
    log[-300:],
)

# An unattributable database (nothing restored, nothing refreshed, no
# marker) is not published under this source's prefix, but is still
# scanned against: there is no evidence it is wrong.
rc, log, out, marker, calls = run_refresh(build="t2", source_id="B")
check("unattributed database does not save", out.get("save") == "false", out)
check("unattributed database keeps the run passing", rc == 0, rc)
check("unattributed database is not marked", marker is None, marker)

# Our own marker, still describing the database, attests it.
rc, log, out, marker, calls = run_refresh(
    build=None, prime_source="B", prime_build="t2", source_id="B"
)
check("own marker attests the database", out.get("save") == "true", out)

# A cold runner downloads the database, so the build moves on and the
# entry is saved.
rc, log, out, marker, calls = run_refresh(build=None, new_build="t5", source_id="B")
check("fresh download saves", out.get("save") == "true", out)
check(
    "fresh download is marked",
    marker is not None and marker.startswith("B t5 "),
    marker,
)

# restore-only reads the cache and never writes it, but still runs the
# provenance work and leaves the directory attributable.
rc, log, out, marker, calls = run_refresh(
    build=None, new_build="t5", cache_db="restore-only", source_id="B"
)
check("restore-only never saves", out.get("save") == "false", out)
check(
    "restore-only still marks provenance",
    marker is not None and marker.startswith("B t5 "),
    marker,
)

# restore-only must protect the scan too: a known foreign database is
# replaced in this mode as well, even though nothing is cached.
rc, log, out, marker, calls = run_refresh(
    build=None,
    new_build="t9",
    prime_source="A",
    prime_build="t2",
    cache_db="restore-only",
    source_id="B",
)
check("restore-only replaces a foreign database", "delete" in calls, calls)
check("restore-only still never saves", out.get("save") == "false", out)

# A database Grype reports as invalid is left alone rather than
# published under a valid-looking key. Grype prints Built: even for a
# database it rejects and signals that only through the exit status, so
# this is the case where reading the timestamp alone would cache a
# corrupt database for every later run to restore.
rc, log, out, marker, calls = run_refresh(
    build=None, prime_source="B", prime_build="t2", source_id="B", invalid=True
)
check("invalid database does not save", out.get("save") == "false", out)
check("invalid database keeps the run passing", rc == 0, rc)
check(
    "invalid database is reported",
    "reports the database as invalid" in log,
    log[-300:],
)

# The same database, without the invalid sentinel, is cached -- so the
# assertions above come from the validity check rather than from some
# other condition happening to block the save.
rc, log, out, marker, calls = run_refresh(
    build=None, prime_source="B", prime_build="t2", source_id="B"
)
check("valid database still saves", out.get("save") == "true", out)

# A replacement that keeps the same upstream build time must not
# inherit the previous attestation. Two feeds can publish the same
# build, so the timestamp alone is not an identity -- the marker also
# binds the database's own fingerprint.
# The identity must bind contents, not file sizes: a same-build,
# same-length database from another feed differs only in the checksum
# Grype reports for it.
rc, log, out, marker, calls = run_refresh(
    build=None,
    prime_source="B",
    prime_build="t2",
    source_id="B",
    db_ref_after_prime="https://other-feed/db.tar.zst?checksum=sha256%3Abbb",
)
check(
    "same-size different-content database is not attested",
    out.get("save") == "false",
    out,
)
check("same-size different-content keeps the run passing", rc == 0, rc)

# A Grype build too old to report a content identity leaves the
# database unattributable rather than letting every such database share
# one blank identity and vouch for the next.
rc, log, out, marker, calls = run_refresh(build="t2", source_id="B", db_ref="")
check(
    "unreportable identity is not attested",
    out.get("save") == "false",
    out,
)
check("unreportable identity is not marked", marker is None, marker)

# The scan's configuration must reach every cache operation, or the
# cache keys and refreshes one configuration while the scan reads
# another.
rc, log, out, marker, calls = run_refresh(
    build="t2", new_build="t9", feed_newer=True, source_id="B", config="/tmp/g.yaml"
)
db_calls = [line for line in LAST_ARGV if " db " in f" {line} "]
check("config reaches every database call", bool(db_calls), LAST_ARGV)
check(
    "every database call carries the scan's config",
    all("--config /tmp/g.yaml" in line for line in db_calls),
    db_calls,
)

# A marker that is a symlink to a directory must be replaced, not
# followed: mv would otherwise drop the temporary file inside the
# target directory and leave the link in place.
with tempfile.TemporaryDirectory() as tmp:
    victim = pathlib.Path(tmp) / "victim"
    victim.mkdir()
    rc, log, out, marker, calls = run_refresh(
        build=None, new_build="t5", source_id="B", marker_symlink_to=str(victim)
    )
    check(
        "directory symlink marker is replaced, not followed",
        marker is not None and not list(victim.iterdir()),
        (marker, list(victim.iterdir())),
    )

# A directory occupying the reserved marker name must cost the cache
# and nothing more: the database is usable, so the scan proceeds.
with tempfile.TemporaryDirectory() as tmp:
    rc, log, out, marker, calls = run_refresh(
        build=None, new_build="t5", source_id="B", marker_is_dir=True
    )
    check("marker path directory keeps the run passing", rc == 0, rc)
    check("marker path directory does not save", out.get("save") == "false", out)

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All provenance tests passed ✅")
