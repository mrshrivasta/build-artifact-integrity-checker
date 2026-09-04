"""Tests for the Security Engine and Detection Rules.

Two layers:
1. Rule-level unit tests against synthetic context dicts (no filesystem I/O).
2. Genuine engine-level tests that create REAL temp directories with REAL
   files, run ScanEngine.run() twice against the SAME target path (passing
   the first run's real snapshot back in as previous_snapshot, exactly like
   the web app and CLI do), with REAL file content/size/mtime/deletion/
   addition changes made on disk in between — asserting the real expected
   BAI-00x findings fire. No mocking of hashing or diffing.
"""
import os
import time
import tempfile
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, hash_file
from app.detection_rules import (
    rule_hash_changed_same_size,
    rule_hash_changed_different_size,
    rule_file_removed,
    rule_file_added,
    rule_first_scan_baseline,
    rule_suspicious_mtime_rollback,
)


# --------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# --------------------------------------------------------------------------

def test_rule_hash_changed_same_size_fires():
    ctx = {
        "relative_path": "bin/app",
        "current": {"sha256": "b" * 64, "size": 100, "mtime": 200.0},
        "previous": {"sha256": "a" * 64, "size": 100, "mtime": 100.0},
        "is_first_scan": False,
    }
    result = rule_hash_changed_same_size(ctx)
    assert result is not None
    assert result["rule_id"] == "BAI-001"
    assert result["severity"] == "critical"


def test_rule_hash_changed_same_size_does_not_fire_when_hash_unchanged():
    ctx = {
        "relative_path": "bin/app",
        "current": {"sha256": "a" * 64, "size": 100, "mtime": 200.0},
        "previous": {"sha256": "a" * 64, "size": 100, "mtime": 100.0},
        "is_first_scan": False,
    }
    assert rule_hash_changed_same_size(ctx) is None


def test_rule_hash_changed_different_size_fires():
    ctx = {
        "relative_path": "bin/app",
        "current": {"sha256": "b" * 64, "size": 150, "mtime": 200.0},
        "previous": {"sha256": "a" * 64, "size": 100, "mtime": 100.0},
        "is_first_scan": False,
    }
    result = rule_hash_changed_different_size(ctx)
    assert result is not None
    assert result["rule_id"] == "BAI-002"
    assert result["severity"] == "high"


def test_rule_hash_changed_different_size_does_not_fire_when_size_same():
    ctx = {
        "relative_path": "bin/app",
        "current": {"sha256": "b" * 64, "size": 100, "mtime": 200.0},
        "previous": {"sha256": "a" * 64, "size": 100, "mtime": 100.0},
        "is_first_scan": False,
    }
    assert rule_hash_changed_different_size(ctx) is None


def test_rule_file_removed_fires():
    ctx = {
        "relative_path": "bin/gone",
        "current": None,
        "previous": {"sha256": "a" * 64, "size": 100, "mtime": 100.0},
        "is_first_scan": False,
    }
    result = rule_file_removed(ctx)
    assert result is not None
    assert result["rule_id"] == "BAI-003"


def test_rule_file_added_fires():
    ctx = {
        "relative_path": "bin/new",
        "current": {"sha256": "c" * 64, "size": 50, "mtime": 300.0},
        "previous": None,
        "is_first_scan": False,
    }
    result = rule_file_added(ctx)
    assert result is not None
    assert result["rule_id"] == "BAI-004"


def test_rule_file_added_does_not_fire_on_first_scan():
    ctx = {
        "relative_path": "bin/new",
        "current": {"sha256": "c" * 64, "size": 50, "mtime": 300.0},
        "previous": None,
        "is_first_scan": True,
    }
    assert rule_file_added(ctx) is None


def test_rule_first_scan_baseline_fires():
    ctx = {
        "relative_path": "bin/new",
        "current": {"sha256": "c" * 64, "size": 50, "mtime": 300.0},
        "previous": None,
        "is_first_scan": True,
    }
    result = rule_first_scan_baseline(ctx)
    assert result is not None
    assert result["rule_id"] == "BAI-005"
    assert result["severity"] == "low"


def test_rule_suspicious_mtime_rollback_fires():
    ctx = {
        "relative_path": "bin/app",
        "current": {"sha256": "a" * 64, "size": 100, "mtime": 50.0},
        "previous": {"sha256": "a" * 64, "size": 100, "mtime": 100.0},
        "is_first_scan": False,
    }
    result = rule_suspicious_mtime_rollback(ctx)
    assert result is not None
    assert result["rule_id"] == "BAI-006"


def test_rule_suspicious_mtime_rollback_does_not_fire_when_hash_changed():
    ctx = {
        "relative_path": "bin/app",
        "current": {"sha256": "b" * 64, "size": 100, "mtime": 50.0},
        "previous": {"sha256": "a" * 64, "size": 100, "mtime": 100.0},
        "is_first_scan": False,
    }
    assert rule_suspicious_mtime_rollback(ctx) is None


# --------------------------------------------------------------------------
# Engine-level tests: real temp dirs, real files, real hashing, real diffing
# --------------------------------------------------------------------------

def test_hash_file_returns_real_sha256_of_actual_bytes():
    tmpdir = tempfile.mkdtemp()
    try:
        target = os.path.join(tmpdir, "a.txt")
        with open(target, "wb") as f:
            f.write(b"hello world")
        import hashlib
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert hash_file(target) == expected
    finally:
        shutil.rmtree(tmpdir)


def test_first_scan_establishes_baseline():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "unchanged.bin"), "wb") as f:
            f.write(b"A" * 32)
        with open(os.path.join(tmpdir, "will_be_modified_same_size.bin"), "wb") as f:
            f.write(b"B" * 32)
        with open(os.path.join(tmpdir, "will_be_modified_diff_size.bin"), "wb") as f:
            f.write(b"C" * 32)
        with open(os.path.join(tmpdir, "will_be_removed.bin"), "wb") as f:
            f.write(b"D" * 32)

        engine = ScanEngine(tmpdir, previous_snapshot=None, max_depth=3)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert rule_ids == {"BAI-005"}
        assert result["files_scanned"] == 4
        assert len(result["snapshot"]) == 4
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_full_diff_cycle_detects_real_changes():
    """The core end-to-end test: real first scan -> real file mutations on
    disk -> real second scan diffed against the real first snapshot."""
    tmpdir = tempfile.mkdtemp()
    try:
        unchanged_path = os.path.join(tmpdir, "unchanged.bin")
        same_size_path = os.path.join(tmpdir, "same_size.bin")
        diff_size_path = os.path.join(tmpdir, "diff_size.bin")
        removed_path = os.path.join(tmpdir, "removed.bin")

        with open(unchanged_path, "wb") as f:
            f.write(b"A" * 32)
        with open(same_size_path, "wb") as f:
            f.write(b"B" * 32)
        with open(diff_size_path, "wb") as f:
            f.write(b"C" * 32)
        with open(removed_path, "wb") as f:
            f.write(b"D" * 32)

        # First real scan: no prior baseline -> BAI-005 for every file.
        engine1 = ScanEngine(tmpdir, previous_snapshot=None, max_depth=3)
        result1 = engine1.run()
        assert {f["rule_id"] for f in result1["findings"]} == {"BAI-005"}
        first_snapshot = result1["snapshot"]

        # Real, on-disk mutations between scans.
        time.sleep(0.05)  # ensure a distinct, later real mtime
        with open(same_size_path, "wb") as f:
            f.write(b"X" * 32)  # same size (32), different content -> BAI-001
        with open(diff_size_path, "wb") as f:
            f.write(b"Y" * 64)  # different size, different content -> BAI-002
        os.remove(removed_path)  # -> BAI-003
        added_path = os.path.join(tmpdir, "added.bin")
        with open(added_path, "wb") as f:
            f.write(b"Z" * 16)  # -> BAI-004

        # Second real scan, diffed against the real first snapshot.
        engine2 = ScanEngine(tmpdir, previous_snapshot=first_snapshot, max_depth=3)
        result2 = engine2.run()

        by_rule = {}
        for f in result2["findings"]:
            by_rule.setdefault(f["rule_id"], []).append(f)

        assert "BAI-001" in by_rule
        assert by_rule["BAI-001"][0]["file_path"] == "same_size.bin"

        assert "BAI-002" in by_rule
        assert by_rule["BAI-002"][0]["file_path"] == "diff_size.bin"

        assert "BAI-003" in by_rule
        assert by_rule["BAI-003"][0]["file_path"] == "removed.bin"

        assert "BAI-004" in by_rule
        assert by_rule["BAI-004"][0]["file_path"] == "added.bin"

        # unchanged.bin must NOT appear in any finding (identical hash/size/mtime-not-rolled-back)
        assert not any(f["file_path"] == "unchanged.bin" for f in result2["findings"])

        assert result2["files_scanned"] == 4  # unchanged, same_size, diff_size, added
        assert result2["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_mtime_rollback_detected_without_hash_change():
    tmpdir = tempfile.mkdtemp()
    try:
        target = os.path.join(tmpdir, "rollback.bin")
        with open(target, "wb") as f:
            f.write(b"SAME" * 8)

        engine1 = ScanEngine(tmpdir, previous_snapshot=None, max_depth=3)
        result1 = engine1.run()
        first_snapshot = result1["snapshot"]

        # Roll the real mtime backward without changing content.
        old_mtime = first_snapshot["rollback.bin"]["mtime"] - 1000
        os.utime(target, (old_mtime, old_mtime))

        engine2 = ScanEngine(tmpdir, previous_snapshot=first_snapshot, max_depth=3)
        result2 = engine2.run()

        rule_ids = {f["rule_id"] for f in result2["findings"]}
        assert "BAI-006" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_excluded_paths_are_skipped():
    tmpdir = tempfile.mkdtemp()
    try:
        excluded = os.path.join(tmpdir, "excluded")
        os.mkdir(excluded)
        with open(os.path.join(excluded, "hidden.bin"), "wb") as f:
            f.write(b"x")
        with open(os.path.join(tmpdir, "visible.bin"), "wb") as f:
            f.write(b"y")

        engine = ScanEngine(tmpdir, previous_snapshot=None, max_depth=3, excludes=[excluded])
        result = engine.run()
        assert "excluded/hidden.bin" not in result["snapshot"]
        assert "visible.bin" in result["snapshot"]
    finally:
        shutil.rmtree(tmpdir)
