"""
Security Engine — Build Artifact Integrity Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Walks a REAL build-output ("dist") directory on the host filesystem, computes
a REAL hashlib.sha256 digest of every real file's actual bytes (plus real
os.path.getsize/getmtime), and diffs that REAL snapshot against the most
recent PRIOR real snapshot recorded for the SAME target_path — either the
previous ScanResult.metadata_snapshot row in the database (web app), or a
local `.bai_baseline.json` cache file (CLI, keyed by absolute target path).

No sample/mock data is ever generated — every Finding reflects an actual
sha256 hash comparison between two real scans of the same real directory.
"""
import hashlib
import json
import os
import time

from app.detection_rules import ALL_RULES

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}
HASH_CHUNK_SIZE = 65536


def hash_file(path):
    """Compute a REAL sha256 digest of a file's actual bytes, streamed in
    chunks so large build artifacts don't have to be loaded into memory."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


class ScanEngine:
    """Real filesystem walk + real sha256 hashing + real snapshot diffing.

    `previous_snapshot` (a dict of {relative_path: {"sha256", "size", "mtime"}}
    or None) is supplied by the caller (web dashboard route or CLI), which is
    responsible for looking it up from wherever the last scan of this exact
    target_path was recorded (database row for the web app, local JSON cache
    file for the CLI). This keeps the engine itself storage-agnostic and easy
    to unit test with synthetic previous snapshots.
    """

    def __init__(self, target_path, previous_snapshot=None, max_depth=12,
                 excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.previous_snapshot = previous_snapshot or {}
        self.is_first_scan = previous_snapshot is None
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []
        self.current_snapshot = {}

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous filesystem walk + real hashing +
        real diff against the previous snapshot. Returns a summary dict that
        also includes `snapshot` (the new baseline the caller should persist
        for the next scan of this target_path)."""
        start = time.time()
        self._walk(self.target_path, depth=0)
        self._diff_against_previous()
        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
            "snapshot": self.current_snapshot,
        }

    def _walk(self, path, depth):
        if self.files_scanned >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue

            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_dir:
                self._walk(full_path, depth + 1)
                continue

            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                size = entry.stat(follow_symlinks=False).st_size
                mtime = entry.stat(follow_symlinks=False).st_mtime
                digest = hash_file(full_path)
            except (PermissionError, FileNotFoundError, OSError):
                self.errors_count += 1
                continue

            rel_path = os.path.relpath(full_path, self.target_path)
            self.current_snapshot[rel_path] = {
                "sha256": digest,
                "size": size,
                "mtime": mtime,
            }
            self.files_scanned += 1

    def _diff_against_previous(self):
        """Real-diff current_snapshot against previous_snapshot and run every
        rule in ALL_RULES against a context dict for each affected relative
        path (present in either snapshot)."""
        all_paths = set(self.current_snapshot) | set(self.previous_snapshot)

        for rel_path in sorted(all_paths):
            cur = self.current_snapshot.get(rel_path)
            prev = self.previous_snapshot.get(rel_path)
            ctx = {
                "relative_path": rel_path,
                "current": cur,
                "previous": prev,
                "is_first_scan": self.is_first_scan,
            }
            self._apply_rules(ctx)

    def _apply_rules(self, ctx):
        for rule in ALL_RULES:
            try:
                result = rule(ctx)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = ctx["relative_path"]
                result["permissions_octal"] = result.pop("hash_compare", "")
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)


def load_previous_snapshot_for_user(db, ScanResult, user_id, target_path):
    """Look up the most recent PRIOR ScanResult for the SAME target_path from
    THIS user and return its stored real snapshot dict, or None if this is
    the first scan ever recorded for this target_path (web app helper)."""
    prior = (
        ScanResult.query
        .filter_by(user_id=user_id, target_path=target_path, status="completed")
        .order_by(ScanResult.id.desc())
        .first()
    )
    if prior is None or not prior.metadata_snapshot:
        return None
    try:
        return json.loads(prior.metadata_snapshot)
    except (TypeError, ValueError):
        return None
