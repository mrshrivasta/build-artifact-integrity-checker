"""
Detection Rules — Build Artifact Integrity Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL per-file "context" dict built by comparing two real
snapshots of a build-output directory: the CURRENT scan's real sha256/size/
mtime for a file, and the PRIOR scan's real sha256/size/mtime for the same
relative path (looked up from the database, or a local baseline cache file
for the CLI). Rules are pure functions — they take a context dict and return
a Finding dict (or None) — so they can be unit tested with synthetic
dictionaries without touching the filesystem.

Context dict shape passed to each rule:
{
    "relative_path": str,
    "current": {"sha256": str, "size": int, "mtime": float} | None,
    "previous": {"sha256": str, "size": int, "mtime": float} | None,
    "is_first_scan": bool,   # True only when there was NO prior ScanResult at all for this target_path
}
Exactly one of "current"/"previous" may be None (added / removed cases).
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def _hash_compare_str(prev_hash, cur_hash):
    """Short 'old:xxxx -> new:yyyy' string reused across rules for the
    permissions_octal-repurposed field."""
    old = (prev_hash or "")[:8]
    new = (cur_hash or "")[:8]
    return f"old:{old} -> new:{new}"


def rule_hash_changed_same_size(ctx):
    """BAI-001: A file's REAL sha256 hash changed between the prior scan and
    this one while its recorded size stayed exactly the same. Content that
    changes without a size delta is the classic signature of a deliberately
    crafted, size-preserving tamper (e.g. a byte-for-byte-equivalent-length
    trojaned binary) — treated as the highest-suspicion supply-chain risk."""
    cur = ctx.get("current")
    prev = ctx.get("previous")
    if not cur or not prev:
        return None
    if cur["sha256"] != prev["sha256"] and cur["size"] == prev["size"]:
        return {
            "rule_id": "BAI-001",
            "rule_name": "Hash Changed, Size Unchanged (Disguised Modification)",
            "severity": SEVERITY_CRITICAL,
            "description": (
                f"{ctx['relative_path']} has a different SHA-256 hash than the previous "
                f"scan, but the file size is identical ({cur['size']} bytes). This pattern "
                f"is consistent with a deliberate, size-preserving tamper of a build artifact."
            ),
            "hash_compare": _hash_compare_str(prev["sha256"], cur["sha256"]),
        }
    return None


def rule_hash_changed_different_size(ctx):
    """BAI-002: A file's REAL sha256 hash changed between scans AND its size
    also changed. Still a real, unexpected content modification of a build
    artifact — lower suspicion than a size-preserving tamper, but still worth
    investigating (could be a legitimate rebuild, or unauthorized injection)."""
    cur = ctx.get("current")
    prev = ctx.get("previous")
    if not cur or not prev:
        return None
    if cur["sha256"] != prev["sha256"] and cur["size"] != prev["size"]:
        return {
            "rule_id": "BAI-002",
            "rule_name": "Hash Changed, Size Changed",
            "severity": SEVERITY_HIGH,
            "description": (
                f"{ctx['relative_path']} content changed between scans (SHA-256 mismatch), "
                f"and size moved from {prev['size']} to {cur['size']} bytes. Confirm this "
                f"corresponds to an intentional rebuild before trusting this artifact."
            ),
            "hash_compare": _hash_compare_str(prev["sha256"], cur["sha256"]),
        }
    return None


def rule_file_removed(ctx):
    """BAI-003: A file present in the prior scan's snapshot is missing
    entirely from the current scan of the same build-output directory — an
    unexpected deletion that could break downstream consumers or indicate
    tampering with the release artifact set."""
    cur = ctx.get("current")
    prev = ctx.get("previous")
    if prev and not cur:
        return {
            "rule_id": "BAI-003",
            "rule_name": "Build Artifact Removed",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{ctx['relative_path']} was present in the previous scan's baseline "
                f"(sha256 {prev['sha256'][:12]}...) but is missing from this scan."
            ),
            "hash_compare": _hash_compare_str(prev["sha256"], None),
        }
    return None


def rule_file_added(ctx):
    """BAI-004: A new file appeared in the current scan that was not present
    in the prior snapshot of the same build-output directory — an unexpected
    addition, which could be a legitimate new artifact or an injected file
    (e.g. malware planted alongside legitimate build output)."""
    cur = ctx.get("current")
    prev = ctx.get("previous")
    if cur and not prev and not ctx.get("is_first_scan"):
        return {
            "rule_id": "BAI-004",
            "rule_name": "New Build Artifact Added",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{ctx['relative_path']} appeared in this scan but was not present in the "
                f"previous baseline (sha256 {cur['sha256'][:12]}...). Verify this addition "
                f"was intentional."
            ),
            "hash_compare": _hash_compare_str(None, cur["sha256"]),
        }
    return None


def rule_first_scan_baseline(ctx):
    """BAI-005: This is the FIRST scan ever recorded for this target path —
    no prior baseline exists to diff against, so this run establishes the
    real local baseline that future scans of the same path will be compared
    to. Informational only; not itself a sign of tampering."""
    if ctx.get("is_first_scan") and ctx.get("current"):
        cur = ctx["current"]
        return {
            "rule_id": "BAI-005",
            "rule_name": "Baseline Established",
            "severity": SEVERITY_LOW,
            "description": (
                f"{ctx['relative_path']} recorded into the new baseline for this target path "
                f"(sha256 {cur['sha256'][:12]}..., {cur['size']} bytes). No prior scan existed "
                f"to compare against."
            ),
            "hash_compare": _hash_compare_str(None, cur["sha256"]),
        }
    return None


def rule_suspicious_mtime_rollback(ctx):
    """BAI-006: A file's real modification time is EARLIER than the previous
    scan's recorded mtime for the same unchanged-hash file — a suspicious
    timestamp rollback. Attackers sometimes reset mtimes backward to make a
    tampered file look untouched or older than a legitimate rebuild."""
    cur = ctx.get("current")
    prev = ctx.get("previous")
    if not cur or not prev:
        return None
    if cur["sha256"] == prev["sha256"] and cur["mtime"] < prev["mtime"]:
        return {
            "rule_id": "BAI-006",
            "rule_name": "Suspicious Mtime Rollback",
            "severity": SEVERITY_LOW,
            "description": (
                f"{ctx['relative_path']} has an unchanged hash but its modification time "
                f"moved backward ({prev['mtime']} -> {cur['mtime']}), which can be used to "
                f"mask tampering or is otherwise unexpected."
            ),
            "hash_compare": _hash_compare_str(prev["sha256"], cur["sha256"]),
        }
    return None


ALL_RULES = [
    rule_hash_changed_same_size,
    rule_hash_changed_different_size,
    rule_file_removed,
    rule_file_added,
    rule_first_scan_baseline,
    rule_suspicious_mtime_rollback,
]
