import os
import shutil
import tempfile
import time


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir = tempfile.mkdtemp()
    try:
        target_file = os.path.join(tmpdir, "artifact.bin")
        with open(target_file, "wb") as f:
            f.write(b"A" * 32)

        # First real scan: no baseline yet -> establishes it (BAI-005).
        resp = registered_client.post("/scan/run", data={"target_path": tmpdir}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Real, on-disk content change between scans (same size -> BAI-001).
        time.sleep(0.05)
        with open(target_file, "wb") as f:
            f.write(b"Z" * 32)

        # Second real scan of the SAME target_path -> should diff against the first.
        resp = registered_client.post("/scan/run", data={"target_path": tmpdir}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan of this real path.
        resp = registered_client.get("/logs")
        assert tmpdir.encode() in resp.data

        # Alerts page should load and now contain a real change-related alert
        # (BAI-001 hash-changed-same-size is critical, above the default "medium" threshold).
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200
        assert b"BAI-001" in resp.data

        # Analytics JSON endpoint returns real aggregated data.
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works.
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
