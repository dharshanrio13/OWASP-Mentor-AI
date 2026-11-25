"""API-level tests: upload handling, ZIP safety limits, sessions and database."""
from __future__ import annotations

import io
import uuid
import warnings
import zipfile

from conftest import make_zip, sample_ruleset, upload

from app import crud
from app.config import Settings
from app.services.zip_inspector import ZipLimits, ZipRejected, inspect_zip

import pytest

GOOD_PROJECT = {
    "src/app.js": "const x = 1;\neval(userInput);\n",
    "src/style.css": "body { color: red; }\n",
    "package.json": '{"name": "demo"}\n',
}


# ---------------------------------------------------------------- basics
def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_rules_are_13_disabled_placeholders(client):
    body = client.get("/api/rules").json()
    assert body["count"] == 13
    assert body["official_list_verified"] is False
    assert all(r["enabled"] is False for r in body["rules"])
    assert all(r["check_type"] == "manual" for r in body["rules"])
    assert {r["id"] for r in body["rules"]} == {f"OWASP-{i:02d}" for i in range(1, 14)}


def test_valid_zip_with_placeholder_rules_is_not_verified(client, session_id):
    response = upload(client, make_zip(GOOD_PROJECT), session_id, "DemoStore.zip")
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["filename"] == "DemoStore.zip"
    assert report["overall_status"] == "COMPLETED"
    assert report["counts"] == {"passed": 0, "failed": 0, "not_verified": 13}
    assert sum(report["counts"].values()) == 13
    assert all(f["status"] == "NOT_VERIFIED" for f in report["findings"])
    assert report["verification_complete"] is False
    assert report["official_rules_verified"] is False
    assert "not a complete security audit" in report["disclaimer"]
    uuid.UUID(report["scan_id"])


# ------------------------------------------------------------ session id
def test_missing_session_header_rejected(client):
    response = client.post("/api/scans/upload", files={"file": ("a.zip", make_zip(GOOD_PROJECT))})
    assert response.status_code == 400


@pytest.mark.parametrize("bad", ["not-a-uuid", "12345", "../../etc/passwd", "{" + str(uuid.uuid4()) + "}", uuid.uuid4().hex])
def test_invalid_session_header_rejected(client, bad):
    response = upload(client, make_zip(GOOD_PROJECT), bad)
    assert response.status_code == 400


# -------------------------------------------------------- invalid uploads
def test_non_zip_extension_rejected(client, session_id):
    response = upload(client, b"hello", session_id, "notes.txt")
    assert response.status_code == 400


def test_text_file_named_zip_rejected(client, session_id):
    response = upload(client, b"this is definitely not a zip file", session_id, "fake.zip")
    assert response.status_code == 400


def test_empty_upload_rejected(client, session_id):
    assert upload(client, b"", session_id).status_code == 400


def test_missing_file_field_rejected(client, session_id):
    response = client.post("/api/scans/upload", headers={"X-Session-ID": session_id})
    assert response.status_code == 422
    assert "Traceback" not in response.text


def test_oversized_upload_rejected(client, session_id):
    big = b"PK\x03\x04" + b"0" * (10 * 1024 * 1024 + 1)
    response = upload(client, big, session_id)
    assert response.status_code == 413


def test_malformed_zip_rejected(client, session_id):
    data = make_zip(GOOD_PROJECT)
    broken = data[: len(data) // 2]
    response = upload(client, broken, session_id)
    assert response.status_code == 400
    assert "malformed" in response.json()["detail"].lower() or "not a valid" in response.json()["detail"].lower()


def test_corrupted_member_data_rejected(client, session_id):
    data = bytearray(make_zip({"a.js": "console.log('hello world, hello world');" * 20}))
    data[40] ^= 0xFF  # flip a byte inside the compressed stream
    response = upload(client, bytes(data), session_id)
    assert response.status_code in (400, 422)


# ------------------------------------------------------- unsafe archives
@pytest.mark.parametrize("name", ["../evil.js", "src/../../evil.js", "/etc/cron.d/evil.js", "C:/Windows/evil.js", "..\\evil.js"])
def test_path_traversal_and_absolute_paths_rejected(client, session_id, name):
    response = upload(client, make_zip({name: "x", "ok.js": "1"}), session_id)
    assert response.status_code == 422, name
    assert "evil" not in response.text  # the hostile name is not echoed back


def test_symlink_rejected(client, session_id):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("link.js")
        info.create_system = 3
        info.external_attr = (0o120777) << 16
        archive.writestr(info, "/etc/passwd")
    response = upload(client, buffer.getvalue(), session_id)
    assert response.status_code == 422
    assert "symbolic" in response.json()["detail"].lower()


def test_duplicate_filenames_rejected(client, session_id):
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.js", "1")
            archive.writestr("a.js", "2")
    response = upload(client, buffer.getvalue(), session_id)
    assert response.status_code == 422
    assert "duplicate" in response.json()["detail"].lower()


def test_excessive_entries_rejected(client, session_id):
    files = {f"f{i}.js": "1" for i in range(301)}
    response = upload(client, make_zip(files), session_id)
    assert response.status_code == 422
    assert "300" in response.json()["detail"]


def test_excessive_uncompressed_size_rejected(client, session_id):
    # 12 x 1.9 MB of zeros compresses tiny, so the size/ratio guards must trip.
    files = {f"big{i}.js": "0" * 1_900_000 for i in range(12)}
    response = upload(client, make_zip(files), session_id)
    assert response.status_code == 422


def test_file_over_2mb_rejected(client, session_id):
    response = upload(client, make_zip({"big.js": "a" * (2 * 1024 * 1024 + 10)}), session_id)
    assert response.status_code == 422


def test_executable_binary_rejected(client, session_id):
    response = upload(client, make_zip({"app.js": "1", "setup.exe": b"MZ\x90\x00"}), session_id)
    assert response.status_code == 422
    assert "binary" in response.json()["detail"].lower()


def test_binary_disguised_as_source_rejected(client, session_id):
    response = upload(client, make_zip({"app.js": "1", "fake.js": b"\x00\x01\x02binary"}), session_id)
    assert response.status_code == 422


def test_nested_zip_rejected(client, session_id):
    inner = make_zip({"a.js": "1"})
    response = upload(client, make_zip({"app.js": "1", "inner.zip": inner}), session_id)
    assert response.status_code == 422


def test_unsupported_but_harmless_files_are_skipped(client, session_id):
    files = {"app.js": "1", "logo.png": b"\x89PNG\r\n\x1a\n", "README.md": "# hi", "node_modules/x/index.js": "1"}
    response = upload(client, make_zip(files), session_id)
    assert response.status_code == 200
    stats = response.json()["stats"]
    assert stats["files_scanned"] == 1
    assert stats["files_skipped"] == 3


def test_excluded_folder_binaries_are_ignored(client, session_id):
    files = {"app.js": "1", "node_modules/pkg/native.node": b"\x7fELF\x00\x00"}
    assert upload(client, make_zip(files), session_id).status_code == 200


def test_zip_without_supported_files_rejected(client, session_id):
    assert upload(client, make_zip({"README.md": "hi"}), session_id).status_code == 422


def test_invalid_utf8_is_decoded_safely(client, session_id):
    response = upload(client, make_zip({"app.js": b"var x = '\xff\xfe\xfa';\n"}), session_id)
    assert response.status_code == 200


# --------------------------------------------- inspector limits (unit level)
def _limits(**overrides) -> ZipLimits:
    return ZipLimits.from_settings(Settings(**overrides))


def test_total_uncompressed_limit_unit():
    limits = _limits(max_total_uncompressed=1000, max_compression_ratio=10**9)
    with pytest.raises(ZipRejected) as exc:
        inspect_zip(make_zip({"a.js": "x" * 600, "b.js": "y" * 600}), limits)
    assert exc.value.status_code == 422
    assert "uncompressed" in exc.value.message


def test_compression_ratio_limit_unit():
    limits = _limits(max_compression_ratio=20)
    with pytest.raises(ZipRejected) as exc:
        inspect_zip(make_zip({"a.js": "0" * 500_000}), limits)
    assert "compression" in exc.value.message


def test_text_budget_truncates_source():
    limits = _limits(max_text_chars=100)
    result = inspect_zip(make_zip({"a.js": "a" * 80, "b.js": "b" * 80, "c.js": "c" * 80}), limits)
    assert result.truncated is True
    assert sum(len(f.text) for f in result.files) <= 100


# ------------------------------------------- session isolation + database
def test_session_isolation_and_history(make_client):
    client = make_client(ruleset=sample_ruleset())
    session_a, session_b = str(uuid.uuid4()), str(uuid.uuid4())

    report = upload(client, make_zip(GOOD_PROJECT), session_a, "A.zip").json()
    scan_id = report["scan_id"]

    own = client.get(f"/api/scans/{scan_id}", headers={"X-Session-ID": session_a})
    assert own.status_code == 200
    assert own.json()["scan_id"] == scan_id
    assert own.json()["counts"] == report["counts"]

    other = client.get(f"/api/scans/{scan_id}", headers={"X-Session-ID": session_b})
    assert other.status_code == 404

    history_a = client.get("/api/scans", headers={"X-Session-ID": session_a}).json()
    history_b = client.get("/api/scans", headers={"X-Session-ID": session_b}).json()
    assert [s["scan_id"] for s in history_a] == [scan_id]
    assert history_a[0]["filename"] == "A.zip"
    assert history_b == []


def test_unknown_or_malformed_scan_id_is_404(client, session_id):
    headers = {"X-Session-ID": session_id}
    assert client.get(f"/api/scans/{uuid.uuid4()}", headers=headers).status_code == 404
    assert client.get("/api/scans/not-a-uuid", headers=headers).status_code == 404


def test_history_requires_session_header(client):
    assert client.get("/api/scans").status_code == 400


def test_database_integration_uses_real_crud(make_client, db_session_factory, session_id):
    client = make_client(ruleset=sample_ruleset())
    scan_id = upload(client, make_zip(GOOD_PROJECT), session_id).json()["scan_id"]

    db = db_session_factory()
    try:
        row = crud.get_scan(db, scan_id, session_id)
        assert row is not None
        assert crud.get_scan(db, scan_id, str(uuid.uuid4())) is None
        assert len(crud.list_scans(db, session_id, limit=20)) == 1
    finally:
        db.close()


def test_database_failure_returns_safe_500(make_client, monkeypatch, session_id):
    from app.routers import scans as scans_module

    def boom(*args, **kwargs):
        raise RuntimeError("secret internal path /home/x/db.sqlite")

    monkeypatch.setattr(scans_module, "create_scan", boom)
    client = make_client(ruleset=sample_ruleset())
    response = upload(client, make_zip(GOOD_PROJECT), session_id)
    assert response.status_code == 500
    assert "secret" not in response.text and "/home" not in response.text


def test_upload_rate_limit(make_client, session_id):
    client = make_client(app_settings=Settings(ai_enabled=False, rate_limit_uploads=2))
    data = make_zip(GOOD_PROJECT)
    assert upload(client, data, session_id).status_code == 200
    assert upload(client, data, session_id).status_code == 200
    blocked = upload(client, data, session_id)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_cors_only_allows_frontend_origin(client):
    ok = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in bad.headers


def test_ai_status_endpoint_never_crashes(client):
    body = client.get("/api/ai/status").json()
    assert body["available"] is False
    assert set(body) >= {"provider", "model", "available"}
