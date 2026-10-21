from recontriage.scope import load_scope
from recontriage.triage import verify


def _scope(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("example.com\n*.example.com\n10.0.0.0/24\n")
    return load_scope(f)


ITEMS = {
    "D1": {"id": "D1", "type": "path", "url": "http://api.example.com/admin", "host": ""},
    "P1": {"id": "P1", "type": "port", "host": "10.0.0.5", "port": 443},
    "X1": {"id": "X1", "type": "path", "url": "http://evil.net/admin", "host": ""},
}


def test_unknown_check_type_rejected(tmp_path):
    r = verify.run_check({"type": "rm_rf", "id": "D1"}, ITEMS, _scope(tmp_path))
    assert "error" in r and "unknown check type" in r["error"]


def test_unknown_id_rejected(tmp_path):
    r = verify.run_check({"type": "dns", "id": "ZZ"}, ITEMS, _scope(tmp_path))
    assert "error" in r and "unknown item id" in r["error"]


def test_out_of_scope_host_refused(tmp_path):
    # X1 points at evil.net, which is NOT in scope -> must be refused even though
    # it is a valid item id and a valid check type.
    r = verify.run_check({"type": "http_head", "id": "X1"}, ITEMS, _scope(tmp_path))
    assert "error" in r and "not in scope" in r["error"]


def test_check_types_are_all_read_only():
    # Guard against someone adding a mutating verb to the menu later.
    for t in verify.CHECK_TYPES:
        assert t in {"http_head", "http_title", "tls_cert", "dns"}
