import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evals"))
from run_evals import _matches  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "evals" / "fixtures"


def test_all_fixtures_have_a_matching_item():
    """Every fixture's expected answer must actually exist in its items, or the
    eval is unwinnable. This catches typos in the fixture files."""
    for path in FIXTURES.glob("*.json"):
        fx = json.loads(path.read_text())
        fake_findings = [{"item": it} for it in fx["items"]]
        assert any(_matches(f, fx["expect_top_type"], fx["expect_top_match"]) for f in fake_findings), \
            f"{fx['name']}: no item matches the expected answer"


def test_matcher_rejects_wrong_type():
    assert not _matches({"item": {"type": "port"}}, "path", ".git")
