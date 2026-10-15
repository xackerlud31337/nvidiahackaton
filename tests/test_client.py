import pytest

from recontriage.triage.client import NANO, ULTRA, Usage, extract_json


def test_extract_plain():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_extract_fenced():
    text = 'Sure, here you go:\n```json\n{"findings": []}\n```\nAnything else?'
    assert extract_json(text) == {"findings": []}


def test_extract_with_prose_around():
    text = 'Ranking below.\n\n[{"id": "P1"}, {"id": "P2"}]\n\nHope this helps.'
    assert extract_json(text) == [{"id": "P1"}, {"id": "P2"}]


def test_extract_nested_braces_inside_strings():
    text = 'x {"title": "a } b", "n": {"k": [1,2]}} y'
    assert extract_json(text) == {"title": "a } b", "n": {"k": [1, 2]}}


def test_extract_fails_loudly():
    with pytest.raises(ValueError):
        extract_json("I cannot help with that.")


def test_usage_cost():
    u = Usage()
    u.add(NANO, 1_000_000, 0)     # $0.06
    u.add(ULTRA, 0, 1_000_000)    # $3.00
    assert abs(u.cost_usd() - 3.06) < 1e-9
    assert "estimated cost" in u.summary()
