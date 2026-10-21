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


class _RepairClient:
    """Exercise chat_json's self-repair path without the network."""
    from recontriage.triage.client import NemotronClient as _N
    chat_json = _N.chat_json          # borrow the real method

    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts = []

    def chat(self, model, system, user, **kw):
        self.prompts.append(user)
        return self.replies.pop(0)


def test_chat_json_repairs_once():
    c = _RepairClient(["Sorry, here it is: findings = none", '{"findings": []}'])
    assert c.chat_json("m", "s", "u") == {"findings": []}
    assert len(c.prompts) == 2
    assert "could not be parsed" in c.prompts[1]


def test_chat_json_gives_up_after_retry():
    c = _RepairClient(["nope", "still nope"])
    with pytest.raises(ValueError):
        c.chat_json("m", "s", "u")
