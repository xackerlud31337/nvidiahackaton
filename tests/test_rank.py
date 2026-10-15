from recontriage.triage.rank import _compact, label_items, rank_with_ultra

ITEMS = [
    {"type": "port", "host": "1.2.3.4", "port": 22, "proto": "tcp", "service": "ssh",
     "product": "OpenSSH", "version": "6.6.1p1", "extra": "", "source": "nmap"},
    {"type": "subdomain", "host": "old.example.com", "ip": "", "source": "crt.sh"},
    {"type": "path", "url": "http://x/.git/HEAD", "status": 200, "size": 23, "words": 2,
     "redirect": "", "source": "ffuf"},
    {"type": "port", "host": "1.2.3.4", "port": 80, "proto": "tcp", "service": "http",
     "product": "", "version": "", "extra": "", "source": "nmap"},
]


def test_label_items_ids_and_no_mutation():
    labelled = label_items(ITEMS)
    assert [i["id"] for i in labelled] == ["P1", "S1", "D1", "P2"]
    assert "id" not in ITEMS[0]


def test_compact_lines():
    labelled = label_items(ITEMS)
    assert _compact(labelled[0]) == "P1 port 1.2.3.4:22/tcp ssh OpenSSH 6.6.1p1"
    assert _compact(labelled[1]) == "S1 subdomain old.example.com -> DOES-NOT-RESOLVE"
    assert _compact(labelled[2]) == "D1 path http://x/.git/HEAD status=200 size=23"


class FakeClient:
    """Stands in for NemotronClient so we can test validation without the API."""
    def __init__(self, reply):
        self.reply = reply

    def chat_json(self, *a, **kw):
        return self.reply


def test_rank_drops_unknown_ids_and_normalises():
    labelled = label_items(ITEMS)
    fake = FakeClient({"findings": [
        {"rank": 2, "id": "P1", "severity": "HIGH", "title": "old ssh", "rationale": "r", "next_step": "n"},
        {"rank": 1, "id": "D1", "severity": "weird", "title": "git", "rationale": "r", "next_step": "n"},
        {"rank": 3, "id": "P99", "severity": "high", "title": "ghost", "rationale": "r", "next_step": "n"},
    ]})
    findings = rank_with_ultra(fake, "example.com", labelled, {})
    assert [f["id"] for f in findings] == ["D1", "P1"]       # sorted, ghost dropped
    assert [f["rank"] for f in findings] == [1, 2]
    assert findings[0]["severity"] == "info"                 # unknown -> info
    assert findings[1]["severity"] == "high"                 # lowercased
    assert findings[0]["item"]["url"] == "http://x/.git/HEAD"
