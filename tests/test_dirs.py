import json

from recontriage.recon.dirs import parse_ffuf_json

FFUF_SAMPLE = {
    "commandline": "ffuf ...",
    "results": [
        {"input": {"FUZZ": "admin"}, "status": 301, "length": 312, "words": 20,
         "url": "http://h/admin", "redirectlocation": "http://h/admin/"},
        {"input": {"FUZZ": ".git/HEAD"}, "status": 200, "length": 23, "words": 2,
         "url": "http://h/.git/HEAD", "redirectlocation": ""},
    ],
}


def test_parse_ffuf_json():
    hits = parse_ffuf_json(json.dumps(FFUF_SAMPLE))
    assert [h["status"] for h in hits] == [200, 301]        # sorted by status
    assert hits[0] == {
        "type": "path", "url": "http://h/.git/HEAD", "status": 200, "size": 23,
        "words": 2, "redirect": "", "source": "ffuf",
    }
    assert hits[1]["redirect"] == "http://h/admin/"


def test_parse_ffuf_no_results():
    assert parse_ffuf_json('{"results": []}') == []
