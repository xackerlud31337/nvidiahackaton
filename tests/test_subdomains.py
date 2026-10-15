from recontriage.recon.subdomains import parse_crtsh

CRTSH_SAMPLE = [
    {"name_value": "www.example.com\nexample.com"},
    {"name_value": "*.example.com"},                 # wildcard -> example.com
    {"name_value": "API.Example.com"},               # case folded
    {"name_value": "www.example.com"},               # duplicate
    {"name_value": "example.com.evil.net"},          # must be dropped
    {"name_value": "notexample.com"},                # must be dropped
]


def test_parse_crtsh_dedup_filter_sort():
    assert parse_crtsh(CRTSH_SAMPLE, "example.com") == [
        "api.example.com",
        "example.com",
        "www.example.com",
    ]


def test_parse_crtsh_empty():
    assert parse_crtsh([], "example.com") == []
