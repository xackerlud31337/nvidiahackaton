import pytest

from recontriage.scope import OutOfScopeError, assert_in_scope, load_scope, normalize_target

SCOPE_TEXT = """
# comment line
example.com
*.example.com
10.10.11.0/24
192.168.1.50
"""


@pytest.fixture
def scope(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text(SCOPE_TEXT)
    return load_scope(f)


# --- things that must be allowed -------------------------------------------
@pytest.mark.parametrize("target", [
    "example.com",                       # exact host
    "EXAMPLE.COM",                       # case insensitive
    "example.com.",                      # trailing dot (DNS style)
    "api.example.com",                   # wildcard subdomain
    "a.b.example.com",                   # deep wildcard subdomain
    "https://api.example.com:8080/login",# URL with scheme, port, path
    "api.example.com:443",               # host:port without scheme
    "10.10.11.7",                        # inside CIDR
    "192.168.1.50",                      # single IP entry
])
def test_allowed(scope, target):
    assert scope.allows(target)
    assert_in_scope(target, scope)       # must not raise


# --- things that must be blocked -------------------------------------------
@pytest.mark.parametrize("target", [
    "google.com",                        # unrelated host
    "evil-example.com",                  # classic endswith bug
    "example.com.evil.net",              # prefix trick
    "10.10.12.1",                        # outside CIDR
    "192.168.1.51",                      # neighbour of single IP
    "",                                  # empty
    "   ",                               # whitespace
])
def test_blocked(scope, target):
    assert not scope.allows(target)
    with pytest.raises(OutOfScopeError):
        assert_in_scope(target, scope)


def test_normalize_target():
    assert normalize_target("HTTPS://Api.Example.com:8080/login") == "api.example.com"
    assert normalize_target("example.com.") == "example.com"
    assert normalize_target("host:8080") == "host"


def test_error_message_names_target(scope):
    with pytest.raises(OutOfScopeError) as exc:
        assert_in_scope("google.com", scope)
    assert "google.com" in str(exc.value)
