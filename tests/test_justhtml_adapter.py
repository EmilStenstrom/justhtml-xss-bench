import pytest

from xssbench.sanitizers import available_sanitizers


def _get_justhtml_sanitizer_or_skip():
    sanitizers = available_sanitizers()
    s = sanitizers.get("justhtml")
    if s is None:
        pytest.skip("justhtml is not installed")
    return s


def test_justhtml_resolves_protocol_relative_href():
    s = _get_justhtml_sanitizer_or_skip()
    out = s.sanitize('<a href="//example.com/path">x</a>')

    assert 'href="https://example.com/path"' in out
    assert 'href="//example.com/path"' not in out


def test_justhtml_strips_javascript_href():
    s = _get_justhtml_sanitizer_or_skip()
    out = s.sanitize('<a href="javascript:alert(1)">x</a>')

    assert "javascript:" not in out.lower()


def test_justhtml_keeps_absolute_img_src():
    s = _get_justhtml_sanitizer_or_skip()

    url = "https://example.com/x.png"
    out = s.sanitize(f'<img src="{url}">')

    assert "/img-proxy?" not in out
    assert f'src="{url}"' in out


def test_justhtml_resolves_protocol_relative_img_src():
    s = _get_justhtml_sanitizer_or_skip()

    url = "//example.com/x.png"
    resolved = "https://example.com/x.png"
    out = s.sanitize(f'<img src="{url}">')

    assert "/img-proxy?" not in out
    assert f'src="{resolved}"' in out
    assert f'src="{url}"' not in out
