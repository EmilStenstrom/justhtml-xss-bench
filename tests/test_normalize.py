from __future__ import annotations

from xssbench.normalize import normalize_payload


def test_normalize_whitespace_and_newlines() -> None:
    a = "\n  <img   src=x\r\n onerror=alert(1) >  \n"
    b = "<img src=x onerror=alert(1)>"
    assert normalize_payload(a) == normalize_payload(b)


def test_normalize_tag_and_attr_casing() -> None:
    a = "<IMG SRC=x oNeRrOr=alert(1)>"
    b = "<img src=x onerror=alert(1)>"
    assert normalize_payload(a) == normalize_payload(b)


def test_normalize_attribute_ordering() -> None:
    a = "<img onerror=alert(1) src=x>"
    b = "<img src=x onerror=alert(1)>"
    assert normalize_payload(a) == normalize_payload(b)


def test_normalize_quotes_and_entities_in_attributes() -> None:
    a = "<img src='x' onerror='alert(1)'>"
    b = '<img onerror="alert(1)" src="x">'
    assert normalize_payload(a) == normalize_payload(b)


def test_normalize_url_scheme_case_only() -> None:
    a = '<a href="JaVaScRiPt:alert(1)">x</a>'
    b = '<a href="javascript:alert(1)">x</a>'
    assert normalize_payload(a) == normalize_payload(b)


def test_script_content_whitespace_outside_quotes_collapsed() -> None:
    a = "<script> alert( 1 ) </script>"
    b = "<script>alert(1)</script>"
    assert normalize_payload(a) == normalize_payload(b)


def test_script_content_preserves_whitespace_inside_quotes() -> None:
    a = "<script>var x='a  b';</script>"
    b = "<script>var x='a  b';</script>"
    assert normalize_payload(a) == normalize_payload(b)
    c = "<script>var x='a b';</script>"
    assert normalize_payload(a) != normalize_payload(c)


def test_malformed_tag_like_input_does_not_hang() -> None:
    # Previously, a stray '<' that wasn't parseable as a tag could cause an
    # infinite loop in normalize_payload().
    s = '<<SCRIPT>alert("XSS");//\\<</SCRIPT>'
    out = normalize_payload(s)
    assert isinstance(out, str)
    assert len(out) > 0
