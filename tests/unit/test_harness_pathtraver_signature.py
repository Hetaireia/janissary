"""M83 Stage 1: signature function tests.

Covers criterion 5 (signature determinism, UUID masking) and part of
criterion 11 (evidence hash).
"""

import hashlib

from janissary.harness.pathtraver import (
    BODY_STORE_LIMIT,
    _evidence_hash,
    _sanitize_case_id,
    _structural_signature,
)


def test_body_store_limit_constant_is_4096():
    assert BODY_STORE_LIMIT == 4096


def test_evidence_hash_is_sha256_of_utf8():
    body = "hello world"
    expected = hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert _evidence_hash(body) == expected


def test_evidence_hash_empty_body():
    assert _evidence_hash("") == hashlib.sha256(b"").hexdigest()


def test_evidence_hash_unicode_body():
    body = "unicode: \u00e9\u00e8\u00ea"
    expected = hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert _evidence_hash(body) == expected


def test_structural_signature_deterministic():
    body = "same content"
    assert _structural_signature(body, "text/plain") == _structural_signature(
        body, "text/plain"
    )


def test_structural_signature_differs_from_evidence_hash():
    body = "Hello    World"
    assert _evidence_hash(body) != _structural_signature(body, "text/plain")


def test_structural_signature_whitespace_normalized():
    body1 = "a    b\n\nc"
    body2 = "a b c"
    assert _structural_signature(body1, "text/plain") == _structural_signature(
        body2, "text/plain"
    )


def test_uuid_v4_masked_makes_signatures_equal():
    body1 = '<div data-id="550e8400-e29b-41d4-a716-446655440000">x</div>'
    body2 = '<div data-id="f47ac10b-58cc-41d4-b716-446655440099">x</div>'
    assert _structural_signature(body1, "text/plain") == _structural_signature(
        body2, "text/plain"
    )


def test_non_v4_uuid_not_masked():
    body1 = "id f47ac10b-58cc-11d4-a716-446655440000 end"
    body2 = "id f47ac10b-58cc-11d4-a716-446655440099 end"
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_uuid_boundary_requires_non_hex_neighbours():
    # Lookbehind (?<![0-9a-f]) blocks matching when the preceding
    # character is a hex digit. So a UUID-adjacent-to-hex is NOT masked.
    body1 = "a550e8400-e29b-41d4-a716-446655440000a"
    body2 = "a550e8400-e29b-41d4-a716-446655440001a"
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_uuid_embedded_in_hex_token_not_masked():
    # A UUID preceded by many hex digits is treated as part of a hex
    # string, not a standalone UUID.
    body1 = "deadbeef550e8400-e29b-41d4-a716-446655440000"
    body2 = "deadbeef550e8400-e29b-41d4-a716-446655440001"
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_hex_token_masked():
    body1 = "value " + ("a" * 32) + " end"
    body2 = "value " + ("b" * 32) + " end"
    assert _structural_signature(body1, "text/plain") == _structural_signature(
        body2, "text/plain"
    )


def test_hex_token_short_not_masked():
    body1 = "value " + ("a" * 16) + " end"
    body2 = "value " + ("b" * 16) + " end"
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_b64_with_csrf_marker_masked():
    body1 = 'csrf="' + ("X" * 30) + '"'
    body2 = 'csrf="' + ("Y" * 30) + '"'
    assert _structural_signature(body1, "text/plain") == _structural_signature(
        body2, "text/plain"
    )


def test_b64_with_token_marker_masked():
    body1 = 'token="' + ("X" * 30) + '"'
    body2 = 'token="' + ("Y" * 30) + '"'
    assert _structural_signature(body1, "text/plain") == _structural_signature(
        body2, "text/plain"
    )


def test_b64_without_known_marker_not_masked():
    body1 = 'xyz="' + ("X" * 30) + '"'
    body2 = 'xyz="' + ("Y" * 30) + '"'
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_html_content_type_strips_tags():
    body1 = "<html><body><p>A</p></body></html>"
    body2 = "<html><body><p>B</p></body></html>"
    assert _structural_signature(body1, "text/html") != _structural_signature(
        body2, "text/html"
    )


def test_html_content_type_ignores_tag_structure():
    body1 = "<html><body><p>Same text</p></body></html>"
    body2 = "<div><span>Same text</span></div>"
    assert _structural_signature(body1, "text/html") == _structural_signature(
        body2, "text/html"
    )


def test_non_html_content_type_keeps_tags():
    body1 = "<p>A</p>"
    body2 = "<p>B</p>"
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_sanitize_case_id_preserves_safe_chars():
    assert _sanitize_case_id("BenchmarkTest00028") == "BenchmarkTest00028"
    assert _sanitize_case_id("abc-DEF_123") == "abc-DEF_123"


def test_sanitize_case_id_replaces_unsafe():
    assert _sanitize_case_id("path/to?file") == "path_to_file"


def test_sanitize_case_id_empty_becomes_underscore():
    assert _sanitize_case_id("") == "_"


def test_sanitize_case_id_short_stays_short():
    assert len(_sanitize_case_id("short")) == 5


def test_sanitize_case_id_long_truncated_with_hash():
    long_name = "a" * 100
    result = _sanitize_case_id(long_name)
    assert len(result) == 64
    assert result[:55] == "a" * 55
    assert result[55] == "_"
    assert len(result[56:]) == 8


def test_uuid_preceded_by_letter_not_masked():
    body1 = "x550e8400-e29b-41d4-a716-446655440000"
    body2 = "x550e8400-e29b-41d4-a716-446655440001"
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_uuid_preceded_by_underscore_not_masked():
    body1 = "_550e8400-e29b-41d4-a716-446655440000"
    body2 = "_550e8400-e29b-41d4-a716-446655440001"
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_uuid_preceded_by_punctuation_masked():
    body1 = "[550e8400-e29b-41d4-a716-446655440000]"
    body2 = "[550e8400-e29b-41d4-a716-446655440099]"
    assert _structural_signature(body1, "text/plain") == _structural_signature(
        body2, "text/plain"
    )


def test_hex_token_embedded_in_longer_identifier_not_masked():
    body1 = "abc" + ("a" * 32) + "xyz"
    body2 = "abc" + ("b" * 32) + "xyz"
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_b64_marker_preceded_by_letter_not_masked():
    body1 = 'userid="' + ("X" * 30) + '"'
    body2 = 'userid="' + ("Y" * 30) + '"'
    assert _structural_signature(body1, "text/plain") != _structural_signature(
        body2, "text/plain"
    )


def test_b64_marker_standalone_masked():
    body1 = ' id="' + ("X" * 30) + '"'
    body2 = ' id="' + ("Y" * 30) + '"'
    assert _structural_signature(body1, "text/plain") == _structural_signature(
        body2, "text/plain"
    )


def test_html_fallback_when_selectolax_unavailable(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "selectolax", None)
    monkeypatch.setitem(sys.modules, "selectolax.parser", None)

    sig = _structural_signature("<p>Hello World</p>", "text/html")
    assert isinstance(sig, str) and len(sig) == 64

    sig2 = _structural_signature("<div>Hello World</div>", "text/html")
    assert sig == sig2


def test_html_post_extraction_whitespace_normalized():
    body1 = "<p>Same   text</p>"
    body2 = "<p>Same text</p>"
    assert _structural_signature(body1, "text/html") == _structural_signature(
        body2, "text/html"
    )


def test_html_equivalent_visible_text_same_signature():
    body1 = "<p>Same text</p>"
    body2 = "<div>Same text</div>"
    assert _structural_signature(body1, "text/html") == _structural_signature(
        body2, "text/html"
    )


def test_b64_data_id_counts_as_id_marker():
    # data- prefix: hyphen is a permitted left boundary for the id= marker.
    # This is a deliberate choice; see Gate D.1 design discussion.
    body1 = '<div data-id="' + ("X" * 30) + '">'
    body2 = '<div data-id="' + ("Y" * 30) + '">'
    assert _structural_signature(body1, "text/plain") == _structural_signature(
        body2, "text/plain"
    )
