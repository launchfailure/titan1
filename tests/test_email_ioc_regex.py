"""Regression test for the email IOC / redaction regex TLD character class.

The TLD class was written [A-Z|a-z], which includes a literal '|' inside the
character class ('|' is not alternation inside [...]). That matched bogus TLDs
containing a pipe. The intent is letters only: [A-Za-z].
"""

from titan_decoder.utils.helpers import extract_iocs


def test_real_emails_still_extracted():
    iocs = extract_iocs("reach me at real.user@corp.example.com or ops@sub.domain.io")
    assert "real.user@corp.example.com" in iocs["emails"]
    assert "ops@sub.domain.io" in iocs["emails"]


def test_pipe_not_accepted_in_tld():
    iocs = extract_iocs("junk a@b.co|m and x@y.z|z endjunk")
    # No extracted email may contain a pipe character.
    assert all("|" not in e for e in iocs["emails"])
    # The match stops at the valid letter run before the pipe.
    assert "a@b.co" in iocs["emails"]


def test_secure_logging_pattern_has_no_pipe_in_class():
    from titan_decoder.core.secure_logging import PIIRedactor

    assert "[A-Z|a-z]" not in PIIRedactor.EMAIL_PATTERN.pattern
    # And redaction still works on a real email.
    assert "[EMAIL_REDACTED]" in PIIRedactor.redact("hi user@example.com bye")
