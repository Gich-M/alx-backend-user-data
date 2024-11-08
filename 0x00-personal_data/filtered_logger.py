#!/usr/bin/env python3
"""Module filtered-logger."""

import re


def filter_datum(fields, redaction, message, separator):
    """Returns the log message obfuscated."""
    pattern = f"({'|'.join(fields)})=[^{separator}]*"
    return re.sub(
        pattern,
        lambda match: f"{
            match.group(1)}={redaction}",
        message)
