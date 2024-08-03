#!/usr/bin/env python3

import re

""" This module encrypts a password using the sha256 algorithm. """


def filter_datum(fields, redaction, message, separator):
    """Function that returns the log message obfuscated"""
    for field in fields:
        pattern = rf"(?<={field}=)[^{separator}]+"
        message = re.sub(pattern, redaction, message)
    return message
