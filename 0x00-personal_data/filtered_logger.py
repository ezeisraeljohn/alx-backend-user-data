#!/usr/bin/env python3

import logging
import re
from typing import Union, List

""" This module encrypts a password using the sha256 algorithm. """


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """Function that returns the log message obfuscated"""
    for field in fields:
        for field in fields:
            message = re.sub(rf"(?<={field}=)[^{separator}]+", redaction, message)
    return message
