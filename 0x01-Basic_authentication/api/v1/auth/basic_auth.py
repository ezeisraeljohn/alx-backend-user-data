#!/usr/bin/env python3

""" This module contains the basic auth class"""


from .auth import Auth


class BasicAuth(Auth):
    """This inherits from Auth"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """Extracts the basic auth token"""
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header:
            return None

        authorization_header_split = authorization_header.split(" ")
        if authorization_header_split[0] + " " != "Basic ":
            return None
        else:
            return authorization_header_split[1]
