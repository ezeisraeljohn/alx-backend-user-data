#!/usr/bin/env python3

""" This module contains the basic auth class"""


from .auth import Auth
import base64
from typing import Tuple, TypeVar
from models.user import User


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

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """Decodes the base64 string"""
        if not isinstance(base64_authorization_header, str):
            return None
        if not base64_authorization_header:
            return None
        try:
            decoded_byte = base64.b64decode(base64_authorization_header)
            decode_str = decoded_byte.decode("utf-8")
            return decode_str
        except:
            return None

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> Tuple[str, str]:
        """Extracts user credentials"""
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if not decoded_base64_authorization_header:
            return (None, None)
        if ":" not in decoded_base64_authorization_header:
            return (None, None)
        email, password = decoded_base64_authorization_header.split(":")
        return (email, password)

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """get user object from credentials"""
        if not isinstance(user_email, str) or not user_email:
            return None
        if not isinstance(user_pwd, str) or not user_pwd:
            return None
        user_list = User.search({"email": user_email})
        if not user_list:
            return None
        if not user_list[0].is_valid_password(user_pwd):
            return None
        return user_list[0]
