#!/usr/bin/env python3

""" This module houses the different auth methods"""


from flask import Flask
from typing import List, TypeVar
from models.user import User


User = TypeVar("User")


class Auth:
    """The auth class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """The require_auth method"""
        if not path:
            return True
        if not excluded_paths:
            return True
        if f"{path}/" in excluded_paths:
            return False
        if path not in excluded_paths:
            return True
        if path in excluded_paths:
            return False

    def authorization_header(self, request=None) -> str:
        """The authorization_header method"""
        if request.headers is None:
            return None
        else:
            return request.headers.get(
                "Authorization",
            )

    def current_user(self, request=None) -> User:
        """The current_user"""
        return None
