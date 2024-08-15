#!/usr/bin/env python3

""" This method houses the security"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
import uuid


def _hash_password(password: str) -> bytes:
    """This method hashes a password"""
    salt = bcrypt.gensalt()
    byte_password = password.encode("utf-8")
    hashed_password = bcrypt.hashpw(salt=salt, password=byte_password)
    return hashed_password


def _generate_uuid() -> str:
    """Generates a new uuid"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers users"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {user.email} already exists")
        except (InvalidRequestError, NoResultFound):
            hashed_password = _hash_password(password)
            new_user = User(email=email, hashed_password=hashed_password)
            self._db._session.add(new_user)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Login Option"""
        try:
            user = self._db.find_user_by(email=email)
            hashed_password = user.hashed_password
            encoded_password = password.encode("utf-8")
            return bcrypt.checkpw(encoded_password, hashed_password)
        except (NoResultFound, InvalidRequestError):
            return False

    def create_session(self, email):
        """Creates a session id"""
        generated_id = _generate_uuid()
        user = self._db._session.query(User).filter_by(email=email).first()
        setattr(user, "session_id", generated_id)
        return generated_id
