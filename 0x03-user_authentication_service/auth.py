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

    def create_session(self, email: str) -> uuid:
        """Creates a session id"""
        generated_id = _generate_uuid()
        try:
            user = self._db.find_user_by(email=email)
            setattr(user, "session_id", generated_id)
            return generated_id
        except (NoResultFound, InvalidRequestError):
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """Gets a user based on its session id"""
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except (NoResultFound, InvalidRequestError):
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session"""
        try:
            user = self._db.find_user_by(id=user_id)
            setattr(user, "session_id", None)
            return None
        except (NoResultFound, InvalidRequestError):
            return None
