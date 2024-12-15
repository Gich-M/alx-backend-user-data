#!/usr/bin/env python3
"""Modules SessionAuth."""
from uuid import uuid4
from .auth import Auth

from models.user import User


class SessionAuth(Auth):
    """Session authentication class.
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates a Session ID for a `user_id`."""
        if isinstance(user_id, str):
            session_id = str(uuid4())
            self.user_id_by_session_id[session_id] = user_id
            return session_id
        return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieves the `user_id` associated with a `session_id`."""
        if isinstance(session_id, str):
            return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Retrieves a user by based on `session_id`."""
        session_id = self.session_cookie(request)
        user_id = None
        if session_id is not None:
            user_id = self.user_id_for_session_id(session_id)

        if user_id is not None:
            return User.get(user_id)
        return None

    def destroy_session(self, request=None):
        """Destroys an authenticated session.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if (request is None or session_id is None) or user_id is None:
            return False
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
        return True
