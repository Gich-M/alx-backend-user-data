#!/usr/bin/env python3
"""Authentication system template."""

from flask import request
from typing import List, TypeVar


class Auth:
    """Authentication system."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determine if authentication is needed for a given path.
        Args:
            path: The path to check
            excluded_paths: Paths that don't require authentication
        Return:
            bool:
        """
        return False

    def authorization_header(self, request=None) -> str:
        """
        Validate the authorization header of the request

        Args:
            request: Flask request object (default: None)
        Return:
            str:
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Get the current user from the request

        Args:
            request: Flask request object (default: None)
        Return:
            User:
        """
        return None
