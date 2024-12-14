#!/usr/bin/env python3
"""Authentication system template."""

import re
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
            bool:True if authentication is required, False otherwise
        """
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Validate the authorization header of the request

        Args:
            request: Flask request object (default: None)
        Return:
            str: Authorization header value or None
        """
        if request is not None:
            return request.headers.get('Authorization', None)
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
