#!/usr/bin/env python3
"""Module BasicAuth"""

import base64
import re
from typing import Optional, TypeVar
from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """
    BasicAuth class that inherits from Auth and implements Basic Authentication
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> Optional[str]:
        """
        Extract the Base64 part of the Authorization header for Basic Auth

        Args:
            authorization_header: Authorization header string

        Return:
            Optional: Base64 part of the Authorization header or None
        """
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field_match = re.fullmatch(pattern, authorization_header.strip())
            if field_match is not None:
                return field_match.group('token')
        return None

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> Optional[str]:
        """
        Decode the Base64 authorization header

        Args:
            base64_authorization_header: Base64 encoded string

        Returns:
            Optional: Decoded UTF-8 string or None
        """
        if base64_authorization_header is None or \
                not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded = base64.b64decode(
                base64_authorization_header).decode('utf-8')
            return decoded
        except Exception:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Extract user email and password from decoded Base64 header

        Args:
            decoded_base64_authorization_header: Decoded authorization header

        Returns:
            tuple: (email, password)
        """
        if decoded_base64_authorization_header is None or \
                not isinstance(decoded_base64_authorization_header, str):
            return None, None

        parts = decoded_base64_authorization_header.split(':', 1)

        if len(parts) != 2:
            return None, None

        return parts[0], parts[1]

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> Optional[TypeVar('User')]:
        """
        Get User object from email and password

        Args:
            user_email: User's email
            user_pwd: User's password

        Returns:
            Optional: User object or None
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({"email": user_email})

            if not users:
                return None

            for user in users:
                if user.is_valid_password(user_pwd):
                    return user

            return None

        except Exception:
            return None

    def current_user(self, request=None) -> Optional[TypeVar('User')]:
        """
        Retrieve User instance for a request

        Args:
            request: The incoming request object (optional)

        Returns:
            Optional: User object or None
        """
        auth_header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(auth_header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        email, pwd = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(email, pwd)
