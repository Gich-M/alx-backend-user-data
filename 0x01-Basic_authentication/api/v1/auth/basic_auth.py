#!/usr/bin/env python3
"""Module BasicAuth"""

import base64
import binascii
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
        """
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field_match = re.fullmatch(
                pattern,
                authorization_header.strip(),
            )
            if field_match is not None:
                return field_match.group('token')
        return None

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> Optional[str]:
        """
        Decode the Base64 authorization header
        """
        if  type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Extract user email and password from decoded Base64 header
        """
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> Optional[TypeVar('User')]:
        """
        Get User object from email and password
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> Optional[TypeVar('User')]:
        """
        Retrieve User instance for a request
        """
        auth_header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(auth_header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        email, pwd = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(email, pwd)
