#!/usr/bin/env python3
""" The BasicAuth class that inherits from the Auth Class
"""
from .auth import Auth
import base64
from flask import request
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ Defines the BasicAuth Class
    """
    def extract_base64_authorization_header(
                                            self,
                                            authorization_header: str
                                            ) -> str:
        """ Extracts the token from the authorization header
        """
        if (authorization_header is None
                or not isinstance(authorization_header, str)
                or not authorization_header.startswith('Basic ')):
            return None
        return authorization_header[len('Basic '):]

    def decode_base64_authorization_header(
                                           self,
                                           base64_authorization_header: str
                                           ) -> str:
        """ Decodes the token from the authorization header
        """
        if (base64_authorization_header is None
                or not isinstance(base64_authorization_header, str)):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
                                  self,
                                  decoded_base64_authorization_header: str
                                  ) -> (str, str):
        """ Extracts user credentials from authorization token
        """
        if (decoded_base64_authorization_header is None
                or not isinstance(decoded_base64_authorization_header, str)
                or ':' not in decoded_base64_authorization_header):
            return (None, None)
        username, password = decoded_base64_authorization_header.split(':')
        return (username, password)

    def user_object_from_credentials(
                                     self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ Validates the credentials from request against database
        """
        if (user_email is None or not isinstance(user_email, str)
                or user_pwd is None or not isinstance(user_pwd, str)):
            return None
        user_class = User()
        user_list = user_class.search({"email": user_email})
        if len(user_list) == 1:
            db_user = user_list[0]
        else:
            return None
        if not db_user.is_valid_password(user_pwd):
            return None
        return db_user

    def current_user(self, request=None) -> TypeVar('User'):
        """ Implements all methods to validate user from HTTP request
        """
        auth_value = self.authorization_header(request)
        if auth_value:
            auth_token = self.extract_base64_authorization_header(auth_value)
            decoded_token = self.decode_base64_authorization_header(auth_token)
            email, password = self.extract_user_credentials(decoded_token)
            return self.user_object_from_credentials(email, password)
        else:
            return None
