#!/usr/bin/env python3
""" Class to manage Authentication
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """ Defines the Authentication class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Determines if path requires authentication
        """
        return False

    def authorization_header(self, request=None) -> str:
        """ Checks for authorization header in request
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Checks the current user
        """
        return None