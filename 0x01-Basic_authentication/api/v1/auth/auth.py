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
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path = path + '/'
        if path not in excluded_paths:
            return True
        if path in excluded_paths and path == '/api/v1/status/':
            return False
        return False

    def authorization_header(self, request=None) -> str:
        """ Checks for authorization header in request
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Checks the current user
        """
        return None
