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
        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """ Checks for authorization header in request
        """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """ Checks the current user
        """
        return None
