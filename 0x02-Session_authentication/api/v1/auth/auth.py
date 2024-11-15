#!/usr/bin/env python3
""" Class to manage Authentication
"""
from flask import request
from typing import List, TypeVar
from models.user import User
from os import getenv


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

    def session_cookie(self, request=None):
        _my_session_id = getenv('SESSION_NAME')
        if request is None:
            return None
        if request.headers.get('Cookie') is None:
            return None
        cookie_value = request.headers.get('Cookie')[len('_my_session_id='):]
        return cookie_value

    def current_user(self, request=None):
        cookie_value = self.session_cookie(request)
        user_id = self.user_id_for_session_id(cookie_value)
        user_class = User()
        db_user = user_class.get(user_id)
        return db_user