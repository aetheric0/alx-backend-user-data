#!/usr/bin/env python3
""" The Session Authentication Class for Session authentication
"""
from api.v1.auth.auth import Auth
from os import getenv
import uuid


class SessionAuth(Auth):
    """ Defines the SessionAuth class for session authentication
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """ Creates a session Id as key for a user id
        """
        if user_id is None or not (isinstance(user_id, str)):
            return None
        session_id = uuid.uuid4()
        self.user_id_by_session_id[str(session_id)] = user_id
        return str(session_id)

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Retrieves a user id based on the session id
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def destroy_session(self, request=None):
        """ Destroys the current session by the session_id
        """
        if request is None or not self.session_cookie(request):
            return False
        if not self.user_id_for_session_id:
            return False
        cookie_name = getenv('SESSION_NAME')
        session_id = request.headers.get('Cookie')[len(cookie_name) + 1:]
        del self.user_id_by_session_id[session_id]
        return True
