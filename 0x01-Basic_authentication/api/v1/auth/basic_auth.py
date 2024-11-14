#!/usr/bin/env python3
""" The BasicAuth class that inherits from the Auth Class
"""
from .auth import Auth
import base64


class BasicAuth(Auth):
    """ Defines the BasicAuth Class
    """
    def extract_base64_authorization_header(
                                            self, authorization_header: str
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
