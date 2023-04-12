#!/usr/bin/env python3
"""
Defining Basic Authentication class - BasicAuth
"""

import base64
from .auth import Auth
from typing import TypeVar


class BasicAuth(Auth):
    """
    Implement Basic Authorization protocol methods
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str
                                            ) -> str:
        """
        Extracts the Base64 part of the Authorization header for a Basic
        Authorization
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        token = authorization_header.split(" ")[-1]
        return token

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """
        Decode a Base64-encoded string
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_auth = base64_authorization_header.encode(
                'utf-8'
                )
            decoded_auth = base64.b64decode(decoded_auth)
        except Exception:
            return None
        else:
            return decoded_auth.decode(
                'utf-8'
            )  # run try code if successful
