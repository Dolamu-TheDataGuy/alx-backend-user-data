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
    def extract_base64_authorization_header(self, authorization_header: str) -> str:
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
