"""
Explanation:
    Handles authentication with Keycloak.
    get_token() logs a user in and returns their JWT access token.
    logout_token() revokes a user's session in Keycloak.
    Every other file that needs to act as a user calls get_token() first.
"""

import httpx
import os
from dotenv import load_dotenv

load_dotenv()

KEYCLOAK_URL           = os.environ["KEYCLOAK_URL"]
KEYCLOAK_REALM         = os.environ["KEYCLOAK_REALM"]
KEYCLOAK_CLIENT_ID     = os.environ["KEYCLOAK_CLIENT_ID"]
KEYCLOAK_CLIENT_SECRET = os.environ["KEYCLOAK_CLIENT_SECRET"]

async def get_token(username: str, password: str) -> str | None:
    """Authenticate as a specific user and return their access token."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
                data={
                    "grant_type":    "password",
                    "client_id":     KEYCLOAK_CLIENT_ID,
                    "client_secret": KEYCLOAK_CLIENT_SECRET,
                    "username":      username,
                    "password":      password,
                    "scope":         "openid",
                },
            )
            if response.status_code == 200:
                return response.json().get("access_token")
            return None
    except httpx.HTTPError:
        return None

async def logout_token(refresh_token: str) -> None:
    """Revoke a user's session in Keycloak. Best-effort — errors are swallowed."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout",
                data={
                    "client_id":     KEYCLOAK_CLIENT_ID,
                    "client_secret": KEYCLOAK_CLIENT_SECRET,
                    "refresh_token": refresh_token,
                },
            )
    except httpx.HTTPError:
        pass