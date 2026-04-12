from fastapi import HTTPException, status
from config import get_settings
import httpx
from urllib.parse import urlencode

settings = get_settings()


# =========================
# Helper: Keycloak token request
# =========================
async def request_keycloak_token(data, url=None, ignore_errors=False):
    """
    Send a token request to Keycloak with the given data dictionary.
    
    Args:
        data: Dictionary containing grant_type, client_id, client_secret, etc.
        url: Optional custom token endpoint URL. Defaults to app realm.
        ignore_errors: If True, returns None instead of raising HTTPException.

    Returns:
        Dictionary containing access_token, refresh_token, etc., or None if ignore_errors=True.
    """
    token_url = url or f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/token"

    try:
        async with httpx.AsyncClient(verify=settings.keycloak_ca_cert) as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            tokens = response.json()

        if not tokens.get("access_token"):
            if ignore_errors:
                return None
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Access token not found in response"
            )
        return tokens

    except httpx.HTTPError as e:
        if ignore_errors:
            return None
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Could not connect to Keycloak: {str(e)}"
        )


# =========================
# OAuth2 token functions
# =========================
async def exchange_code_for_token(code):
    """
    Exchange an authorization code for Keycloak access and refresh tokens.
    """
    data = {
        "grant_type": "authorization_code",
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
        "redirect_uri": settings.keycloak_redirect_uri,
        "code": code
    }
    return await request_keycloak_token(data)


async def refresh_access_token(refresh_token):
    """
    Refresh an expired access token using a refresh token.
    """
    data = {
        "grant_type": "refresh_token",
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
        "refresh_token": refresh_token
    }
    return await request_keycloak_token(data)


async def get_keycloak_admin_token():
    """
    Authenticate as Keycloak admin against the master realm.
    
    Returns:
        Admin access token string if successful, None if failed.
    """
    data = {
        "client_id": "admin-cli",
        "username": settings.keycloak_admin_username,
        "password": settings.keycloak_admin_password,
        "grant_type": "password",
    }

    token_response = await request_keycloak_token(
        data,
        url=f"{settings.keycloak_url}/realms/master/protocol/openid-connect/token",
        ignore_errors=True
    )

    return token_response.get("access_token") if token_response else None


# =========================
# Keycloak login/logout URL
# =========================
def get_keycloak_login_url():
    """
    Generate the Keycloak authorization URL for OAuth2 login flow.
    """
    base_url = f"{settings.keycloak_browser_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/auth"
    params = {
        "response_type": "code",
        "client_id": settings.keycloak_client_id,
        "redirect_uri": settings.keycloak_redirect_uri,
        "scope": "openid profile email"
    }
    return f"{base_url}?{urlencode(params)}"

def get_keycloak_logout_url() -> str:
    """Build the Keycloak front-channel logout URL to kill the SSO session."""
    base = f"{settings.keycloak_browser_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/logout"
    params = {
        "client_id": settings.keycloak_client_id,
        "post_logout_redirect_uri": f"http://{settings.keycloak_browser_url.split('//')[1].split(':')[0]}:10000/login"
    }
    return f"{base}?{urlencode(params)}"


# =========================
# Logout
# =========================
async def logout_user(refresh_token):
    """
    Logout user by revoking their refresh token in Keycloak.
    """
    logout_url = f"{settings.keycloak_url}/realms/{settings.keycloak_realm}/protocol/openid-connect/logout"
    data = {
        "client_id": settings.keycloak_client_id,
        "client_secret": settings.keycloak_client_secret,
        "refresh_token": refresh_token
    }

    try:
        async with httpx.AsyncClient(verify=settings.keycloak_ca_cert) as client:
            await client.post(logout_url, data=data)
    except httpx.HTTPError:
        pass  # best-effort logout


# =========================
# Helper: Fetch users and roles
# =========================
async def fetch_all_users(token, realm, base_url):
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(verify=settings.keycloak_ca_cert) as client:
        resp = await client.get(f"{base_url}/admin/realms/{realm}/users", headers=headers)
        if resp.status_code == 200:
            return resp.json()
    return []


async def fetch_user_roles(token, realm, base_url, user_id, known_roles):
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(verify=settings.keycloak_ca_cert) as client:
        resp = await client.get(f"{base_url}/admin/realms/{realm}/users/{user_id}/role-mappings/realm", headers=headers)
        if resp.status_code == 200:
            return [r["name"] for r in resp.json() if r["name"] in known_roles]
    return []


def build_user_dict(user, roles):
    return {
        "username": user.get("username"),
        "email": user.get("email", ""),
        "role": roles[0] if roles else "unknown",
        "status": "Active" if user.get("enabled", False) else "Inactive",
    }


# =========================
# Get all Keycloak users
# =========================
async def get_keycloak_users():
    """
    Return all users in the hospital realm with their assigned roles.
    Only includes users with known roles: doctor, nurse, pharmacist, admin.
    """
    token = await get_keycloak_admin_token()
    if not token:
        return []

    realm = settings.keycloak_realm
    base = settings.keycloak_url
    known_roles = {"doctor", "nurse", "pharmacist", "admin"}

    users = await fetch_all_users(token, realm, base)
    result = []

    for user in users:
        user_id = user.get("id")
        roles = await fetch_user_roles(token, realm, base, user_id, known_roles)
        result.append(build_user_dict(user, roles))

    return result
