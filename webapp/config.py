from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    # ── Keycloak server ───────────────────────────────────────────────────────
    # keycloak_url: internal URL used for server-to-server calls (token exchange,
    #               JWKS fetch, admin API). On a two-VM setup this is 10.0.0.1:8080.
    # keycloak_browser_url: public-facing URL the browser is redirected to for login.
    #               On a two-VM setup this is the gateway VM's LAN IP.
    keycloak_url:          str
    keycloak_browser_url:  str
    keycloak_realm:        str

    # ── Client credentials ────────────────────────────────────────────────────
    keycloak_client_id:     str
    keycloak_client_secret: str
    keycloak_redirect_uri:  str

    # ── Admin API credentials (used by admin portal to list real users) ───────
    keycloak_admin_username: str = "admin"
    keycloak_admin_password: str = "admin"

    # ── TLS ───────────────────────────────────────────────────────────────────
    # Set to path of CA cert file in production. False disables verification.
    keycloak_ca_cert: bool = False

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    @property
    def keycloak_jwks_url(self) -> str:
        """Derived from keycloak_url — no need to set separately in .env."""
        return f"{self.keycloak_url}/realms/{self.keycloak_realm}/protocol/openid-connect/certs"

@lru_cache
def get_settings() -> Settings:
    return Settings()