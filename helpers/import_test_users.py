"""
Import TEST users into Keycloak

Run:
    python3 import_test_users.py
"""

import httpx
import sys

# --------------------------------------------------
# Config
# --------------------------------------------------

KEYCLOAK_URL = "http://localhost:8080"
REALM = "hospital"
ADMIN_USER = "<KEYCLOAK_USERNAME>"
ADMIN_PASSWORD = "<KEYCLOAK_PASSWORD>"

# --------------------------------------------------
# Test Users
# --------------------------------------------------

TEST_USERS = [
    {"username": "test.user1", "password": "Test1!Pass"},
    {"username": "test.user2", "password": "Test2!Pass"},
    {"username": "test.user3", "password": "Test3!Pass"},
    {"username": "test.user4", "password": "Test4!Pass"},
    {"username": "test.user5", "password": "Test5!Pass"},
    {"username": "test.user6", "password": "Test6!Pass"},
]

# --------------------------------------------------
# Helpers
# --------------------------------------------------

def get_admin_token(client: httpx.Client) -> str:
    resp = client.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
            "grant_type": "password",
        }
    )
    if resp.status_code != 200:
        print(f"ERROR: Could not get admin token: {resp.text}")
        sys.exit(1)

    return resp.json()["access_token"]


def create_user(client: httpx.Client, headers: dict, user: dict):
    resp = client.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
        headers=headers,
        json={
            "username": user["username"],
            "enabled": True,
            "credentials": [{
                "type": "password",
                "value": user["password"],
                "temporary": False
            }]
        }
    )

    if resp.status_code == 201:
        print(f"OK created {user['username']}")
    elif resp.status_code == 409:
        print(f"SKIP {user['username']} (already exists)")
    else:
        print(f"ERROR {user['username']}: {resp.status_code} {resp.text}")

# --------------------------------------------------
# Main
# --------------------------------------------------

def main():
    print("Importing test users...\n")

    with httpx.Client(verify=False, timeout=15) as client:
        token = get_admin_token(client)

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        for user in TEST_USERS:
            create_user(client, headers, user)

    print("\nDone.")


if __name__ == "__main__":
    main()