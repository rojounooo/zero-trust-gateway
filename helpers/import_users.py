"""
Keycloak User Import Script
Creates all 24 hospital staff users in the hospital realm,
sets passwords, and assigns realm roles.

Run from the gateway VM:
    python3 import_users.py

Requirements: pip3 install httpx
"""

import httpx
import sys

# =============================================================================
# Config
# =============================================================================

KEYCLOAK_URL    = "http://localhost:8080"
REALM           = "hospital"
ADMIN_USER      = "<KEYCLOAK_USERNAME>"
ADMIN_PASSWORD  = "KEYCLOAK_PASSWORD>"
CLIENT_ID       = "fastapi-app"
CLIENT_SECRET   = "<CLIENT_SECRET>"

# =============================================================================
# Users
# =============================================================================

USERS = [
    # Doctors
    {"username": "doctor.smith",    "first": "James",   "last": "Smith",    "email": "smith@hospital.com",    "password": "qT8#mNp3", "role": "doctor"},
    {"username": "doctor.jones",    "first": "Sarah",   "last": "Jones",    "email": "jones@hospital.com",    "password": "Lw5@rKx9", "role": "doctor"},
    {"username": "doctor.patel",    "first": "Priya",   "last": "Patel",    "email": "patel@hospital.com",    "password": "Yb2!vGm6", "role": "doctor"},
    {"username": "doctor.williams", "first": "Owen",    "last": "Williams", "email": "williams@hospital.com", "password": "Hp4$nJd7", "role": "doctor"},
    {"username": "doctor.brown",    "first": "Claire",  "last": "Brown",    "email": "brown@hospital.com",    "password": "Fc6^kRw1", "role": "doctor"},
    {"username": "doctor.taylor",   "first": "Marcus",  "last": "Taylor",   "email": "taylor@hospital.com",   "password": "Zd9&mBs4", "role": "doctor"},

    # Nurses
    {"username": "nurse.robinson",  "first": "Emma",    "last": "Robinson", "email": "robinson@hospital.com", "password": "Wm3#tLp8", "role": "nurse"},
    {"username": "nurse.davies",    "first": "Liam",    "last": "Davies",   "email": "davies@hospital.com",   "password": "Xk7@nVc2", "role": "nurse"},
    {"username": "nurse.evans",     "first": "Sophie",  "last": "Evans",    "email": "evans@hospital.com",    "password": "Qr5!hMd9", "role": "nurse"},
    {"username": "nurse.wilson",    "first": "Daniel",  "last": "Wilson",   "email": "wilson@hospital.com",   "password": "Jb4$pFw6", "role": "nurse"},
    {"username": "nurse.thomas",    "first": "Grace",   "last": "Thomas",   "email": "thomas@hospital.com",   "password": "Ny8^rKx3", "role": "nurse"},
    {"username": "nurse.roberts",   "first": "Ryan",    "last": "Roberts",  "email": "roberts@hospital.com",  "password": "Gs1&mTl7", "role": "nurse"},

    # Pharmacists
    {"username": "pharmacist.harris",   "first": "Olivia",  "last": "Harris",   "email": "harris@hospital.com",   "password": "Bt6#wJn4", "role": "pharmacist"},
    {"username": "pharmacist.martin",   "first": "Ben",     "last": "Martin",   "email": "martin@hospital.com",   "password": "Kp2@vRm8", "role": "pharmacist"},
    {"username": "pharmacist.jackson",  "first": "Chloe",   "last": "Jackson",  "email": "jackson@hospital.com",  "password": "Hd9!tXc5", "role": "pharmacist"},
    {"username": "pharmacist.white",    "first": "Noah",    "last": "White",    "email": "white@hospital.com",    "password": "Lw3$nGk7", "role": "pharmacist"},
    {"username": "pharmacist.lewis",    "first": "Isla",    "last": "Lewis",    "email": "lewis@hospital.com",    "password": "Yf7^mBp1", "role": "pharmacist"},
    {"username": "pharmacist.hall",     "first": "Tyler",   "last": "Hall",     "email": "hall@hospital.com",     "password": "Rc4&hDs6", "role": "pharmacist"},

    # Admins
    {"username": "admin.afroz",  "first": "Ahmad",   "last": "Afroz",  "email": "afroz@hospital.com",  "password": "Af5#mWp9", "role": "admin"},
    {"username": "admin.ahmed",  "first": "Zaeem",   "last": "Ahmed",  "email": "ahmed@hospital.com",  "password": "Zm8@rKn3", "role": "admin"},
    {"username": "admin.clark",  "first": "Nathan",  "last": "Clark",  "email": "clark@hospital.com",  "password": "Jc2!tVd7", "role": "admin"},
    {"username": "admin.walker", "first": "Laura",   "last": "Walker", "email": "walker@hospital.com", "password": "Nw6$hLx4", "role": "admin"},
    {"username": "admin.young",  "first": "Finn",    "last": "Young",  "email": "young@hospital.com",  "password": "By9^kMf1", "role": "admin"},
    {"username": "admin.king",   "first": "Rachel",  "last": "King",   "email": "king@hospital.com",   "password": "Gs3&pTr8", "role": "admin"},
]

# =============================================================================
# Helpers
# =============================================================================

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


def get_realm_roles(client: httpx.Client, headers: dict) -> dict:
    """Return a dict of role_name -> role_id for the hospital realm."""
    resp = client.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles",
        headers=headers
    )
    if resp.status_code != 200:
        print(f"ERROR: Could not fetch roles: {resp.text}")
        sys.exit(1)
    return {r["name"]: r["id"] for r in resp.json()}


def create_user(client: httpx.Client, headers: dict, user: dict) -> str | None:
    """Create user and return their Keycloak ID, or None if already exists."""
    resp = client.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users",
        headers=headers,
        json={
            "username":  user["username"],
            "firstName": user["first"],
            "lastName":  user["last"],
            "email":     user["email"],
            "enabled":   True,
            "credentials": [{
                "type":      "password",
                "value":     user["password"],
                "temporary": False,
            }]
        }
    )

    if resp.status_code == 201:
        location = resp.headers.get("Location", "")
        return location.split("/")[-1]
    elif resp.status_code == 409:
        print(f"  SKIP {user['username']} — already exists")
        search = client.get(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users?username={user['username']}&exact=true",
            headers=headers
        )
        results = search.json()
        return results[0]["id"] if results else None
    else:
        print(f"  ERROR creating {user['username']}: {resp.status_code} {resp.text}")
        return None


def assign_role(client: httpx.Client, headers: dict, user_id: str, role_name: str, roles_map: dict):
    role_id = roles_map.get(role_name)
    if not role_id:
        print(f"  ERROR: Role '{role_name}' not found in realm — create it in Keycloak first")
        return

    resp = client.post(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
        headers=headers,
        json=[{"id": role_id, "name": role_name}]
    )
    if resp.status_code not in (200, 204):
        print(f"  ERROR assigning role {role_name}: {resp.status_code} {resp.text}")


# =============================================================================
# Main
# =============================================================================

def main():
    print(f"Connecting to Keycloak at {KEYCLOAK_URL} ...")

    with httpx.Client(verify=False, timeout=15) as client:
        token = get_admin_token(client)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        print("Fetching realm roles ...")
        roles_map = get_realm_roles(client, headers)
        print(f"  Found roles: {list(roles_map.keys())}")

        required = {"doctor", "nurse", "pharmacist", "admin"}
        missing = required - set(roles_map.keys())
        if missing:
            print(f"\nERROR: Missing roles in hospital realm: {missing}")
            print("Create them in Keycloak Admin → hospital realm → Realm roles, then re-run.")
            sys.exit(1)

        print(f"\nCreating {len(USERS)} users ...\n")
        success = 0

        for user in USERS:
            print(f"  {user['first']} {user['last']} ({user['username']}) ...", end=" ")
            user_id = create_user(client, headers, user)
            if user_id:
                assign_role(client, headers, user_id, user["role"], roles_map)
                print(f"OK ({user['role']})")
                success += 1

    print(f"\nDone — {success}/{len(USERS)} users created/updated.")
    print("Delete this script and credentials.md once you've verified the users in Keycloak.")


if __name__ == "__main__":
    main()
