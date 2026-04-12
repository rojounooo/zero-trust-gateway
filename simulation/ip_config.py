import random
from helpers import get_on_shift_users, get_off_shift_users

# Staff IP pool — any on-shift user gets assigned one of these
STAFF_IP_POOL   = [f"192.168.1.{i}" for i in range(10, 20)]  # 10 IPs
ATTACKER_IPS    = [f"192.168.2.{i}" for i in range(10, 16)]  # 6 IPs

def get_on_shift_ip(credentials: dict) -> tuple | None:
    """
    Pick a random on-shift user and assign them a random staff IP.
    Returns (ip, username, password, role) or None if nobody is on shift.
    """
    on_shift = get_on_shift_users(credentials)
    if not on_shift:
        return None
    username, password, role = random.choice(on_shift)
    ip = random.choice(STAFF_IP_POOL)
    return ip, username, password, role

def get_off_shift_ip(credentials: dict) -> tuple | None:
    """
    Pick a random off-shift user and assign them a random staff IP.
    Used for TBAC attack — valid staff IP, wrong time.
    Returns (ip, username, password, role) or None.
    """
    off_shift = get_off_shift_users(credentials)
    if not off_shift:
        return None
    username, password, role = random.choice(off_shift)
    ip = random.choice(STAFF_IP_POOL)
    return ip, username, password, role

def get_attacker_ip() -> str:
    """Return a random attacker IP from the attacker range."""
    return random.choice(ATTACKER_IPS)