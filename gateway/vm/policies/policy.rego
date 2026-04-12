package httpapi.authz

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default allow = false

# =============================================================================
# JWT decoding
# Read full token from Authorization header, strip Bearer prefix, decode.
# =============================================================================

payload := p if {
    auth := input.attributes.request.http.headers.authorization
    token := trim_prefix(auth, "Bearer ")
    [_, p, _] := io.jwt.decode(token)
}

role := r if {
    roles := payload.realm_access.roles
    r := roles[_]
    r in {"doctor", "nurse", "pharmacist", "admin"}
}

user := payload.preferred_username

# =============================================================================
# Public paths — no auth or shift check required
# =============================================================================

public_path if {
    input.attributes.request.http.path in {"/", "/login", "/dashboard", "/favicon.ico", "/logout"}
}

public_path if {
    startswith(input.attributes.request.http.path, "/callback")
}

public_path if {
    startswith(input.attributes.request.http.path, "/static")
}

# =============================================================================
# Role-based access control (RBAC)
# Each role can only access their own path prefix.
# =============================================================================

role_allowed if { role == "doctor";     startswith(input.attributes.request.http.path, "/doctor") }
role_allowed if { role == "nurse";      startswith(input.attributes.request.http.path, "/nurse") }
role_allowed if { role == "pharmacist"; startswith(input.attributes.request.http.path, "/pharmacist") }
role_allowed if { role == "admin";      startswith(input.attributes.request.http.path, "/admin") }

# =============================================================================
# Time Based Access Control (TBAC)
# Checks shifts.json loaded via OPA --data flag.
# Handles normal shifts (e.g. 07:00-19:00) and overnight shifts (e.g. 19:00-07:00).
# =============================================================================

on_shift if {
    shift := data.shifts[user]
    now   := time.now_ns()
    day   := lower(time.weekday(now))
    hour  := time.clock(now)[0]

    shift.days[_] == day

    # Normal shift — start hour is before end hour (e.g. 07:00-19:00)
    shift.start <= shift.end
    hour >= shift.start
    hour < shift.end
}

on_shift if {
    shift := data.shifts[user]
    now  := time.now_ns()
    day  := lower(time.weekday(now))
    hour := time.clock(now)[0]

    shift.days[_] == day

    # Overnight shift — current day, evening portion (e.g. hour >= 19)
    shift.start > shift.end
    hour >= shift.start
}

on_shift if {
    shift        := data.shifts[user]
    now          := time.now_ns()
    yesterday_ns := now - (24 * 60 * 60 * 1000000000)
    yesterday    := lower(time.weekday(yesterday_ns))
    hour         := time.clock(now)[0]

    # Overnight shift — yesterday was a scheduled day, now in early morning portion
    shift.days[_] == yesterday
    shift.start > shift.end
    hour < shift.end
}

# =============================================================================
# Emergency / overtime override (TBAC exception)
# Checked independently of on_shift — either condition can grant access.
# Overrides are stored in overrides.json, mounted into OPA alongside shifts.json.
# Each override has a Unix timestamp expiry — once elapsed, normal shift rules apply.
# The reason field is for audit purposes only and is not evaluated by OPA.
# =============================================================================

has_override if {
    override := data.overrides[user]
    # Convert expiry from Unix seconds to nanoseconds for comparison with time.now_ns()
    time.now_ns() < override.expires * 1000000000
}

# =============================================================================
# Final allow decision
# Public paths always allowed.
# Protected paths require role match AND (on shift OR active override).
# =============================================================================

allow if { public_path }

allow if {
    role_allowed
    on_shift
}

allow if {
    role_allowed
    has_override
}

# =============================================================================
# Structured response
# OPA injects x-user-role and x-user-id headers into every allowed request.
# Envoy forwards these to FastAPI where they are read via get_user().
# =============================================================================

response_headers := {"x-user-role": role, "x-user-id": user} if {
    role
    user
} else := {}

response := {
    "allowed": allow,
    "headers": response_headers,
    "debug": debug
}

debug := {
    "user": user,
    "role": role,
    "hour": time.clock(time.now_ns())[0],
    "day": time.weekday(time.now_ns()),
    "on_shift": on_shift
}