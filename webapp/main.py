from fastapi import FastAPI, Request, Form, Header, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from config import get_settings
from auth import get_keycloak_login_url, exchange_code_for_token, logout_user, get_keycloak_users
from db import (
    get_patient, get_patient_nhs_number, get_emergency_contact,
    get_medical_records, get_patient_by_nhs, update_patient,
    get_emergency_contact_single, update_emergency_contact,
    get_medical_record_single, update_medical_record,
    add_medical_record, delete_medical_record,
    create_audit_log_table, add_audit_log, get_audit_logs,
)

settings = get_settings()
app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Create audit log table on startup
create_audit_log_table()

# =============================================================================
# Least-privilege field filtering
# Controls which patient fields each role can see.
# None = full access, named set = restricted fields, empty set = no access.
# =============================================================================

PATIENT_FIELDS_BY_ROLE = {
    "doctor":     None,
    "nurse":      None,
    "pharmacist": {"name", "age", "gender", "nhs_number"},
    "admin":      set(),  # admins manage users, not patient records
}

def filter_patient_fields(patients: list, role: str) -> list:
    """Return patients with only the fields permitted for the given role."""
    permitted = PATIENT_FIELDS_BY_ROLE.get(role)
    if permitted is None:
        return patients
    if not permitted:
        return []
    return [
        {k: v for k, v in dict(p).items() if k in permitted}
        for p in patients
    ]

# =============================================================================
# Shared dependencies
# =============================================================================

def get_user(
    x_user_id:   str | None = Header(None),
    x_user_role: str | None = Header(None),
) -> dict:
    """
    Extract OPA identity headers injected by Envoy on every authenticated request.
    x-user-id and x-user-role are set by OPA after JWT decoding and policy evaluation.
    Falls back to 'unknown' if headers are missing.
    """
    return {
        "id":   x_user_id   or "unknown",
        "role": x_user_role or "unknown",
    }

def patient_redirect(role: str, nhs_number: str) -> RedirectResponse:
    """
    After a write operation, redirect back to the patient search page
    for the given role, pre-filled with the patient's name.
    """
    patient = get_patient_by_nhs(nhs_number)
    name = patient["name"] if patient else ""
    return RedirectResponse(url=f"/{role}/patient?name={name}", status_code=303)

# =============================================================================
# Auth routes
# =============================================================================

@app.get("/")
def root():
    return RedirectResponse(url="/login")

@app.get("/login")
def login():
    """Redirect the browser to Keycloak's authorization endpoint to begin login."""
    return RedirectResponse(url=get_keycloak_login_url())

@app.get("/callback")
async def callback(code: str):
    """
    Keycloak redirects here after the user authenticates.
    Exchange the authorization code for tokens and store the access token
    in an httponly cookie so Envoy's Lua filter can forward it as a Bearer header.
    The refresh token is stored separately so the logout route can revoke the session.
    """
    try:
        tokens = await exchange_code_for_token(code)
        access_token  = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")
        if not access_token:
            return RedirectResponse(url="/login")
    except Exception:
        # Token exchange failed — send user back to login rather than showing a 500
        return RedirectResponse(url="/login")

    response = RedirectResponse(url="/dashboard")
    response.set_cookie(
        key="access_token", value=access_token,
        httponly=True, secure=False, samesite="lax",
        max_age=300, path="/"  # 5 mins — matches Keycloak's default access token lifetime
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, secure=False, samesite="lax",
        max_age=1800, path="/"  # 30 mins — matches Keycloak's default refresh token lifetime
    )
    return response

@app.get("/logout")
async def logout(request: Request):
    """
    Revoke the Keycloak session via front-channel logout.
    Clears both cookies via JavaScript then redirects the browser to Keycloak's
    logout endpoint — this kills the SSO session so Keycloak won't silently
    re-authenticate and issue new cookies when /login is next visited.
    """
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        await logout_user(refresh_token)

    keycloak_logout_url = (
        f"{settings.keycloak_browser_url}/realms/{settings.keycloak_realm}"
        f"/protocol/openid-connect/logout"
        f"?client_id={settings.keycloak_client_id}"
        f"&post_logout_redirect_uri={settings.keycloak_redirect_uri.replace('/callback', '/login')}"
    )

    response = HTMLResponse(content=f"""
        <html><body>
        <script>
        document.cookie = 'access_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
        document.cookie = 'refresh_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
        window.location.href = '{keycloak_logout_url}';
        </script>
        </body></html>
    """)
    response.delete_cookie("access_token", path="/", httponly=True, samesite="lax")
    response.delete_cookie("refresh_token", path="/", httponly=True, samesite="lax")
    return response

@app.get("/dashboard")
def dashboard(x_user_role: str | None = Header(None)):
    """
    Route the user to their role-specific dashboard.
    x-user-role is injected by OPA after validating the JWT and checking the shift rota.
    If the role is unrecognised, fall back to /login.
    """
    known_roles = {"doctor", "nurse", "pharmacist", "admin"}
    role = x_user_role if x_user_role in known_roles else None
    return RedirectResponse(url=f"/{role}/dashboard" if role else "/login")

# =============================================================================
# DOCTOR ROUTES
# Full access: view patients, edit demographics, emergency contacts,
# add/edit/delete medical records.
# =============================================================================

@app.get("/doctor/dashboard", response_class=HTMLResponse)
def doctor_dashboard(request: Request, user: dict = Depends(get_user)):
    return templates.TemplateResponse(
        "doctor/dashboard.html",
        {"request": request, "role": user["role"]}
    )

@app.get("/doctor/patient", response_class=HTMLResponse)
def doctor_patient(
    request: Request,
    name: str = "",
    user: dict = Depends(get_user)
):
    patients   = get_patient(name)
    nhs_row    = get_patient_nhs_number(name)
    nhs_number = nhs_row["nhs_number"] if nhs_row else None

    if name and patients:
        add_audit_log(user["id"], user["role"], "VIEW_PATIENT", name)

    return templates.TemplateResponse("doctor/patient.html", {
        "request":           request,
        "patients":          patients,
        "name":              name,
        "emergency_contact": get_emergency_contact(nhs_number),
        "medical_records":   get_medical_records(nhs_number),
        "role":              user["role"],
    })

@app.get("/doctor/edit/{nhs_number}", response_class=HTMLResponse)
def doctor_edit_patient_form(
    request: Request,
    nhs_number: str,
    user: dict = Depends(get_user)
):
    patient = get_patient_by_nhs(nhs_number)
    if not patient:
        return RedirectResponse(url="/doctor/patient")
    return templates.TemplateResponse("doctor/edit_patient.html", {
        "request":    request,
        "edit_type":  "patient",
        "patient":    patient,
        "action_url": f"/doctor/update/{nhs_number}",
        "role":       user["role"],
    })

@app.post("/doctor/update/{nhs_number}")
def doctor_update_patient(
    nhs_number:   str,
    user:         dict = Depends(get_user),
    name:         str  = Form(...),
    age:          int  = Form(...),
    gender:       str  = Form(...),
    phone_number: str  = Form(...),
    email:        str  = Form(...),
    address:      str  = Form(...)
):
    update_patient(nhs_number, name=name, age=age, gender=gender,
                   phone_number=phone_number, email=email, address=address)
    add_audit_log(user["id"], user["role"], "EDIT_PATIENT", f"NHS:{nhs_number}")
    return patient_redirect("doctor", nhs_number)

@app.get("/doctor/edit-contact/{nhs_number}", response_class=HTMLResponse)
def doctor_edit_contact_form(
    request: Request,
    nhs_number: str,
    user: dict = Depends(get_user)
):
    contact = get_emergency_contact_single(nhs_number)
    patient = get_patient_by_nhs(nhs_number)
    if not contact or not patient:
        return RedirectResponse(url="/doctor/patient")
    return templates.TemplateResponse("doctor/edit_patient.html", {
        "request":    request,
        "edit_type":  "contact",
        "contact":    contact,
        "patient":    patient,
        "action_url": f"/doctor/update-contact/{nhs_number}",
        "role":       user["role"],
    })

@app.post("/doctor/update-contact/{nhs_number}")
def doctor_update_contact(
    nhs_number:   str,
    user:         dict = Depends(get_user),
    name:         str  = Form(...),
    relationship: str  = Form(...),
    phone_number: str  = Form(...),
    email:        str  = Form(...)
):
    update_emergency_contact(nhs_number, name=name, relationship=relationship,
                             phone_number=phone_number, email=email)
    add_audit_log(user["id"], user["role"], "EDIT_EMERGENCY_CONTACT", f"NHS:{nhs_number}")
    return patient_redirect("doctor", nhs_number)

@app.get("/doctor/edit-medical/{nhs_number}/{record_id}", response_class=HTMLResponse)
def doctor_edit_medical_form(
    request: Request,
    nhs_number: str,
    record_id: int,
    user: dict = Depends(get_user)
):
    record  = get_medical_record_single(record_id, nhs_number)
    patient = get_patient_by_nhs(nhs_number)
    if not record or not patient:
        return RedirectResponse(url="/doctor/patient")
    return templates.TemplateResponse("doctor/edit_patient.html", {
        "request":    request,
        "edit_type":  "medical",
        "record":     record,
        "patient":    patient,
        "action_url": f"/doctor/update-medical/{nhs_number}/{record_id}",
        "role":       user["role"],
    })

@app.post("/doctor/update-medical/{nhs_number}/{record_id}")
def doctor_update_medical(
    nhs_number: str,
    record_id:  int,
    user:       dict = Depends(get_user),
    condition:  str  = Form(...),
    treatment:  str  = Form(...)
):
    update_medical_record(record_id, nhs_number, condition=condition, treatment=treatment)
    add_audit_log(user["id"], user["role"], "EDIT_MEDICAL_RECORD", f"NHS:{nhs_number} Record:{record_id}")
    return patient_redirect("doctor", nhs_number)

@app.get("/doctor/add-medical/{nhs_number}", response_class=HTMLResponse)
def doctor_add_medical_form(
    request: Request,
    nhs_number: str,
    user: dict = Depends(get_user)
):
    patient = get_patient_by_nhs(nhs_number)
    if not patient:
        return RedirectResponse(url="/doctor/patient")
    return templates.TemplateResponse(
        "doctor/add_medical.html",
        {"request": request, "patient": patient, "role": user["role"]}
    )

@app.post("/doctor/save-medical/{nhs_number}")
def doctor_save_medical(
    nhs_number: str,
    user:       dict = Depends(get_user),
    condition:  str  = Form(...),
    treatment:  str  = Form(...)
):
    add_medical_record(nhs_number, condition, treatment)
    add_audit_log(user["id"], user["role"], "ADD_MEDICAL_RECORD", f"NHS:{nhs_number}")
    return patient_redirect("doctor", nhs_number)

@app.post("/doctor/delete-medical/{nhs_number}/{record_id}")
def doctor_delete_medical(
    nhs_number: str,
    record_id:  int,
    user:       dict = Depends(get_user)
):
    delete_medical_record(record_id, nhs_number)
    add_audit_log(user["id"], user["role"], "DELETE_MEDICAL_RECORD", f"NHS:{nhs_number} Record:{record_id}")
    return patient_redirect("doctor", nhs_number)

# =============================================================================
# NURSE ROUTES
# View patients and emergency contacts, add medical records only.
# Cannot edit or delete existing records.
# =============================================================================

@app.get("/nurse/dashboard", response_class=HTMLResponse)
def nurse_dashboard(request: Request, user: dict = Depends(get_user)):
    return templates.TemplateResponse(
        "nurse/dashboard.html",
        {"request": request, "role": user["role"]}
    )

@app.get("/nurse/patient", response_class=HTMLResponse)
def nurse_patient(
    request: Request,
    name: str = "",
    user: dict = Depends(get_user)
):
    patients   = get_patient(name)
    nhs_row    = get_patient_nhs_number(name)
    nhs_number = nhs_row["nhs_number"] if nhs_row else None

    if name and patients:
        add_audit_log(user["id"], user["role"], "VIEW_PATIENT", name)

    return templates.TemplateResponse("nurse/patient.html", {
        "request":           request,
        "patients":          patients,
        "name":              name,
        "emergency_contact": get_emergency_contact(nhs_number),
        "medical_records":   get_medical_records(nhs_number),
        "role":              user["role"],
    })

@app.get("/nurse/add-medical/{nhs_number}", response_class=HTMLResponse)
def nurse_add_medical_form(
    request: Request,
    nhs_number: str,
    user: dict = Depends(get_user)
):
    patient = get_patient_by_nhs(nhs_number)
    if not patient:
        return RedirectResponse(url="/nurse/patient")
    return templates.TemplateResponse(
        "nurse/add_medical.html",
        {"request": request, "patient": patient, "role": user["role"]}
    )

@app.post("/nurse/save-medical/{nhs_number}")
def nurse_save_medical(
    nhs_number: str,
    user:       dict = Depends(get_user),
    condition:  str  = Form(...),
    treatment:  str  = Form(...)
):
    add_medical_record(nhs_number, condition, treatment)
    add_audit_log(user["id"], user["role"], "ADD_MEDICAL_RECORD", f"NHS:{nhs_number}")
    return patient_redirect("nurse", nhs_number)

# =============================================================================
# PHARMACIST ROUTES
# View patients with restricted fields only (name, age, gender, NHS number).
# No emergency contacts, no editing.
# =============================================================================

@app.get("/pharmacist/dashboard", response_class=HTMLResponse)
def pharmacist_dashboard(request: Request, user: dict = Depends(get_user)):
    return templates.TemplateResponse(
        "pharmacist/dashboard.html",
        {"request": request, "role": user["role"]}
    )

@app.get("/pharmacist/patient", response_class=HTMLResponse)
def pharmacist_patient(
    request: Request,
    name: str = "",
    user: dict = Depends(get_user)
):
    patients   = get_patient(name)
    nhs_row    = get_patient_nhs_number(name)
    nhs_number = nhs_row["nhs_number"] if nhs_row else None

    if name and patients:
        add_audit_log(user["id"], user["role"], "VIEW_PATIENT", name)

    return templates.TemplateResponse("pharmacist/patient.html", {
        "request":         request,
        "patients":        filter_patient_fields(patients, user["role"]),
        "name":            name,
        "medical_records": get_medical_records(nhs_number),
        "role":            user["role"],
    })

# =============================================================================
# ADMIN ROUTES
# User management via Keycloak Admin API, audit log viewer.
# No access to patient records.
# =============================================================================

@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, user: dict = Depends(get_user)):
    return templates.TemplateResponse(
        "admin/dashboard.html",
        {"request": request, "role": user["role"]}
    )

@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, user: dict = Depends(get_user)):
    """Fetch live user list from Keycloak Admin API."""
    users = await get_keycloak_users()
    add_audit_log(user["id"], user["role"], "VIEW_USERS", "keycloak_user_list")
    return templates.TemplateResponse(
        "admin/users.html",
        {"request": request, "users": users, "role": user["role"]}
    )

@app.get("/admin/logs", response_class=HTMLResponse)
def admin_logs(
    request: Request,
    limit: int = 100,
    user: dict = Depends(get_user)
):
    """
    View audit log entries. limit can be passed as a query param e.g. /admin/logs?limit=500.
    The act of viewing logs is itself audit logged.
    """
    logs = get_audit_logs(limit=limit)
    add_audit_log(user["id"], user["role"], "VIEW_AUDIT_LOGS", "audit_log_table")
    return templates.TemplateResponse(
        "admin/logs.html",
        {"request": request, "logs": logs, "role": user["role"]}
    )
