import datetime as dt
import os
import secrets
import json

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import (
    init_db, Appointment, get_db,
    get_setting, set_setting, set_settings, get_public_settings,
    hash_password, verify_password,
    create_session, get_session, delete_session,
)

init_db()

# ── Auth ────────────────────────────────────────────────────────────

SUPER_ADMIN_KEY = os.environ.get("SUPER_ADMIN_KEY")
security = HTTPBearer(auto_error=False)


def verify_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = credentials.credentials
    session = get_session(db, token)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return True


def verify_super_admin(request: Request):
    if not SUPER_ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Super admin not configured. Set SUPER_ADMIN_KEY env var.")
    key = request.headers.get("X-Super-Admin-Key")
    if not key or not secrets.compare_digest(key, SUPER_ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Invalid or missing super admin key")
    return True


# ── Pydantic models ────────────────────────────────────────────────

class ScheduleRequest(BaseModel):
    patient_name: str
    reason: str | None = None
    start_time: dt.datetime


class CancelRequest(BaseModel):
    patient_name: str
    date: dt.date


class ListRequest(BaseModel):
    date: dt.date


class HealthResponse(BaseModel):
    status: str


class LoginRequest(BaseModel):
    password: str


class SetupRequest(BaseModel):
    clinic_name: str
    admin_password: str
    clinic_address: str = ""
    clinic_phone: str = ""
    clinic_email: str = ""
    clinic_hours: str = "[]"
    brand_primary_color: str = "#2b9e82"
    brand_accent_color: str = "#0b3b5c"
    vapi_assistant_id: str = ""
    vapi_public_key: str = ""
    custom_domain: str = ""


class StatusUpdateRequest(BaseModel):
    status: str


class AppointmentEditRequest(BaseModel):
    patient_name: str | None = None
    reason: str | None = None
    start_time: dt.datetime | None = None


class ChangePasswordRequest(BaseModel):
    new_password: str


# ── FastAPI app ─────────────────────────────────────────────────────

app = FastAPI(title="Clinic Voice Agent - AI Receptionist")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok")


# ── Setup (first-time, requires super admin key) ───────────────────

@app.post("/admin/setup")
def admin_setup(body: SetupRequest, _=Depends(verify_super_admin), db: Session = Depends(get_db)):
    if get_setting(db, "admin_password_hash"):
        raise HTTPException(status_code=400, detail="Setup already completed. Use PUT /admin/settings to update.")

    pwd_hash, salt = hash_password(body.admin_password)
    kv = {
        "clinic_name": body.clinic_name,
        "clinic_address": body.clinic_address,
        "clinic_phone": body.clinic_phone,
        "clinic_email": body.clinic_email,
        "clinic_hours": body.clinic_hours,
        "brand_primary_color": body.brand_primary_color,
        "brand_accent_color": body.brand_accent_color,
        "vapi_assistant_id": body.vapi_assistant_id,
        "vapi_public_key": body.vapi_public_key,
        "custom_domain": body.custom_domain,
        "admin_password_hash": pwd_hash,
        "admin_password_salt": salt,
    }
    set_settings(db, kv)
    return {"ok": True, "message": "Setup complete. You can now log in with the admin password."}


# ── Admin Login ─────────────────────────────────────────────────────

@app.post("/admin/login")
def admin_login(body: LoginRequest, db: Session = Depends(get_db)):
    stored_hash = get_setting(db, "admin_password_hash")
    salt = get_setting(db, "admin_password_salt")
    if not stored_hash or not salt:
        raise HTTPException(status_code=400, detail="Setup not complete. Contact the developer.")
    if not verify_password(body.password, stored_hash, salt):
        raise HTTPException(status_code=401, detail="Invalid password")
    token = create_session(db)
    return {"ok": True, "token": token}


# ─── Admin Logout ───────────────────────────────────────────────────

@app.post("/admin/logout")
def admin_logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
):
    if credentials:
        delete_session(db, credentials.credentials)
    return {"ok": True}


# ── Public Settings (no auth required) ──────────────────────────────

@app.get("/admin/settings")
def admin_settings(db: Session = Depends(get_db)):
    return get_public_settings(db)


# ── Update Settings (requires super admin key) ─────────────────────

@app.put("/admin/settings")
def admin_update_settings(
    body: dict,
    db: Session = Depends(get_db),
    _=Depends(verify_super_admin),
):
    allowed_keys = {
        "clinic_name", "clinic_address", "clinic_phone", "clinic_email",
        "clinic_hours", "brand_primary_color", "brand_accent_color",
        "vapi_assistant_id", "vapi_public_key", "custom_domain",
    }
    kv = {}
    for key, value in body.items():
        if key not in allowed_keys:
            raise HTTPException(status_code=400, detail=f"Unknown setting: {key}")
        kv[key] = str(value) if not isinstance(value, str) else value
    if kv:
        set_settings(db, kv)
    return {"ok": True, "settings": get_public_settings(db)}


# ── Change Password (requires super admin key) ─────────────────────

@app.post("/admin/change-password")
def admin_change_password(
    body: ChangePasswordRequest,
    db: Session = Depends(get_db),
    _=Depends(verify_super_admin),
):
    if len(body.new_password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    pwd_hash, salt = hash_password(body.new_password)
    set_setting(db, "admin_password_hash", pwd_hash)
    set_setting(db, "admin_password_salt", salt)
    return {"ok": True, "message": "Admin password changed successfully"}


# ── Admin: Stats ────────────────────────────────────────────────────

@app.get("/admin/stats")
def admin_stats(
    db: Session = Depends(get_db),
    _=Depends(verify_admin),
):
    now = dt.datetime.now(dt.UTC)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + dt.timedelta(days=1)
    week_start = today_start - dt.timedelta(days=today_start.weekday())
    month_start = today_start.replace(day=1)

    def count_by_status(base_query, status_col=Appointment.status):
        total = base_query.count()
        scheduled = base_query.filter(status_col == "scheduled").count()
        completed = base_query.filter(status_col == "completed").count()
        no_show = base_query.filter(status_col == "no_show").count()
        cancelled = base_query.filter(status_col == "cancelled").count()
        return {
            "total": total,
            "scheduled": scheduled,
            "completed": completed,
            "no_show": no_show,
            "cancelled": cancelled,
        }

    base = db.query(Appointment)
    today = count_by_status(base.filter(Appointment.start_time >= today_start, Appointment.start_time < today_end))
    this_week = count_by_status(base.filter(Appointment.start_time >= week_start, Appointment.start_time < today_end))
    this_month = count_by_status(base.filter(Appointment.start_time >= month_start, Appointment.start_time < today_end))
    overall = count_by_status(base)

    daily_rows = (
        db.query(
            func.date(Appointment.start_time).label("date"),
            Appointment.status,
            func.count(Appointment.id).label("cnt"),
        )
        .where(Appointment.start_time >= today_start - dt.timedelta(days=13))
        .group_by(func.date(Appointment.start_time), Appointment.status)
        .order_by(func.date(Appointment.start_time))
        .all()
    )

    daily_map: dict[str, dict] = {}
    for row in daily_rows:
        d = str(row.date)
        if d not in daily_map:
            daily_map[d] = {"date": d, "total": 0, "scheduled": 0, "completed": 0, "no_show": 0, "cancelled": 0}
        daily_map[d][row.status] = row.cnt
        daily_map[d]["total"] += row.cnt

    return {
        "today": today,
        "this_week": this_week,
        "this_month": this_month,
        "overall": overall,
        "daily": sorted(daily_map.values(), key=lambda x: x["date"]),
    }


# ── Admin: List appointments ────────────────────────────────────────

class AppointmentOut(BaseModel):
    id: int
    patient_name: str
    reason: str | None
    start_time: dt.datetime
    status: str
    canceled: bool
    created_at: dt.datetime

    class Config:
        from_attributes = True


@app.get("/admin/appointments")
def admin_list_appointments(
    status: str | None = None,
    date_from: dt.date | None = None,
    date_to: dt.date | None = None,
    patient_name: str | None = None,
    page: int = 1,
    per_page: int = 50,
    db: Session = Depends(get_db),
    _=Depends(verify_admin),
):
    query = db.query(Appointment)

    if status:
        query = query.filter(Appointment.status == status)
    if date_from:
        query = query.filter(Appointment.start_time >= dt.datetime.combine(date_from, dt.time.min))
    if date_to:
        query = query.filter(Appointment.start_time < dt.datetime.combine(date_to, dt.time.max) + dt.timedelta(days=1))
    if patient_name:
        query = query.filter(Appointment.patient_name.ilike(f"%{patient_name}%"))

    total = query.count()
    appointments = (
        query.order_by(Appointment.start_time.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "appointments": [AppointmentOut.model_validate(a) for a in appointments],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


# ── Admin: Update status ────────────────────────────────────────────

@app.patch("/admin/appointments/{appointment_id}/status")
def admin_update_status(
    appointment_id: int,
    body: StatusUpdateRequest,
    db: Session = Depends(get_db),
    _=Depends(verify_admin),
):
    if body.status not in ("scheduled", "completed", "no_show", "cancelled"):
        raise HTTPException(status_code=400, detail="Invalid status. Use: scheduled, completed, no_show, cancelled")

    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")

    appointment.status = body.status
    if body.status == "cancelled":
        appointment.canceled = True
    db.commit()

    return {"ok": True, "status": appointment.status}


# ── Admin: Edit appointment ─────────────────────────────────────────

@app.put("/admin/appointments/{appointment_id}")
def admin_edit_appointment(
    appointment_id: int,
    body: AppointmentEditRequest,
    db: Session = Depends(get_db),
    _=Depends(verify_admin),
):
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")

    if body.patient_name is not None:
        appointment.patient_name = body.patient_name
    if body.reason is not None:
        appointment.reason = body.reason
    if body.start_time is not None:
        appointment.start_time = body.start_time

    db.commit()
    db.refresh(appointment)

    return AppointmentOut.model_validate(appointment)


# ── Schedule an appointment ─────────────────────────────────────────

@app.post("/schedule_appointment/")
def schedule_appointment(body: ScheduleRequest, db: Session = Depends(get_db)):
    existing = db.query(Appointment).filter(
        Appointment.start_time == body.start_time,
        Appointment.canceled == False,
    ).first()

    if existing:
        return {
            "result": (
                f"I'm sorry, but there is already an appointment "
                f"scheduled at {body.start_time.strftime('%I:%M %p on %B %d, %Y')}. "
                f"Could you please choose a different time?"
            )
        }

    clinic_name = get_setting(db, "clinic_name") or "the clinic"

    appointment = Appointment(
        patient_name=body.patient_name,
        reason=body.reason,
        start_time=body.start_time,
        status="scheduled",
    )
    db.add(appointment)
    db.commit()
    db.refresh(appointment)

    time_str = body.start_time.strftime("%I:%M %p on %B %d, %Y")
    return {
        "result": (
            f"Perfect, {body.patient_name}! Your appointment has been "
            f"scheduled for {time_str}. We look forward to seeing you at "
            f"{clinic_name}. Is there anything else I can help you with?"
        )
    }


# ── Cancel an appointment ───────────────────────────────────────────

@app.post("/cancel_appointment/")
def cancel_appointment(body: CancelRequest, db: Session = Depends(get_db)):
    start_dt = dt.datetime.combine(body.date, dt.time.min)
    end_dt = start_dt + dt.timedelta(days=1)

    appointments = db.query(Appointment).filter(
        Appointment.patient_name == body.patient_name,
        Appointment.start_time >= start_dt,
        Appointment.start_time < end_dt,
        Appointment.canceled == False,
    ).all()

    if not appointments:
        return {
            "result": (
                f"I couldn't find any appointment for {body.patient_name} "
                f"on {body.date.strftime('%B %d, %Y')}. Please check the name and date and try again."
            )
        }

    for a in appointments:
        a.canceled = True
        a.status = "cancelled"

    db.commit()

    names = ", ".join(a.start_time.strftime("%I:%M %p") for a in appointments)
    return {
        "result": (
            f"Alright, I've cancelled {len(appointments)} appointment(s) "
            f"for {body.patient_name} on {body.date.strftime('%B %d, %Y')} "
            f"at the following time(s): {names}. You're all set!"
        )
    }


# ── List appointments for a given date ──────────────────────────────

@app.post("/list_appointments/")
def list_appointments(body: ListRequest, db: Session = Depends(get_db)):
    start_dt = dt.datetime.combine(body.date, dt.time.min)
    end_dt = start_dt + dt.timedelta(days=1)

    appointments = db.query(Appointment).filter(
        Appointment.canceled == False,
        Appointment.start_time >= start_dt,
        Appointment.start_time < end_dt,
    ).order_by(Appointment.start_time.asc()).all()

    if not appointments:
        return {
            "result": (
                f"There are no appointments scheduled "
                f"for {body.date.strftime('%B %d, %Y')}. The day is completely free!"
            )
        }

    lines = [
        f"{a.start_time.strftime('%I:%M %p')} — {a.patient_name}"
        + (f" ({a.reason})" if a.reason else "")
        for a in appointments
    ]
    summary = "\n".join(lines)

    return {
        "result": (
            f"Here are the appointments for {body.date.strftime('%B %d, %Y')}:\n{summary}\n"
            f"That's {len(appointments)} appointment(s) in total."
        )
    }


# ── Run ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend:app", host="0.0.0.0", port=8000)
