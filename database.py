import os
from collections.abc import Generator
import datetime as dt
import hashlib
import secrets
import json

from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./appointments_db.db",
)

_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Appointment(Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, index=True)
    patient_name = Column(String, index=True)
    reason = Column(String, nullable=True)
    start_time = Column(DateTime, index=True)
    canceled = Column(Boolean, default=False)
    status = Column(String, default="scheduled")
    created_at = Column(DateTime, default=dt.datetime.now(dt.UTC))


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String, primary_key=True)
    value = Column(String, nullable=True)


class SessionToken(Base):
    __tablename__ = "sessions"

    token = Column(String, primary_key=True)
    created_at = Column(DateTime, default=dt.datetime.now(dt.UTC))


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _migrate_existing_data()


def _migrate_existing_data() -> None:
    with engine.begin() as conn:
        if engine.dialect.name == "sqlite":
            result = conn.execute(text("PRAGMA table_info(appointments)"))
            cols = [row[1] for row in result.fetchall()]
            if "status" not in cols:
                conn.execute(text("ALTER TABLE appointments ADD COLUMN status VARCHAR DEFAULT 'scheduled'"))
        else:
            conn.execute(
                text("ALTER TABLE appointments ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'scheduled'")
            )

        conn.execute(
            text(
                "UPDATE appointments SET status = 'cancelled' "
                "WHERE status IS NULL AND canceled = TRUE"
            )
        )
        conn.execute(
            text(
                "UPDATE appointments SET status = 'scheduled' "
                "WHERE status IS NULL AND canceled = FALSE"
            )
        )


def get_db() -> Generator[Session, None, None]:
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Settings helpers ───────────────────────────────────────────────

def get_setting(db: Session, key: str, default: str | None = None) -> str | None:
    s = db.query(Setting).filter(Setting.key == key).first()
    return s.value if s else default


def set_setting(db: Session, key: str, value: str) -> None:
    s = db.query(Setting).filter(Setting.key == key).first()
    if s:
        s.value = value
    else:
        db.add(Setting(key=key, value=value))
    db.commit()


def set_settings(db: Session, kv: dict[str, str]) -> None:
    for key, value in kv.items():
        s = db.query(Setting).filter(Setting.key == key).first()
        if s:
            s.value = str(value)
        else:
            db.add(Setting(key=key, value=str(value)))
    db.commit()


def get_all_settings(db: Session) -> dict[str, str]:
    rows = db.query(Setting).all()
    return {r.key: r.value for r in rows}


# ── Password helpers ──────────────────────────────────────────────

def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return pwd_hash.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return secrets.compare_digest(pwd_hash.hex(), stored_hash)


# ── Session helpers ───────────────────────────────────────────────

def create_session(db: Session) -> str:
    token = secrets.token_hex(32)
    db.add(SessionToken(token=token))
    db.commit()
    return token


def get_session(db: Session, token: str) -> SessionToken | None:
    return db.query(SessionToken).filter(SessionToken.token == token).first()


def delete_session(db: Session, token: str) -> None:
    db.query(SessionToken).filter(SessionToken.token == token).delete()
    db.commit()


# ── Public settings (for frontend) ────────────────────────────────

def get_public_settings(db: Session) -> dict:
    all_ = get_all_settings(db)
    keys = [
        "clinic_name", "clinic_address", "clinic_phone", "clinic_email",
        "clinic_hours", "brand_primary_color", "brand_accent_color",
        "vapi_assistant_id", "vapi_public_key", "custom_domain",
    ]
    result = {}
    for k in keys:
        val = all_.get(k)
        if k == "clinic_hours" and val:
            try:
                result[k] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                result[k] = val
        else:
            result[k] = val or ""
    result["setup_complete"] = "admin_password_hash" in all_
    return result
