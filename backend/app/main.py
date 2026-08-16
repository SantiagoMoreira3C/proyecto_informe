from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://altura:altura@postgres:5432/altura_nexo",
)
JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-secret")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"
MONTHS = {
    1: "ENE",
    2: "FEB",
    3: "MAR",
    4: "ABR",
    5: "MAY",
    6: "JUN",
    7: "JUL",
    8: "AGO",
    9: "SEP",
    10: "OCT",
    11: "NOV",
    12: "DIC",
}
ALLOWED_EXTENSIONS = {".xlsx", ".xls", ".pdf", ".jpg", ".jpeg", ".png"}

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="user")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(RegisterRequest):
    pass


class ReportRow(BaseModel):
    actividad: str = ""
    cliente: str = ""
    fecha_desde: str = ""
    fecha_hasta: str = ""
    descripcion: str = ""


class ReportRequest(BaseModel):
    month: int = Field(ge=1, le=12)
    year: int = Field(ge=2000, le=2100)
    person: str = "GENERAL"
    rows: list[ReportRow] = Field(default_factory=list)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180_000)
    return f"pbkdf2_sha256$180000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def create_token(user: User) -> str:
    return jwt.encode(
        {"sub": str(user.id), "username": user.username, "role": user.role, "exp": int(time.time()) + 86_400},
        JWT_SECRET,
        algorithm="HS256",
    )


def current_user(token: str | None, db: Session) -> User:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión requerida")
    try:
        payload = jwt.decode(token.removeprefix("Bearer "), JWT_SECRET, algorithms=["HS256"])
        user = db.get(User, int(payload["sub"]))
    except (jwt.InvalidTokenError, KeyError, ValueError):
        user = None
    if not user or not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión no válida")
    return user


def normalize_person(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", value.upper()).strip("_")
    return value or "SIN_PERSONA"


def normalized_filename(filename: str, month: int, year: int) -> tuple[str, str | None]:
    original = Path(filename).name
    extension = Path(original).suffix.lower()
    stem = Path(original).stem.upper().replace("–", "-").replace("_", "-")
    parts = [part for part in stem.split("-") if part]
    person = "SIN_PERSONA"
    warning = None
    if len(parts) >= 6 and parts[0] in {"ALT", "AT"}:
        person = normalize_person("_".join(parts[5:]))
        if parts[0] != "ALT":
            warning = "El prefijo fue normalizado a ALT."
        if parts[4] != str(year) or parts[3] != MONTHS[month]:
            warning = "El nombre del archivo no coincide con el mes/año seleccionado."
    else:
        warning = "El nombre no sigue el formato ALT-INF-ACT-PER-MES-AÑO-NOMBRE_APELLIDO."
    return f"ALT-INF-ACT-PER-{MONTHS[month]}-{year}-{person}{extension}", warning


def ensure_database() -> None:
    for _ in range(20):
        try:
            Base.metadata.create_all(engine)
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError("No se pudo conectar con PostgreSQL")


app = FastAPI(title="ALTURA NEXO API", version="0.1.0")
origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "http://localhost:6000").split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    ensure_database()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "altura-nexo-api"}


@app.get("/api/bootstrap-status")
def bootstrap_status(db: Session = Depends(get_db)) -> dict[str, bool]:
    return {"needs_registration": db.scalar(select(User.id).limit(1)) is None}


@app.get("/api/users")
def users(db: Session = Depends(get_db)) -> list[dict[str, str | int]]:
    return [
        {"id": user.id, "username": user.username, "role": user.role}
        for user in db.scalars(select(User).where(User.active.is_(True)).order_by(User.username)).all()
    ]


@app.post("/api/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    if db.scalar(select(User.id).limit(1)) is not None:
        raise HTTPException(status_code=403, detail="El registro inicial ya fue realizado")
    username = payload.username.strip().lower()
    user = User(username=username, password_hash=hash_password(payload.password), role="admin")
    db.add(user)
    db.commit()
    return {"message": "Usuario administrador creado"}


@app.post("/api/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    user = db.scalar(select(User).where(User.username == payload.username.strip().lower()))
    if not user or not user.active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    return {"access_token": create_token(user), "user": {"id": user.id, "username": user.username, "role": user.role}}


@app.post("/api/uploads")
async def upload_files(
    month: Annotated[int, Form(ge=1, le=12)],
    year: Annotated[int, Form(ge=2000, le=2100)],
    files: list[UploadFile] = File(...),
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    current_user(authorization, db)
    current_year = datetime.now().year
    warnings: list[str] = []
    saved: list[dict[str, str]] = []
    target = UPLOAD_DIR / str(year) / f"{month:02d}"
    target.mkdir(parents=True, exist_ok=True)
    for index, upload in enumerate(files, start=1):
        extension = Path(upload.filename or "").suffix.lower()
        if extension not in ALLOWED_EXTENSIONS:
            warnings.append(f"{upload.filename}: tipo de archivo no permitido.")
            continue
        name, warning = normalized_filename(upload.filename or f"documento-{index}", month, year)
        destination = target / f"{index:03d}-{name}"
        destination.write_bytes(await upload.read())
        if warning:
            warnings.append(f"{upload.filename}: {warning}")
        saved.append({"original": upload.filename or "", "stored": str(destination.relative_to(DATA_DIR))})
    if year != current_year:
        warnings.append(f"El año seleccionado es {year}; el año actual es {current_year}.")
    return {"month": MONTHS[month], "year": year, "saved": saved, "warnings": warnings}


@app.post("/api/reports/generate")
def generate_report(
    payload: ReportRequest,
    db: Session = Depends(get_db),
    authorization: Annotated[str | None, Header()] = None,
):
    current_user(authorization, db)
    person = normalize_person(payload.person)
    filename = f"ALT-INF-RES-PER-{MONTHS[payload.month]}-{payload.year}-{person}.xlsx"
    destination = REPORT_DIR / str(payload.year) / f"{payload.month:02d}" / filename
    destination.parent.mkdir(parents=True, exist_ok=True)

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Resumen"
    headers = ["No.", "Actividad", "Cliente/Proyecto/Servicio", "Fecha desde", "Fecha hasta", "Descripción"]
    sheet.append(headers)
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="176B87")
    for index, row in enumerate(payload.rows, start=1):
        sheet.append([index, row.actividad, row.cliente, row.fecha_desde, row.fecha_hasta, row.descripcion])
    widths = [8, 30, 30, 16, 16, 60]
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[chr(64 + index)].width = width
    sheet.freeze_panes = "A2"
    workbook.save(destination)
    return FileResponse(
        destination,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=filename,
    )
