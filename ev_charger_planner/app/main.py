import os
import sqlite3
import hashlib
import secrets
import ipaddress
import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(title="EV Ladeplaner")

DATA_DIR = "/data" if os.path.exists("/data") else "./data"
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "planner.db")

SECRET_FILE = os.path.join(DATA_DIR, ".secret_key")
if os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "r") as f:
        SECRET_KEY = f.read().strip()
else:
    SECRET_KEY = secrets.token_hex(32)
    with open(SECRET_FILE, "w") as f:
        f.write(SECRET_KEY)

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
templates = Jinja2Templates(directory="templates")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    salt = "ev_planner_salt_2026"
    return hashlib.sha256((salt + password).encode()).hexdigest()


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('company_cidrs', '192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('allow_remote_global', '0')")

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_approved INTEGER DEFAULT 0,
            allow_remote INTEGER DEFAULT 0,
            car_model TEXT DEFAULT 'Standard E-Auto',
            battery_kwh REAL DEFAULT 60.0,
            max_charge_kw REAL DEFAULT 11.0
        )
    """)

    # Neue Tabelle für mehrere Fahrzeuge pro Benutzer
    c.execute("""
        CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            car_model TEXT NOT NULL,
            battery_kwh REAL NOT NULL,
            max_charge_kw REAL NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS chargers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            max_kw REAL DEFAULT 11.0,
            ha_entity_id TEXT DEFAULT NULL
        )
    """)
    c.execute("SELECT COUNT(*) as cnt FROM chargers")
    if c.fetchone()["cnt"] == 0:
        c.execute("INSERT INTO chargers (name, max_kw) VALUES ('Ladestation 1 (Links)', 11.0)")
        c.execute("INSERT INTO chargers (name, max_kw) VALUES ('Ladestation 2 (Rechts)', 11.0)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            charger_id INTEGER NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            soc_start INTEGER DEFAULT 20,
            soc_target INTEGER DEFAULT 80,
            note TEXT DEFAULT '',
            car_model TEXT DEFAULT '',
            max_charge_kw REAL DEFAULT 11.0,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(charger_id) REFERENCES chargers(id)
        )
    """)

    # Migration für bestehende Datenbanken (Spalten nachrüsten falls nötig)
    cols = [row[1] for row in c.execute("PRAGMA table_info(bookings)").fetchall()]
    if "car_model" not in cols:
        c.execute("ALTER TABLE bookings ADD COLUMN car_model TEXT DEFAULT ''")
    if "max_charge_kw" not in cols:
        c.execute("ALTER TABLE bookings ADD COLUMN max_charge_kw REAL DEFAULT 11.0")

    # Standard-Admin anlegen falls leer
    c.execute("SELECT COUNT(*) as cnt FROM users")
    if c.fetchone()["cnt"] == 0:
        c.execute("""
            INSERT INTO users (username, full_name, password_hash, is_admin, is_approved, allow_remote, car_model, battery_kwh, max_charge_kw)
            VALUES (?, ?, ?, 1, 1, 1, 'Admin E-Auto', 77.0, 11.0)
        """, ("admin", "Administrator", hash_password("admin123")))

    # Bestehende User-Autos automatisch in die vehicles-Tabelle übernehmen, falls User noch kein Fahrzeug dort hat
    users = c.execute("SELECT * FROM users").fetchall()
    for u in users:
        v_cnt = c.execute("SELECT COUNT(*) as cnt FROM vehicles WHERE user_id = ?", (u["id"],)).fetchone()["cnt"]
        if v_cnt == 0:
            c.execute("""
                INSERT INTO vehicles (user_id, car_model, battery_kwh, max_charge_kw)
                VALUES (?, ?, ?, ?)
            """, (u["id"], u["car_model"], u["battery_kwh"], u["max_charge_kw"]))

    conn.commit()
    conn.close()


init_db()


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def is_company_network(ip_str: str, cidrs_str: str) -> bool:
    try:
        if ip_str.startswith("172.30.32.") or ip_str == "127.0.0.1":
            return False
        ip = ipaddress.ip_address(ip_str)
        for cidr in cidrs_str.split(","):
            cidr = cidr.strip()
            if cidr and ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def get_settings(conn):
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


def get_current_user(request: Request, conn):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def base_path(request: Request) -> str:
    return request.headers.get("X-Ingress-Path", "")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, msg: Optional[str] = None, err: Optional[str] = None):
    conn = get_db()
    settings = get_settings(conn)
    user = get_current_user(request, conn)
    bp = base_path(request)
    client_ip = get_client_ip(request)
    in_company = is_company_network(client_ip, settings.get("company_cidrs", ""))

    access_denied_remote = False
    if user:
        global_remote = settings.get("allow_remote_global") == "1"
        if not in_company and not (user["is_admin"] or user["allow_remote"] or global_remote):
            access_denied_remote = True

    chargers = conn.execute("SELECT * FROM chargers").fetchall()

    # Buchungen für den Kalender laden (letzte 14 Tage bis +7 Tage)
    now = datetime.now()
    history_window = (now - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M")
    raw_bookings = conn.execute("""
        SELECT b.*, u.full_name,
               COALESCE(NULLIF(b.car_model, ''), u.car_model) as display_car,
               COALESCE(NULLIF(b.max_charge_kw, 0), u.max_charge_kw) as display_kw,
               c.name as charger_name
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN chargers c ON b.charger_id = c.id
        WHERE b.end_time >= ?
        ORDER BY b.start_time ASC
    """, (history_window,)).fetchall()

    bookings_list = [dict(b) for b in raw_bookings]

    user_vehicles = []
    if user:
        user_vehicles = [dict(v) for v in conn.execute("SELECT * FROM vehicles WHERE user_id = ? ORDER BY id ASC", (user["id"],)).fetchall()]

    all_users = []
    if user and user["is_admin"]:
        users_rows = conn.execute("SELECT * FROM users ORDER BY is_approved ASC, full_name ASC").fetchall()
        for u in users_rows:
            u_dict = dict(u)
            u_dict["vehicles"] = [dict(v) for v in conn.execute("SELECT * FROM vehicles WHERE user_id = ? ORDER BY id ASC", (u["id"],)).fetchall()]
            all_users.append(u_dict)

    conn.close()

    default_start = (now + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M")
    max_start = (now + timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M")

    return templates.TemplateResponse("index.html", {
        "request": request,
        "base_path": bp,
        "user": user,
        "user_vehicles": user_vehicles,
        "user_vehicles_json": json.dumps(user_vehicles),
        "chargers": chargers,
        "bookings": bookings_list,
        "bookings_json": json.dumps(bookings_list),
        "all_users": all_users,
        "settings": settings,
        "client_ip": client_ip,
        "in_company": in_company,
        "access_denied_remote": access_denied_remote,
        "default_start": default_start,
        "max_start": max_start,
        "now_iso": now.strftime("%Y-%m-%dT%H:%M"),
        "msg": msg,
        "err": err
    })


@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    bp = base_path(request)
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip().lower(),)).fetchone()
    conn.close()

    if not user or user["password_hash"] != hash_password(password):
        return RedirectResponse(f"{bp}/?err=Benutzername+oder+Passwort+falsch", status_code=303)

    if not user["is_approved"]:
        return RedirectResponse(f"{bp}/?err=Dein+Account+wartet+noch+auf+Admin-Freischaltung", status_code=303)

    request.session["user_id"] = user["id"]
    return RedirectResponse(f"{bp}/", status_code=303)


@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    car_model: str = Form(...),
    battery_kwh: float = Form(...),
    max_charge_kw: float = Form(...)
):
    bp = base_path(request)
    if password != password_confirm:
        return RedirectResponse(f"{bp}/?err=Die+beiden+Passwörter+stimmen+nicht+überein!", status_code=303)
    if len(password) < 4:
        return RedirectResponse(f"{bp}/?err=Passwort+muss+mindestens+4+Zeichen+lang+sein", status_code=303)

    conn = get_db()
    try:
        cur = conn.cursor()
        b_kwh = max(1.0, min(200.0, battery_kwh))
        m_kw = max(1.0, min(22.0, max_charge_kw))
        cur.execute("""
            INSERT INTO users (username, full_name, password_hash, is_admin, is_approved, allow_remote, car_model, battery_kwh, max_charge_kw)
            VALUES (?, ?, ?, 0, 0, 0, ?, ?, ?)
        """, (
            username.strip().lower(),
            full_name.strip(),
            hash_password(password),
            car_model.strip(),
            b_kwh,
            m_kw
        ))
        new_user_id = cur.lastrowid
        cur.execute("""
            INSERT INTO vehicles (user_id, car_model, battery_kwh, max_charge_kw)
            VALUES (?, ?, ?, ?)
        """, (new_user_id, car_model.strip(), b_kwh, m_kw))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return RedirectResponse(f"{bp}/?err=Benutzername+ist+bereits+vergeben", status_code=303)
    conn.close()
    return RedirectResponse(f"{bp}/?msg=Registrierung+erfolgreich!+Bitte+warte+auf+Freischaltung+durch+den+Admin.", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    bp = base_path(request)
    request.session.clear()
    return RedirectResponse(f"{bp}/", status_code=303)


@app.post("/vehicles/add")
async def add_vehicle(
    request: Request,
    car_model: str = Form(...),
    battery_kwh: float = Form(...),
    max_charge_kw: float = Form(...),
    target_user_id: Optional[int] = Form(None)
):
    conn = get_db()
    bp = base_path(request)
    user = get_current_user(request, conn)
    if user:
        owner_id = user["id"]
        if target_user_id and user["is_admin"]:
            owner_id = target_user_id
        conn.execute("""
            INSERT INTO vehicles (user_id, car_model, battery_kwh, max_charge_kw)
            VALUES (?, ?, ?, ?)
        """, (owner_id, car_model.strip(), max(1.0, min(200.0, battery_kwh)), max(1.0, min(22.0, max_charge_kw))))
        conn.commit()
    conn.close()
    return RedirectResponse(f"{bp}/?msg=Fahrzeug+hinzugefügt", status_code=303)


@app.post("/vehicles/{vehicle_id}/delete")
async def delete_vehicle(request: Request, vehicle_id: int):
    conn = get_db()
    bp = base_path(request)
    user = get_current_user(request, conn)
    if user:
        veh = conn.execute("SELECT * FROM vehicles WHERE id = ?", (vehicle_id,)).fetchone()
        if veh and (veh["user_id"] == user["id"] or user["is_admin"]):
            cnt = conn.execute("SELECT COUNT(*) as cnt FROM vehicles WHERE user_id = ?", (veh["user_id"],)).fetchone()["cnt"]
            if cnt <= 1:
                conn.close()
                return RedirectResponse(f"{bp}/?err=Mindestens+ein+Fahrzeug+muss+hinterlegt+bleiben", status_code=303)
            conn.execute("DELETE FROM vehicles WHERE id = ?", (vehicle_id,))
            conn.commit()
    conn.close()
    return RedirectResponse(f"{bp}/?msg=Fahrzeug+entfernt", status_code=303)


@app.post("/book")
async def create_booking(
    request: Request,
    charger_id: int = Form(...),
    vehicle_id: int = Form(...),
    start_time: str = Form(...),
    soc_start: int = Form(...),
    soc_target: int = Form(...),
    note: str = Form("")
):
    conn = get_db()
    bp = base_path(request)
    user = get_current_user(request, conn)
    if not user or not user["is_approved"]:
        conn.close()
        return RedirectResponse(f"{bp}/?err=Nicht+autorisiert", status_code=303)

    vehicle = conn.execute("SELECT * FROM vehicles WHERE id = ? AND user_id = ?", (vehicle_id, user["id"])).fetchone()
    if not vehicle:
        conn.close()
        return RedirectResponse(f"{bp}/?err=Bitte+ein+gültiges+Fahrzeug+auswählen", status_code=303)

    try:
        dt_start = datetime.strptime(start_time, "%Y-%m-%dT%H:%M")
    except ValueError:
        conn.close()
        return RedirectResponse(f"{bp}/?err=Ungültiges+Datumsformat", status_code=303)

    now = datetime.now()
    if dt_start < now - timedelta(minutes=15):
        conn.close()
        return RedirectResponse(f"{bp}/?err=Startzeit+darf+nicht+in+der+Vergangenheit+liegen", status_code=303)

    if dt_start > now + timedelta(hours=48):
        conn.close()
        return RedirectResponse(f"{bp}/?err=Buchungen+sind+maximal+2+Tage+(48h)+im+Voraus+möglich!", status_code=303)

    if soc_target <= soc_start:
        conn.close()
        return RedirectResponse(f"{bp}/?err=Ziel-Ladestand+muss+höher+als+Start-Ladestand+sein", status_code=303)

    charger = conn.execute("SELECT * FROM chargers WHERE id = ?", (charger_id,)).fetchone()
    if not charger:
        conn.close()
        return RedirectResponse(f"{bp}/?err=Ladestation+nicht+gefunden", status_code=303)

    needed_kwh = vehicle["battery_kwh"] * ((soc_target - soc_start) / 100.0)
    effective_kw = min(charger["max_kw"], vehicle["max_charge_kw"])
    duration_hours = (needed_kwh / effective_kw) * 1.10
    duration_minutes = max(30, int(round(duration_hours * 60)))
    dt_end = dt_start + timedelta(minutes=duration_minutes)

    start_str = dt_start.strftime("%Y-%m-%dT%H:%M")
    end_str = dt_end.strftime("%Y-%m-%dT%H:%M")

    conflict = conn.execute("""
        SELECT b.*, u.full_name FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.charger_id = ?
          AND b.start_time < ?
          AND b.end_time > ?
    """, (charger_id, end_str, start_str)).fetchone()

    if conflict:
        conn.close()
        return RedirectResponse(
            f"{bp}/?err=Überschneidung!+Säule+ist+belegt+durch+{conflict['full_name']}+bis+{conflict['end_time'].replace('T', '+')}",
            status_code=303
        )

    conn.execute("""
        INSERT INTO bookings (user_id, charger_id, start_time, end_time, soc_start, soc_target, note, car_model, max_charge_kw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user["id"], charger_id, start_str, end_str, soc_start, soc_target, note.strip(), vehicle["car_model"], vehicle["max_charge_kw"]))
    conn.commit()
    conn.close()

    return RedirectResponse(f"{bp}/?msg=Ladeslot+für+{vehicle['car_model']}+gebucht+({duration_minutes}+Minuten)", status_code=303)


@app.post("/booking/{booking_id}/delete")
async def delete_booking(request: Request, booking_id: int):
    conn = get_db()
    bp = base_path(request)
    user = get_current_user(request, conn)
    if user:
        if user["is_admin"]:
            conn.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
        else:
            conn.execute("DELETE FROM bookings WHERE id = ? AND user_id = ?", (booking_id, user["id"]))
        conn.commit()
    conn.close()
    return RedirectResponse(f"{bp}/?msg=Buchung+gelöscht", status_code=303)


@app.post("/admin/user/{target_id}/toggle")
async def admin_toggle_user(request: Request, target_id: int, field: str = Form(...)):
    conn = get_db()
    bp = base_path(request)
    user = get_current_user(request, conn)
    if user and user["is_admin"] and field in ("is_approved", "allow_remote", "is_admin"):
        if not (target_id == user["id"] and field in ("is_admin", "is_approved")):
            conn.execute(f"UPDATE users SET {field} = 1 - {field} WHERE id = ?", (target_id,))
            conn.commit()
    conn.close()
    return RedirectResponse(f"{bp}/?msg=Benutzerstatus+aktualisiert", status_code=303)


@app.post("/admin/user/{target_id}/delete")
async def admin_delete_user(request: Request, target_id: int):
    conn = get_db()
    bp = base_path(request)
    user = get_current_user(request, conn)
    if user and user["is_admin"] and target_id != user["id"]:
        conn.execute("DELETE FROM bookings WHERE user_id = ?", (target_id,))
        conn.execute("DELETE FROM vehicles WHERE user_id = ?", (target_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
        conn.commit()
    conn.close()
    return RedirectResponse(f"{bp}/?msg=Benutzer+entfernt", status_code=303)


@app.post("/admin/settings")
async def admin_settings(
    request: Request,
    company_cidrs: str = Form(...),
    allow_remote_global: Optional[str] = Form(None)
):
    conn = get_db()
    bp = base_path(request)
    user = get_current_user(request, conn)
    if user and user["is_admin"]:
        conn.execute("UPDATE settings SET value = ? WHERE key = 'company_cidrs'", (company_cidrs.strip(),))
        conn.execute("UPDATE settings SET value = ? WHERE key = 'allow_remote_global'", ("1" if allow_remote_global else "0",))
        conn.commit()
    conn.close()
    return RedirectResponse(f"{bp}/?msg=Netzwerk-Einstellungen+gespeichert", status_code=303)
