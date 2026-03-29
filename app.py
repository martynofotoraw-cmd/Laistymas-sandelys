from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, jsonify, g
)
import os
import sqlite3
from datetime import datetime, timedelta
import csv
import io
import shutil
import threading
import time
import traceback
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "DEV_ONLY_SECRET_CHANGE_ME")

DB = os.environ.get("DB_PATH", "database.db")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "backups")

PAGRINDINIS = "PAGRINDINIS"
ISORINIS = "ISORINIS"

INACTIVITY_MINUTES = 30
AUTO_BACKUP_EVERY_MINUTES = 60

DEFAULT_ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123!")


def gauti_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def dabar():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_dirs():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def init_db():
    ensure_dirs()
    conn = gauti_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS produktai (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pavadinimas TEXT NOT NULL,
        barkodas TEXT UNIQUE,
        matas TEXT NOT NULL,
        min_kiekis REAL NOT NULL DEFAULT 0
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS likutis (
        produkto_id INTEGER NOT NULL,
        vieta TEXT NOT NULL,
        kiekis REAL NOT NULL DEFAULT 0,
        PRIMARY KEY (produkto_id, vieta)
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS judejimai (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        produkto_id INTEGER NOT NULL,
        tipas TEXT NOT NULL,
        is_kur TEXT,
        i_kur TEXT,
        kiekis REAL NOT NULL,
        data TEXT NOT NULL,
        pastaba TEXT,
        atsauktas INTEGER NOT NULL DEFAULT 0,
        atsauke_judejima_id INTEGER,
        user_id INTEGER
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS vartotojai (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'darbuotojas')),
        active INTEGER NOT NULL DEFAULT 1,
        must_change_password INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_logai (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS error_logai (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        page TEXT,
        error_message TEXT,
        stack_trace TEXT,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS prisijungimu_istorija (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        sekmingas INTEGER NOT NULL,
        ip_adresas TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    conn.commit()

    # migracijos senai DB
    try:
        c.execute("ALTER TABLE judejimai ADD COLUMN atsauktas INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    except:
        pass

    try:
        c.execute("ALTER TABLE judejimai ADD COLUMN atsauke_judejima_id INTEGER")
        conn.commit()
    except:
        pass

    try:
        c.execute("ALTER TABLE judejimai ADD COLUMN user_id INTEGER")
        conn.commit()
    except:
        pass

    try:
        c.execute("ALTER TABLE produktai ADD COLUMN barkodas TEXT UNIQUE")
        conn.commit()
    except:
        pass

    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('system_locked', '0')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('backup_interval_minutes', ?)", (str(AUTO_BACKUP_EVERY_MINUTES),))
    conn.commit()

    c.execute("SELECT COUNT(*) AS cnt FROM vartotojai")
    cnt = c.fetchone()["cnt"]
    if cnt == 0:
        c.execute("""
        INSERT INTO vartotojai (username, password_hash, role, active, must_change_password, created_at)
        VALUES (?, ?, 'admin', 1, 1, ?)
        """, (
            DEFAULT_ADMIN_USERNAME,
            generate_password_hash(DEFAULT_ADMIN_PASSWORD),
            dabar()
        ))
        conn.commit()

    conn.close()


def get_setting(key, default=""):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (key, str(value)))
    conn.commit()
    conn.close()


def system_locked():
    return get_setting("system_locked", "0") == "1"


def current_user_id():
    return session.get("user_id")


def current_username():
    return session.get("username")


def log_audit(action, details=""):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    INSERT INTO audit_logai (user_id, action, details, created_at)
    VALUES (?, ?, ?, ?)
    """, (current_user_id(), action, details, dabar()))
    conn.commit()
    conn.close()


def log_error(page, error_message, stack_trace=""):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    INSERT INTO error_logai (user_id, username, page, error_message, stack_trace, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        current_user_id(),
        current_username(),
        page,
        error_message,
        stack_trace,
        dabar()
    ))
    conn.commit()
    conn.close()


def log_login_attempt(username, sekmingas):
    conn = gauti_conn()
    c = conn.cursor()

    user_id = None
    c.execute("SELECT id FROM vartotojai WHERE username = ?", (username,))
    row = c.fetchone()
    if row:
        user_id = row["id"]

    c.execute("""
    INSERT INTO prisijungimu_istorija (user_id, username, sekmingas, ip_adresas, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        username,
        1 if sekmingas else 0,
        request.remote_addr,
        request.headers.get("User-Agent", "")[:500],
        dabar()
    ))
    conn.commit()
    conn.close()


def gauti_vartotoja_pagal_username(username):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM vartotojai WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row


def gauti_vartotojus():
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM vartotojai ORDER BY username")
    rows = c.fetchall()
    conn.close()
    return rows


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))

        last_activity = session.get("last_activity")
        if last_activity:
            last_dt = datetime.fromisoformat(last_activity)
            if datetime.now() - last_dt > timedelta(minutes=INACTIVITY_MINUTES):
                session.clear()
                return redirect(url_for("login", message="Sesija baigėsi dėl neaktyvumo."))

        session["last_activity"] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect(url_for("dashboard", message="Neturi teisių."))
        return f(*args, **kwargs)
    return wrapper


def gauti_kieki(produkto_id, vieta):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT kiekis FROM likutis WHERE produkto_id = ? AND vieta = ?", (produkto_id, vieta))
    row = c.fetchone()
    conn.close()
    return float(row["kiekis"]) if row else 0.0


def nustatyti_kieki(produkto_id, vieta, kiekis):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    INSERT INTO likutis (produkto_id, vieta, kiekis)
    VALUES (?, ?, ?)
    ON CONFLICT(produkto_id, vieta)
    DO UPDATE SET kiekis = excluded.kiekis
    """, (produkto_id, vieta, kiekis))
    conn.commit()
    conn.close()


def pakeisti_kieki(produkto_id, vieta, pokytis):
    dabartinis = gauti_kieki(produkto_id, vieta)
    naujas = dabartinis + pokytis
    if naujas < 0:
        return False
    nustatyti_kieki(produkto_id, vieta, naujas)
    return True


def registruoti_judejima(produkto_id, tipas, is_kur, i_kur, kiekis, pastaba="", atsauke_judejima_id=None):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    INSERT INTO judejimai (
        produkto_id, tipas, is_kur, i_kur, kiekis, data, pastaba, atsauke_judejima_id, user_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        produkto_id, tipas, is_kur, i_kur, kiekis, dabar(), pastaba, atsauke_judejima_id, current_user_id()
    ))
    conn.commit()
    conn.close()


def prideti_produkta(pavadinimas, barkodas, matas, min_kiekis):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    INSERT INTO produktai (pavadinimas, barkodas, matas, min_kiekis)
    VALUES (?, ?, ?, ?)
    """, (pavadinimas, barkodas if barkodas else None, matas, min_kiekis))
    produkto_id = c.lastrowid
    conn.commit()
    conn.close()

    nustatyti_kieki(produkto_id, PAGRINDINIS, 0)
    nustatyti_kieki(produkto_id, ISORINIS, 0)
    log_audit("PRIDETAS_PRODUKTAS", pavadinimas)


def redaguoti_produkta(produkto_id, pavadinimas, barkodas, matas, min_kiekis):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    UPDATE produktai
    SET pavadinimas = ?, barkodas = ?, matas = ?, min_kiekis = ?
    WHERE id = ?
    """, (pavadinimas, barkodas if barkodas else None, matas, min_kiekis, produkto_id))
    conn.commit()
    conn.close()
    log_audit("REDAGUOTAS_PRODUKTAS", f"ID {produkto_id}")


def istrinti_produkta(produkto_id):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT pavadinimas FROM produktai WHERE id = ?", (produkto_id,))
    row = c.fetchone()
    pavadinimas = row["pavadinimas"] if row else f"ID {produkto_id}"

    c.execute("DELETE FROM judejimai WHERE produkto_id = ?", (produkto_id,))
    c.execute("DELETE FROM likutis WHERE produkto_id = ?", (produkto_id,))
    c.execute("DELETE FROM produktai WHERE id = ?", (produkto_id,))
    conn.commit()
    conn.close()

    log_audit("ISTRINTAS_PRODUKTAS", pavadinimas)
    return "Produktas pilnai ištrintas."


def gauti_produkta(produkto_id):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM produktai WHERE id = ?", (produkto_id,))
    row = c.fetchone()
    conn.close()
    return row


def gauti_produkta_pagal_barkoda(barkodas):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM produktai WHERE barkodas = ?", (barkodas,))
    row = c.fetchone()
    conn.close()
    return row


def gauti_produktus(paieska=""):
    conn = gauti_conn()
    c = conn.cursor()
    if paieska.strip():
        q = f"%{paieska.strip()}%"
        c.execute("""
        SELECT * FROM produktai
        WHERE pavadinimas LIKE ? OR barkodas LIKE ?
        ORDER BY pavadinimas
        """, (q, q))
    else:
        c.execute("SELECT * FROM produktai ORDER BY pavadinimas")
    rows = c.fetchall()
    conn.close()
    return rows


def gauti_inventoriu(paieska=""):
    produktai = gauti_produktus(paieska)
    result = []
    for p in produktai:
        result.append({
            "id": p["id"],
            "pavadinimas": p["pavadinimas"],
            "barkodas": p["barkodas"] or "",
            "matas": p["matas"],
            "min_kiekis": p["min_kiekis"],
            "pagrindinis": gauti_kieki(p["id"], PAGRINDINIS),
            "isorinis": gauti_kieki(p["id"], ISORINIS),
        })
    return result


def gauti_mazo_likucio_produktus():
    inventorius = gauti_inventoriu()
    return [p for p in inventorius if p["pagrindinis"] <= p["min_kiekis"]]


def gauti_judejimus(limit=200):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    SELECT j.*, p.pavadinimas, v.username AS atliko_vartotojas
    FROM judejimai j
    JOIN produktai p ON p.id = j.produkto_id
    LEFT JOIN vartotojai v ON v.id = j.user_id
    ORDER BY j.id DESC
    LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


def parduoti(produkto_id, kiekis):
    if kiekis <= 0:
        return "Kiekis turi būti didesnis už 0."
    dabartinis = gauti_kieki(produkto_id, PAGRINDINIS)
    if dabartinis < kiekis:
        return "Nepakanka kiekio pagrindiniame sandėlyje."
    nustatyti_kieki(produkto_id, PAGRINDINIS, dabartinis - kiekis)
    registruoti_judejima(produkto_id, "PARDAVIMAS", PAGRINDINIS, "", kiekis)
    log_audit("PARDAVIMAS", f"Produktas ID {produkto_id}, kiekis {kiekis}")
    return "Pardavimas išsaugotas."


def papildyti_is_isorinio(produkto_id, kiekis):
    if kiekis <= 0:
        return "Kiekis turi būti didesnis už 0."
    isorinis = gauti_kieki(produkto_id, ISORINIS)
    if isorinis < kiekis:
        return "Nepakanka kiekio išoriniame sandėlyje."
    nustatyti_kieki(produkto_id, ISORINIS, isorinis - kiekis)
    nustatyti_kieki(produkto_id, PAGRINDINIS, gauti_kieki(produkto_id, PAGRINDINIS) + kiekis)
    registruoti_judejima(produkto_id, "PERKELIMAS", ISORINIS, PAGRINDINIS, kiekis)
    log_audit("PERKELIMAS", f"Produktas ID {produkto_id}, kiekis {kiekis}")
    return "Papildymas iš išorinio atliktas."


def prideti_i_isorini(produkto_id, kiekis):
    if kiekis <= 0:
        return "Kiekis turi būti didesnis už 0."
    dabartinis = gauti_kieki(produkto_id, ISORINIS)
    nustatyti_kieki(produkto_id, ISORINIS, dabartinis + kiekis)
    registruoti_judejima(produkto_id, "PAPILDYMAS", "", ISORINIS, kiekis)
    return "Kiekis pridėtas į išorinį sandėlį."


def prideti_i_pagrindini(produkto_id, kiekis):
    if kiekis <= 0:
        return "Kiekis turi būti didesnis už 0."
    dabartinis = gauti_kieki(produkto_id, PAGRINDINIS)
    nustatyti_kieki(produkto_id, PAGRINDINIS, dabartinis + kiekis)
    registruoti_judejima(produkto_id, "PAPILDYMAS", "", PAGRINDINIS, kiekis)
    return "Kiekis pridėtas į pagrindinį sandėlį."


def koreguoti_likuti(produkto_id, vieta, naujas_kiekis, pastaba):
    if naujas_kiekis < 0:
        return "Kiekis negali būti neigiamas."
    senas = gauti_kieki(produkto_id, vieta)
    skirtumas = naujas_kiekis - senas
    nustatyti_kieki(produkto_id, vieta, naujas_kiekis)
    if skirtumas != 0:
        registruoti_judejima(
            produkto_id,
            "KOREKCIJA",
            "",
            vieta,
            abs(skirtumas),
            f"{pastaba} | Buvo: {senas}, tapo: {naujas_kiekis}"
        )
    return "Likutis pakoreguotas."


def atsaukti_judejima(judejimo_id):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM judejimai WHERE id = ?", (judejimo_id,))
    j = c.fetchone()

    if not j:
        conn.close()
        return "Judėjimas nerastas."
    if j["atsauktas"] == 1:
        conn.close()
        return "Šis judėjimas jau buvo atšauktas."

    produkto_id = j["produkto_id"]
    tipas = j["tipas"]
    kiekis = float(j["kiekis"])
    i_kur = j["i_kur"] or ""

    if tipas == "PARDAVIMAS":
        ok = pakeisti_kieki(produkto_id, PAGRINDINIS, kiekis)
        if not ok:
            conn.close()
            return "Nepavyko atšaukti pardavimo."
        registruoti_judejima(produkto_id, "ATŠAUKIMAS", "", PAGRINDINIS, kiekis, f"Atšauktas judėjimas ID {judejimo_id}", judejimo_id)

    elif tipas == "PERKELIMAS":
        pagr = gauti_kieki(produkto_id, PAGRINDINIS)
        if pagr < kiekis:
            conn.close()
            return "Nepavyko atšaukti perkėlimo."
        nustatyti_kieki(produkto_id, PAGRINDINIS, pagr - kiekis)
        nustatyti_kieki(produkto_id, ISORINIS, gauti_kieki(produkto_id, ISORINIS) + kiekis)
        registruoti_judejima(produkto_id, "ATŠAUKIMAS", PAGRINDINIS, ISORINIS, kiekis, f"Atšauktas judėjimas ID {judejimo_id}", judejimo_id)

    elif tipas == "PAPILDYMAS":
        if i_kur == PAGRINDINIS:
            pagr = gauti_kieki(produkto_id, PAGRINDINIS)
            if pagr < kiekis:
                conn.close()
                return "Nepavyko atšaukti papildymo pagrindiniame."
            nustatyti_kieki(produkto_id, PAGRINDINIS, pagr - kiekis)
        elif i_kur == ISORINIS:
            isor = gauti_kieki(produkto_id, ISORINIS)
            if isor < kiekis:
                conn.close()
                return "Nepavyko atšaukti papildymo išoriniame."
            nustatyti_kieki(produkto_id, ISORINIS, isor - kiekis)
        else:
            conn.close()
            return "Nepalaikomas papildymo atšaukimas."

        registruoti_judejima(produkto_id, "ATŠAUKIMAS", i_kur, "", kiekis, f"Atšauktas judėjimas ID {judejimo_id}", judejimo_id)

    elif tipas == "KOREKCIJA":
        conn.close()
        return "Korekcijų automatiškai atšaukti negalima."

    elif tipas == "ATŠAUKIMAS":
        conn.close()
        return "Atšaukimo atšaukti negalima."

    else:
        conn.close()
        return "Nepalaikomas judėjimo tipas."

    c.execute("UPDATE judejimai SET atsauktas = 1 WHERE id = ?", (judejimo_id,))
    conn.commit()
    conn.close()
    return "Judėjimas atšauktas."


def importuoti_csv(failas):
    stream = io.StringIO(failas.stream.read().decode("utf-8-sig"))
    reader = csv.DictReader(stream)
    prideta = 0
    atnaujinta = 0

    for row in reader:
        pavadinimas = (row.get("pavadinimas") or "").strip()
        barkodas = (row.get("barkodas") or "").strip()
        matas = (row.get("matas") or "vnt").strip()
        min_kiekis = float(row.get("min_kiekis") or 0)
        pagrindinis = float(row.get("pagrindinis") or 0)
        isorinis = float(row.get("isorinis") or 0)

        if not pavadinimas:
            continue

        esamas = gauti_produkta_pagal_barkoda(barkodas) if barkodas else None

        if esamas:
            redaguoti_produkta(esamas["id"], pavadinimas, barkodas, matas, min_kiekis)
            nustatyti_kieki(esamas["id"], PAGRINDINIS, pagrindinis)
            nustatyti_kieki(esamas["id"], ISORINIS, isorinis)
            atnaujinta += 1
        else:
            prideti_produkta(pavadinimas, barkodas, matas, min_kiekis)
            naujas = gauti_produkta_pagal_barkoda(barkodas) if barkodas else None
            if naujas:
                nustatyti_kieki(naujas["id"], PAGRINDINIS, pagrindinis)
                nustatyti_kieki(naujas["id"], ISORINIS, isorinis)
            prideta += 1

    return f"Importas baigtas. Pridėta: {prideta}, atnaujinta: {atnaujinta}."


def create_backup():
    ensure_dirs()
    if not os.path.exists(DB):
        return None
    name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    path = os.path.join(BACKUP_DIR, name)
    shutil.copy2(DB, path)
    return path


def backup_loop():
    while True:
        try:
            minutes = int(get_setting("backup_interval_minutes", str(AUTO_BACKUP_EVERY_MINUTES)))
            time.sleep(max(60, minutes * 60))
            create_backup()
        except Exception as e:
            try:
                log_error("backup_loop", str(e), traceback.format_exc())
            except Exception:
                pass


@app.before_request
def before_request():
    g.current_user = None

    if request.endpoint in {"login", "static", "manifest", "service_worker"}:
        return

    if system_locked():
        allowed = {"login", "logout", "dashboard", "static", "manifest", "service_worker"}
        if request.endpoint not in allowed:
            if session.get("role") != "admin":
                return redirect(url_for("dashboard", message="Sistema užrakinta. Kreipkis į adminą."))


@app.errorhandler(Exception)
def handle_exception(e):
    log_error(request.path, str(e), traceback.format_exc())
    return f"Klaida: {str(e)}", 500


@app.route("/login", methods=["GET", "POST"])
def login():
    message = request.args.get("message", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = gauti_vartotoja_pagal_username(username)
        if not user:
            log_login_attempt(username, False)
            return render_template("login.html", message="Neteisingi prisijungimo duomenys.")

        if user["active"] != 1:
            log_login_attempt(username, False)
            return render_template("login.html", message="Paskyra neaktyvi.")

        if not check_password_hash(user["password_hash"], password):
            log_login_attempt(username, False)
            return render_template("login.html", message="Neteisingi prisijungimo duomenys.")

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["last_activity"] = datetime.now().isoformat()

        log_login_attempt(username, True)
        log_audit("LOGIN", username)

        return redirect(url_for("dashboard"))

    return render_template("login.html", message=message)


@app.route("/logout")
@login_required
def logout():
    log_audit("LOGOUT", current_username())
    session.clear()
    return redirect(url_for("login", message="Atsijungta."))


@app.route("/keisti-slaptazodi", methods=["POST"])
@login_required
def keisti_slaptazodi():
    senas = request.form.get("senas", "")
    naujas = request.form.get("naujas", "")

    user = gauti_vartotoja_pagal_username(current_username())
    if not check_password_hash(user["password_hash"], senas):
        return redirect(url_for("dashboard", message="Neteisingas senas slaptažodis."))

    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    UPDATE vartotojai
    SET password_hash = ?, must_change_password = 0
    WHERE id = ?
    """, (generate_password_hash(naujas), current_user_id()))
    conn.commit()
    conn.close()

    log_audit("PAKEISTAS_SLAPTAZODIS", current_username())
    return redirect(url_for("dashboard", message="Slaptažodis pakeistas."))


@app.route("/")
def root():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    inventorius = gauti_inventoriu()
    judejimai = gauti_judejimus(10)

    produktu_kiekis = len(inventorius)
    mazai_likucio = sum(1 for p in inventorius if p["pagrindinis"] <= p["min_kiekis"])
    bendras_pagr = sum(p["pagrindinis"] for p in inventorius)
    bendras_isor = sum(p["isorinis"] for p in inventorius)

    return render_template(
        "dashboard.html",
        produktu_kiekis=produktu_kiekis,
        mazai_likucio=mazai_likucio,
        bendras_pagr=round(bendras_pagr, 2),
        bendras_isor=round(bendras_isor, 2),
        judejimai=judejimai,
        message=request.args.get("message", "")
    )


@app.route("/produktai")
@admin_required
def produktai():
    paieska = request.args.get("q", "")
    redaguoti_id = request.args.get("redaguoti")
    produktai = gauti_produktus(paieska)
    redaguojamas = gauti_produkta(int(redaguoti_id)) if redaguoti_id else None

    return render_template(
        "produktai.html",
        produktai=produktai,
        paieska=paieska,
        message=request.args.get("message", ""),
        redaguojamas=redaguojamas
    )


@app.route("/inventorius")
@login_required
def inventorius():
    paieska = request.args.get("q", "")
    inventorius = gauti_inventoriu(paieska)
    return render_template("inventorius.html", inventorius=inventorius, paieska=paieska, message=request.args.get("message", ""))


@app.route("/judejimai")
@login_required
def judejimai():
    return render_template("judejimai.html", judejimai=gauti_judejimus(200), message=request.args.get("message", ""))


@app.route("/korekcijos")
@login_required
def korekcijos():
    paieska = request.args.get("q", "")
    inventorius = gauti_inventoriu(paieska)
    return render_template("korekcijos.html", inventorius=inventorius, paieska=paieska, message=request.args.get("message", ""))


@app.route("/truksta")
@login_required
def truksta():
    return render_template("truksta.html", produktai=gauti_mazo_likucio_produktus(), message=request.args.get("message", ""))


@app.route("/scanner")
@login_required
def scanner():
    return render_template("scanner.html", message=request.args.get("message", ""))


@app.route("/vartotojai")
@admin_required
def vartotojai():
    return render_template("vartotojai.html", vartotojai=gauti_vartotojus(), message=request.args.get("message", ""), system_locked=system_locked())


@app.route("/error-logai")
@admin_required
def error_logai():
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM error_logai ORDER BY id DESC LIMIT 300")
    rows = c.fetchall()
    conn.close()
    return render_template("error_logs.html", logs=rows, message=request.args.get("message", ""))


@app.route("/prisijungimu-istorija")
@admin_required
def prisijungimu_istorija():
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM prisijungimu_istorija ORDER BY id DESC LIMIT 300")
    rows = c.fetchall()
    conn.close()
    return render_template("login_history.html", rows=rows, message=request.args.get("message", ""))


@app.route("/sukurti-vartotoja", methods=["POST"])
@admin_required
def sukurti_vartotoja():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "darbuotojas")

    try:
        conn = gauti_conn()
        c = conn.cursor()
        c.execute("""
        INSERT INTO vartotojai (username, password_hash, role, active, must_change_password, created_at)
        VALUES (?, ?, ?, 1, 1, ?)
        """, (
            username,
            generate_password_hash(password),
            role,
            dabar()
        ))
        conn.commit()
        conn.close()
        msg = "Vartotojas sukurtas."
    except sqlite3.IntegrityError:
        msg = "Toks vartotojo vardas jau yra."

    return redirect(url_for("vartotojai", message=msg))


@app.route("/perjungti-vartotoja/<int:user_id>", methods=["POST"])
@admin_required
def perjungti_vartotoja(user_id):
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM vartotojai WHERE id = ?", (user_id,))
    user = c.fetchone()

    if not user:
        conn.close()
        return redirect(url_for("vartotojai", message="Vartotojas nerastas."))

    new_active = 0 if user["active"] == 1 else 1
    c.execute("UPDATE vartotojai SET active = ? WHERE id = ?", (new_active, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for("vartotojai", message="Vartotojo būsena pakeista."))


@app.route("/reset-slaptazodis/<int:user_id>", methods=["POST"])
@admin_required
def reset_slaptazodis(user_id):
    new_password = request.form.get("new_password", "")
    conn = gauti_conn()
    c = conn.cursor()
    c.execute("""
    UPDATE vartotojai
    SET password_hash = ?, must_change_password = 1
    WHERE id = ?
    """, (generate_password_hash(new_password), user_id))
    conn.commit()
    conn.close()

    return redirect(url_for("vartotojai", message="Slaptažodis atnaujintas."))


@app.route("/uzrakinti-sistema", methods=["POST"])
@admin_required
def uzrakinti_sistema():
    set_setting("system_locked", "1")
    return redirect(url_for("vartotojai", message="Sistema užrakinta."))


@app.route("/atrakinti-sistema", methods=["POST"])
@admin_required
def atrakinti_sistema():
    set_setting("system_locked", "0")
    return redirect(url_for("vartotojai", message="Sistema atrakinta."))


@app.route("/api/produktas-pagal-barkoda/<barkodas>")
@login_required
def api_produktas_pagal_barkoda(barkodas):
    p = gauti_produkta_pagal_barkoda(barkodas)
    if not p:
        return jsonify({"found": False})
    return jsonify({
        "found": True,
        "id": p["id"],
        "pavadinimas": p["pavadinimas"],
        "barkodas": p["barkodas"],
        "matas": p["matas"]
    })


@app.route("/prideti_produkta", methods=["POST"])
@admin_required
def prideti_produkta_route():
    try:
        pavadinimas = request.form["pavadinimas"].strip()
        barkodas = request.form["barkodas"].strip()
        matas = request.form["matas"].strip()
        min_kiekis = float(request.form["min_kiekis"])
        prideti_produkta(pavadinimas, barkodas, matas, min_kiekis)
        msg = "Produktas pridėtas."
    except sqlite3.IntegrityError:
        msg = "Toks barkodas jau egzistuoja."
    except Exception as e:
        log_error("/prideti_produkta", str(e), traceback.format_exc())
        msg = f"Klaida: {e}"

    return redirect(url_for("produktai", message=msg))


@app.route("/redaguoti_produkta", methods=["POST"])
@admin_required
def redaguoti_produkta_route():
    try:
        produkto_id = int(request.form["produkto_id"])
        pavadinimas = request.form["pavadinimas"].strip()
        barkodas = request.form["barkodas"].strip()
        matas = request.form["matas"].strip()
        min_kiekis = float(request.form["min_kiekis"])
        redaguoti_produkta(produkto_id, pavadinimas, barkodas, matas, min_kiekis)
        msg = "Produktas atnaujintas."
    except sqlite3.IntegrityError:
        msg = "Toks barkodas jau egzistuoja."
    except Exception as e:
        log_error("/redaguoti_produkta", str(e), traceback.format_exc())
        msg = f"Klaida: {e}"

    return redirect(url_for("produktai", message=msg))


@app.route("/istrinti_produkta/<int:produkto_id>", methods=["POST"])
@admin_required
def istrinti_produkta_route(produkto_id):
    msg = istrinti_produkta(produkto_id)
    return redirect(url_for("produktai", message=msg))


@app.route("/parduoti", methods=["POST"])
@login_required
def parduoti_route():
    pid = int(request.form["pid"])
    kiekis = float(request.form["kiekis"])
    msg = parduoti(pid, kiekis)
    return redirect(url_for("inventorius", message=msg))


@app.route("/papildyti", methods=["POST"])
@login_required
def papildyti_route():
    pid = int(request.form["pid"])
    kiekis = float(request.form["kiekis"])
    msg = papildyti_is_isorinio(pid, kiekis)
    return redirect(url_for("inventorius", message=msg))


@app.route("/isorinis_prideti", methods=["POST"])
@login_required
def isorinis_prideti_route():
    pid = int(request.form["pid"])
    kiekis = float(request.form["kiekis"])
    msg = prideti_i_isorini(pid, kiekis)
    return redirect(url_for("inventorius", message=msg))


@app.route("/pagrindinis_prideti", methods=["POST"])
@login_required
def pagrindinis_prideti_route():
    pid = int(request.form["pid"])
    kiekis = float(request.form["kiekis"])
    msg = prideti_i_pagrindini(pid, kiekis)
    return redirect(url_for("inventorius", message=msg))


@app.route("/koreguoti", methods=["POST"])
@login_required
def koreguoti_route():
    pid = int(request.form["pid"])
    vieta = request.form["vieta"]
    naujas_kiekis = float(request.form["naujas_kiekis"])
    pastaba = request.form.get("pastaba", "").strip()
    msg = koreguoti_likuti(pid, vieta, naujas_kiekis, pastaba or "Rankinė korekcija")
    return redirect(url_for("korekcijos", message=msg))


@app.route("/atsaukti/<int:judejimo_id>", methods=["POST"])
@login_required
def atsaukti_route(judejimo_id):
    msg = atsaukti_judejima(judejimo_id)
    return redirect(url_for("judejimai", message=msg))


@app.route("/importas", methods=["POST"])
@admin_required
def importas_route():
    failas = request.files.get("csv_failas")
    if not failas:
        return redirect(url_for("produktai", message="CSV failas nepasirinktas."))

    try:
        msg = importuoti_csv(failas)
    except Exception as e:
        log_error("/importas", str(e), traceback.format_exc())
        msg = f"Importo klaida: {e}"

    return redirect(url_for("produktai", message=msg))


@app.route("/eksportuoti-produktus")
@admin_required
def eksportuoti_produktus():
    inventorius = gauti_inventoriu()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["pavadinimas", "barkodas", "matas", "min_kiekis", "pagrindinis", "isorinis"])

    for p in inventorius:
        writer.writerow([
            p["pavadinimas"], p["barkodas"], p["matas"],
            p["min_kiekis"], p["pagrindinis"], p["isorinis"]
        ])

    mem = io.BytesIO()
    mem.write(output.getvalue().encode("utf-8-sig"))
    mem.seek(0)

    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="produktai_eksportas.csv")


@app.route("/atsargine-kopija")
@admin_required
def atsargine_kopija():
    path = create_backup()
    if not path:
        return redirect(url_for("dashboard", message="Nepavyko sukurti kopijos."))
    return send_file(path, as_attachment=True)


@app.route("/manifest.webmanifest")
def manifest():
    return send_file("static/manifest.webmanifest", mimetype="application/manifest+json")


@app.route("/service-worker.js")
def service_worker():
    return send_file("static/service-worker.js", mimetype="application/javascript")


if __name__ == "__main__":
    init_db()
    thread = threading.Thread(target=backup_loop, daemon=True)
    thread.start()
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))