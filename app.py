from __future__ import annotations

import os
import pickle
import secrets
import hmac
import re
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any
from uuid import uuid4

import pandas as pd
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from PIL import Image, UnidentifiedImageError
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename



BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
RUNTIME_DIR = Path(os.environ.get("SCAMSHIELD_DATA_DIR", str(BASE_DIR)))
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
INSTANCE_DIR = RUNTIME_DIR / "instance"
MODEL_DIR = RUNTIME_DIR / "models"
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = RUNTIME_DIR / "uploads"

DB_PATH = INSTANCE_DIR / "scam_system.db"
MODEL_PATH = MODEL_DIR / "scam_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"
DATASET_PATH = DATA_DIR / "sms_dataset.csv"

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

for directory in (INSTANCE_DIR, MODEL_DIR, UPLOAD_DIR):
    directory.mkdir(exist_ok=True)

app = Flask(__name__)
secret_file = INSTANCE_DIR / "secret.key"
if not os.environ.get("SECRET_KEY") and not secret_file.exists():
    try:
        with secret_file.open("x") as handle:
            handle.write(secrets.token_hex(32))
        secret_file.chmod(0o600)
    except FileExistsError:
        pass
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secret_file.read_text().strip()
app.config.update(MAX_CONTENT_LENGTH=5 * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1")


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def validate_csrf():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400, "Invalid form token. Reload the page and try again.")


def normalize_phone(value):
    value = re.sub(r"[\s-]", "", value.strip())
    if value.startswith("00"):
        value = "+" + value[2:]
    if not re.fullmatch(r"\+?[0-9]{7,15}", value):
        raise ValueError("Enter a valid phone number using 7 to 15 digits.")
    return value


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_database() -> None:
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT NOT NULL,
                message TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'Other',
                received_date TEXT,
                received_time TEXT,
                screenshot_path TEXT,
                predicted_label TEXT NOT NULL,
                prediction_confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                cluster_id INTEGER,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL,
                FOREIGN KEY (report_id) REFERENCES reports(id)
            );

            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            """
        )

        # Small migration for databases created by an earlier build.
        report_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(reports)").fetchall()
        }
        if "screenshot_path" not in report_columns:
            db.execute("ALTER TABLE reports ADD COLUMN screenshot_path TEXT")

        admin = db.execute(
            "SELECT id FROM admins WHERE username = ?",
            (os.environ.get("ADMIN_USERNAME", "admin"),),
        ).fetchone()

        if admin is None:
            password = os.environ.get("ADMIN_PASSWORD", "")
            if len(password) < 12 or password == "replace-with-a-unique-password":
                raise RuntimeError("Set ADMIN_PASSWORD to a unique password of at least 12 characters in .env before first launch.")
            db.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                (os.environ.get("ADMIN_USERNAME", "admin"), generate_password_hash(password)),
            )


def clean_text(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"https?://\S+|www\.\S+", " urltoken ", text)
    text = re.sub(r"\b\d{6,}\b", " numbertoken ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def train_model_if_needed() -> None:
    if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
        return

    dataset = pd.read_csv(DATASET_PATH)
    dataset["clean_message"] = dataset["message"].astype(str).apply(clean_text)

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=1,
        max_features=2500,
        stop_words="english",
    )
    features = vectorizer.fit_transform(dataset["clean_message"])

    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(features, dataset["label"])

    with MODEL_PATH.open("wb") as model_file:
        pickle.dump(model, model_file)

    with VECTORIZER_PATH.open("wb") as vectorizer_file:
        pickle.dump(vectorizer, vectorizer_file)

def load_model() -> tuple[LogisticRegression, TfidfVectorizer]:
    train_model_if_needed()

    with MODEL_PATH.open("rb") as model_file:
        model = pickle.load(model_file)

    with VECTORIZER_PATH.open("rb") as vectorizer_file:
        vectorizer = pickle.load(vectorizer_file)

    return model, vectorizer


MODEL = None
VECTORIZER = None


def get_ml_objects() -> tuple[LogisticRegression, TfidfVectorizer]:
    global MODEL, VECTORIZER

    if MODEL is None or VECTORIZER is None:
        MODEL, VECTORIZER = load_model()

    return MODEL, VECTORIZER


def predict_message(message: str) -> tuple[str, float]:
    model, vectorizer = get_ml_objects()
    features = vectorizer.transform([clean_text(message)])
    label = str(model.predict(features)[0])
    probabilities = model.predict_proba(features)[0]
    class_index = list(model.classes_).index(label)
    confidence = float(probabilities[class_index]) * 100
    return label, round(confidence, 2)


def calculate_risk_score(
    phone_number: str,
    message: str,
    predicted_label: str,
    confidence: float,
) -> tuple[int, str]:
    with get_db() as db:
        repeat_count = db.execute(
            "SELECT COUNT(*) AS count FROM reports WHERE phone_number = ?",
            (phone_number,),
        ).fetchone()["count"]

    ai_points = (
        confidence * 0.60
        if predicted_label == "scam"
        else max(0, (100 - confidence) * 0.20)
    )
    repeat_points = min(repeat_count * 8, 25)

    suspicious_terms = [
        "won",
        "winner",
        "prize",
        "claim",
        "blocked",
        "expire",
        "urgent",
        "otp",
        "password",
        "click",
        "bank",
        "lottery",
        "payment",
        "transfer",
        "verify",
    ]
    lowered = message.lower()
    matched_terms = sum(1 for term in suspicious_terms if term in lowered)
    keyword_points = min(matched_terms * 3, 12)

    if re.search(r"https?://|www\.", lowered):
        keyword_points += 3

    score = int(round(min(ai_points + repeat_points + keyword_points, 100)))

    if score >= 75:
        level = "High"
    elif score >= 50:
        level = "Suspicious"
    elif score >= 25:
        level = "Moderate"
    else:
        level = "Low"

    return score, level


def refresh_clusters() -> None:
    with get_db() as db:
        rows = db.execute(
            "SELECT id, message FROM reports WHERE predicted_label = 'scam'"
        ).fetchall()

    if not rows:
        return

    report_ids = [row["id"] for row in rows]
    messages = [clean_text(row["message"]) for row in rows]

    if len(rows) == 1:
        assignments = [0]
    else:
        _, vectorizer = get_ml_objects()
        features = vectorizer.transform(messages)
        cluster_count = min(3, len(rows))
        clustering_model = KMeans(
            n_clusters=cluster_count,
            random_state=42,
            n_init=10,
        )
        assignments = clustering_model.fit_predict(features).tolist()

    with get_db() as db:
        for report_id, cluster_id in zip(report_ids, assignments):
            db.execute(
                "UPDATE reports SET cluster_id = ? WHERE id = ?",
                (int(cluster_id), report_id),
            )


def allowed_image(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS
    )


def save_screenshot(uploaded_file: Any) -> str | None:
    if uploaded_file is None or not uploaded_file.filename:
        return None

    if not allowed_image(uploaded_file.filename):
        raise ValueError("Screenshot must be a PNG, JPG, JPEG or WEBP image.")

    safe_name = secure_filename(uploaded_file.filename)
    extension = safe_name.rsplit(".", 1)[1].lower()
    unique_name = f"{datetime.now():%Y%m%d%H%M%S}_{uuid4().hex[:8]}.{extension}"
    try:
        with Image.open(uploaded_file.stream) as img:
            if img.format not in {"PNG", "JPEG", "WEBP"}:
                raise ValueError("Unsupported image content.")
            img.verify()
        uploaded_file.stream.seek(0)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as error:
        raise ValueError("Screenshot must contain a valid image.") from error
    uploaded_file.save(UPLOAD_DIR / unique_name)
    return unique_name


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_id"):
            flash("Please log in to access the administrator area.", "warning")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped_view


@app.context_processor
def inject_current_year() -> dict[str, int]:
    return {"current_year": datetime.now().year}


@app.route("/")
def home():
    with get_db() as db:
        recent_alerts = db.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 3"
        ).fetchall()
    return render_template("index.html", recent_alerts=recent_alerts)


@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename: str):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/report", methods=["GET", "POST"])
def report_scam():
    if request.method == "POST":
        phone_number = request.form.get("phone_number", "").strip()
        message = request.form.get("message", "").strip()
        category = request.form.get("category", "Other").strip() or "Other"
        received_date = request.form.get("received_date", "").strip()
        received_time = request.form.get("received_time", "").strip()

        if not phone_number or not message:
            flash("Phone number and message are required.", "danger")
            return render_template("report.html")

        try:
            phone_number = normalize_phone(phone_number)
        except ValueError as error:
            flash(str(error), "danger")
            return render_template("report.html"), 400
        if len(message) > 10000 or len(category) > 80:
            abort(400, "Message or category is too long.")

        try:
            screenshot_path = save_screenshot(request.files.get("screenshot"))
        except ValueError as error:
            flash(str(error), "danger")
            return render_template("report.html")

        predicted_label, confidence = predict_message(message)
        risk_score, risk_level = calculate_risk_score(
            phone_number,
            message,
            predicted_label,
            confidence,
        )

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with get_db() as db:
            cursor = db.execute(
                """
                INSERT INTO reports (
                    phone_number, message, category, received_date,
                    received_time, screenshot_path, predicted_label,
                    prediction_confidence, risk_score, risk_level, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    phone_number,
                    message,
                    category,
                    received_date,
                    received_time,
                    screenshot_path,
                    predicted_label,
                    confidence,
                    risk_score,
                    risk_level,
                    created_at,
                ),
            )
            report_id = cursor.lastrowid

            if risk_score >= 75:
                db.execute(
                    """
                    INSERT INTO alerts (
                        report_id, title, details, risk_score, created_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        report_id,
                        "Possible Scam Campaign Detected",
                        f"High-risk activity linked to {phone_number}. "
                        f"Category: {category}.",
                        risk_score,
                        created_at,
                    ),
                )

        session["report_ids"] = (session.get("report_ids", []) + [report_id])[-20:]
        refresh_clusters()
        flash("Report submitted and analysed successfully.", "success")
        return redirect(url_for("report_result", report_id=report_id))

    return render_template("report.html")


@app.route("/result/<int:report_id>")
def report_result(report_id: int):
    if not session.get("admin_id") and report_id not in session.get("report_ids", []):
        abort(404)
    with get_db() as db:
        report = db.execute(
            "SELECT * FROM reports WHERE id = ?",
            (report_id,),
        ).fetchone()

    if report is None:
        flash("Report not found.", "danger")
        return redirect(url_for("home"))

    return render_template("result.html", report=report)


@app.route("/check-number", methods=["GET", "POST"])
def check_number():
    results = None
    phone_number = ""

    if request.method == "POST":
        try:
            phone_number = normalize_phone(request.form.get("phone_number", ""))
        except ValueError as error:
            flash(str(error), "danger")
            return render_template("check_number.html", results=None, phone_number=""), 400

        with get_db() as db:
            results = db.execute(
                """
                SELECT
                    phone_number,
                    COUNT(*) AS report_count,
                    MAX(risk_score) AS highest_risk,
                    CASE
                        WHEN MAX(risk_score) >= 75 THEN 'High'
                        WHEN MAX(risk_score) >= 50 THEN 'Suspicious'
                        WHEN MAX(risk_score) >= 25 THEN 'Moderate'
                        ELSE 'Low'
                    END AS risk_level,
                    MAX(created_at) AS last_reported
                FROM reports
                WHERE phone_number = ?
                GROUP BY phone_number
                """,
                (phone_number,),
            ).fetchone()

    return render_template(
        "check_number.html",
        results=results,
        phone_number=phone_number,
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            admin = db.execute(
                "SELECT * FROM admins WHERE username = ?",
                (username,),
            ).fetchone()

        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("admin_login.html")


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/admin/dashboard")
@login_required
def dashboard():
    refresh_clusters()

    with get_db() as db:
        total_reports = db.execute(
            "SELECT COUNT(*) AS count FROM reports"
        ).fetchone()["count"]
        scam_reports = db.execute(
            "SELECT COUNT(*) AS count FROM reports WHERE predicted_label = 'scam'"
        ).fetchone()["count"]
        legitimate_reports = db.execute(
            """
            SELECT COUNT(*) AS count
            FROM reports
            WHERE predicted_label = 'legitimate'
            """
        ).fetchone()["count"]
        high_risk_reports = db.execute(
            "SELECT COUNT(*) AS count FROM reports WHERE risk_score >= 75"
        ).fetchone()["count"]

        category_rows = db.execute(
            """
            SELECT category, COUNT(*) AS count
            FROM reports
            GROUP BY category
            ORDER BY count DESC
            """
        ).fetchall()

        trend_rows = db.execute(
            """
            SELECT DATE(created_at) AS report_day, COUNT(*) AS count
            FROM reports
            GROUP BY DATE(created_at)
            ORDER BY report_day ASC
            """
        ).fetchall()

        classification_rows = db.execute(
            """SELECT predicted_label, COUNT(*) AS count FROM reports GROUP BY predicted_label"""
        ).fetchall()

        risk_rows = db.execute(
            """SELECT risk_level, COUNT(*) AS count FROM reports GROUP BY risk_level"""
        ).fetchall()

        recent_reports = db.execute(
            "SELECT * FROM reports ORDER BY id DESC LIMIT 8"
        ).fetchall()

        high_risk_numbers = db.execute(
            """
            SELECT
                phone_number,
                COUNT(*) AS report_count,
                MAX(risk_score) AS risk_score
            FROM reports
            GROUP BY phone_number
            HAVING MAX(risk_score) >= 50
            ORDER BY risk_score DESC
            LIMIT 8
            """
        ).fetchall()

        clusters = db.execute(
            """
            SELECT
                cluster_id,
                COUNT(*) AS report_count,
                ROUND(AVG(risk_score), 1) AS average_risk
            FROM reports
            WHERE predicted_label = 'scam'
              AND cluster_id IS NOT NULL
            GROUP BY cluster_id
            ORDER BY cluster_id
            """
        ).fetchall()

    classification_map = {row["predicted_label"]: row["count"] for row in classification_rows}
    risk_map = {row["risk_level"]: row["count"] for row in risk_rows}

    return render_template(
        "dashboard.html",
        total_reports=total_reports,
        scam_reports=scam_reports,
        legitimate_reports=legitimate_reports,
        high_risk_reports=high_risk_reports,
        recent_reports=recent_reports,
        high_risk_numbers=high_risk_numbers,
        clusters=clusters,
        category_labels=[row["category"] for row in category_rows],
        category_values=[row["count"] for row in category_rows],
        trend_labels=[row["report_day"] for row in trend_rows],
        trend_values=[row["count"] for row in trend_rows],
        classification_values=[classification_map.get("scam", 0), classification_map.get("legitimate", 0)],
        risk_values=[risk_map.get("Low", 0), risk_map.get("Moderate", 0), risk_map.get("Suspicious", 0), risk_map.get("High", 0)],
    )


@app.route("/admin/reports")
@login_required
def admin_reports():
    with get_db() as db:
        reports = db.execute(
            "SELECT * FROM reports ORDER BY id DESC"
        ).fetchall()
    return render_template("reports.html", reports=reports)


@app.route("/admin/campaigns")
@login_required
def admin_campaigns():
    refresh_clusters()

    with get_db() as db:
        cluster_rows = db.execute(
            """
            SELECT
                cluster_id,
                COUNT(*) AS report_count,
                COUNT(DISTINCT phone_number) AS phone_count,
                ROUND(AVG(risk_score), 1) AS average_risk,
                MAX(created_at) AS latest_activity
            FROM reports
            WHERE predicted_label = 'scam'
              AND cluster_id IS NOT NULL
            GROUP BY cluster_id
            ORDER BY average_risk DESC
            """
        ).fetchall()

        campaigns = []
        for cluster in cluster_rows:
            categories = db.execute(
                """
                SELECT category, COUNT(*) AS count
                FROM reports
                WHERE cluster_id = ?
                GROUP BY category
                ORDER BY count DESC
                LIMIT 3
                """,
                (cluster["cluster_id"],),
            ).fetchall()

            samples = db.execute(
                """
                SELECT phone_number, message, risk_score
                FROM reports
                WHERE cluster_id = ?
                ORDER BY risk_score DESC, id DESC
                LIMIT 3
                """,
                (cluster["cluster_id"],),
            ).fetchall()

            campaigns.append(
                {
                    "cluster": cluster,
                    "categories": categories,
                    "samples": samples,
                }
            )

    return render_template("campaigns.html", campaigns=campaigns)




@app.route("/admin/alerts")
@login_required
def admin_alerts():
    with get_db() as db:
        alerts = db.execute(
            """
            SELECT alerts.*, reports.phone_number, reports.category
            FROM alerts
            JOIN reports ON reports.id = alerts.report_id
            ORDER BY alerts.id DESC
            """
        ).fetchall()
    return render_template("alerts.html", alerts=alerts)


@app.route("/admin/alerts/<int:alert_id>/close", methods=["POST"])
@login_required
def close_alert(alert_id: int):
    with get_db() as db:
        db.execute(
            "UPDATE alerts SET status = 'Closed' WHERE id = ?",
            (alert_id,),
        )
    flash("Alert marked as closed.", "success")
    return redirect(url_for("admin_alerts"))


@app.errorhandler(413)
def file_too_large(_error: Any):
    flash("Screenshot size must be 5 MB or less.", "danger")
    return redirect(url_for("report_scam"))


@app.errorhandler(404)
def not_found(_error: Any):
    return render_template("404.html"), 404


init_database()
train_model_if_needed()
refresh_clusters()

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
