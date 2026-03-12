from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
import sqlite3

# --------- PROJECT MODULES ----------
from modules.recon import get_server_info, get_ip_address
from modules.scanner import scan_ports
from modules.exploit import check_sql_injection, check_xss
from modules.malware import check_malware
from modules.owasp import check_security_headers, check_directory_listing
from modules.ssl_check import check_ssl
from modules.charts import generate_chart
from modules.report import generate_pdf_report
from modules.risk_engine import calculate_risk
from modules.crawler import crawl_website
from modules.param_finder import extract_parameters

app = Flask(__name__)
app.secret_key = "supersecretkey"

bcrypt = Bcrypt(app)

# ---------------- LOGIN MANAGER ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------------- USER CLASS ----------------
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()

    conn.close()

    if user:
        return User(user[0], user[1])

    return None


# ---------------- MAIN SCANNER ----------------
@login_required
def start_scan(url):

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    # -------- RECON --------
    server = get_server_info(url)
    ip = get_ip_address(url)

    # -------- PORT SCAN --------
    ports = scan_ports(ip)

    # -------- CRAWL WEBSITE --------
    all_sql = []
    all_xss = []

    urls = crawl_website(url)

    # If crawler fails scan main URL
    if not urls:
        urls = [url]

    # Limit number of pages to avoid timeout
    urls = urls[:3]

    for page in urls:

        params = extract_parameters(page)

        # If no parameters found use common ones
        if not params:
            params = ["id", "q", "search"]

        params = params[:2]

        for param in params:

            sql_results = check_sql_injection(page, param)
            all_sql.extend(sql_results)

            xss_results = check_xss(page, param)
            all_xss.extend(xss_results)

    # -------- MALWARE --------
    malware = check_malware(url)

    # -------- OWASP CHECKS --------
    header_results = check_security_headers(url)
    headers = header_results.get("missing", [])

    directory = check_directory_listing(url)

    # -------- SSL --------
    ssl_status = check_ssl(domain)

    report_data = {
        "URL": url,
        "IP": ip,
        "Server": server,
        "Open Ports": ports,
        "SQL": all_sql,
        "XSS": all_xss,
        "Malware": malware,
        "Missing Headers": headers,
        "Directory Listing": directory,
        "SSL": ssl_status
    }

    return report_data


# ---------------- MAIN PAGE ----------------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    if request.method == "POST":

        url = request.form["url"]

        report_data = start_scan(url)

        vulnerabilities = {
            "SQL": 1 if any("sql injection" in str(i).lower() for i in report_data["SQL"]) else 0,
            "XSS": 1 if any("xss" in str(i).lower() for i in report_data["XSS"]) else 0,
            "Malware": 1 if "no malware" not in str(report_data["Malware"]).lower() else 0,
            "Headers": len(report_data["Missing Headers"]),
            "Directory": 1 if "enabled" in str(report_data["Directory Listing"]).lower() else 0
        }

        chart = generate_chart(vulnerabilities)

        risk_score, severity, issues = calculate_risk(report_data)

        pdf = generate_pdf_report(report_data)

        return render_template(
            "results.html",
            data=report_data,
            chart=chart,
            pdf=pdf,
            risk_score=risk_score,
            severity=severity,
            issues=issues
        )

    return render_template("index.html")


# ---------------- SIGNUP ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form["username"]
        password = bcrypt.generate_password_hash(
            request.form["password"]
        ).decode("utf-8")

        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        try:
            c.execute(
                "INSERT INTO users (username, password) VALUES (?,?)",
                (username, password)
            )

            conn.commit()
            conn.close()

            return redirect(url_for("login"))

        except:
            conn.close()
            return "Username already exists"

    return render_template("signup.html")


# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()

        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):

            login_user(User(user[0], user[1]))

            return redirect(url_for("index"))

        else:
            return "Invalid Credentials"

    return render_template("login.html")


# ---------------- LOGOUT ----------------
@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))


# ---------------- RUN SERVER ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)