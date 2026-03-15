import sys
sys.path.insert(0, './modules')

from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
import sqlite3
import requests
import socket
import time
from urllib.parse import urlparse

# Module imports
from modules.recon import get_server_info, get_ip_address
from modules.scanner import check_security_headers, check_directory_listing
from modules.exploit import check_sql_injection, check_xss
from modules.malware import check_malware
from modules.ssl_check import check_ssl
from modules.charts import generate_chart
from modules.report import generate_pdf_report
from modules.risk_engine import calculate_risk

app = Flask(__name__)
app.secret_key = "supersecretkey"

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Database setup
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)")
    conn.commit()
    conn.close()
init_db()

class User(UserMixin):
    def __init__(self, id, username):
        self.id, self.username = id, username

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    return User(user[0], user[1]) if user else None

def start_scan(url):
    print(f"🔍 Starting accurate scan on: {url}")
    start_time = time.time()
    sql_issues, xss_issues = [], []
    report_data = {"URL": url}
    
    # Recon
    report_data["Server"] = get_server_info(url).get("server", "Unknown")
    report_data["IP"] = get_ip_address(url)
    
    # 1. Vulnerability Tests (Using your new stable functions)
    
    params = ["id", "q", "search"]
    
    # Clean URL for scanning
    target_base = url.split('?')[0] 
    
    for param in params:
        if check_sql_injection(target_base, param):
            sql_issues.append(f"SQLi detected on param: {param}")
        if check_xss(target_base, param):
            xss_issues.append(f"XSS detected on param: {param}")
    
    report_data["SQL"] = sql_issues if sql_issues else ["No SQLi detected"]
    report_data["XSS"] = xss_issues if xss_issues else ["No XSS detected"]
    
    # 2. Other Checks
    report_data["Missing Headers"] = check_security_headers(requests.get(url)).get("missing", [])
    report_data["Malware"] = [check_malware(url)]
    report_data["SSL"] = check_ssl(urlparse(url).netloc)
    report_data["Directory Listing"] = [check_directory_listing(url).get("status", "Disabled")]
    
    print(f"✅ SCAN COMPLETE in {time.time() - start_time:.1f}s!")
    return report_data

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        # 1. Capture URL
        url = request.form.get("url", "").strip()
        # 2. Perform fresh scan
        report_data = start_scan(url)
        vulns = {
            "SQL": 1 if "detected" in str(report_data.get("SQL", "")) and "No" not in str(report_data.get("SQL", "")) else 0,
            "XSS": 1 if "detected" in str(report_data.get("XSS", "")) and "No" not in str(report_data.get("XSS", "")) else 0,
            "Malware": 1 if "clean" not in str(report_data.get("Malware", "")).lower() else 0,
            "Headers": len(report_data.get("Missing Headers", [])),
            "Directory": 1 if "Enabled" in str(report_data.get("Directory Listing", "")) else 0
        }
            
        # Compute dependencies
        chart = generate_chart(vulns)
        risk_score, severity, issues, severity_color = calculate_risk(report_data)
        pdf = generate_pdf_report(report_data)
        # Add this in your app.py inside the POST block
        print(f"DEBUG: Chart string length: {len(chart)}")
        print(f"DEBUG: First 50 chars of chart: {chart[:50]}")
        return render_template("results.html",
                                data=report_data, 
                                chart=chart, 
                                pdf=pdf, 
                                risk_score=risk_score, 
                                severity=severity, 
                                issues=issues,
                                severity_color=severity_color,
                                vulnerabilities=vulns)
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = bcrypt.generate_password_hash(request.form["password"]).decode("utf-8")
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?,?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("signup.html", error="Username exists!")
    return render_template("signup.html")

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
        return render_template("login.html", error="Invalid credentials!")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
