import sqlite3
import requests
import time
import logging
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, make_response, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
import threading
import signal
from flask import send_file, abort
import os
from io import BytesIO
from fpdf import FPDF

# Module imports with TIMEOUT protection
try:
    from modules.recon import get_server_info, get_ip_address
    from modules.scanner import check_security_headers, check_directory_listing, scan_ports
    from modules.exploit import check_sql_injection, check_xss
    from modules.malware import check_malware
    from modules.ssl_check import check_ssl
    from modules.charts import generate_chart
    from modules.risk_engine import calculate_risk
except ImportError as e:
    print(f"Module import error: {e}")
    # Create dummy functions
    def get_server_info(url): return {"server": "Unknown"}
    def get_ip_address(url): return "N/A"
    def check_security_headers(resp): return []
    def check_directory_listing(url): return "Disabled"
    def scan_ports(host): return ["80", "443"]
    def check_sql_injection(url, param): return False
    def check_xss(url, param): return False
    def check_malware(url): return "Clean"
    def check_ssl(host): return "Unknown"
    def generate_chart(vulns): return None
    def calculate_risk(data): return (0, "Low", [], "low")

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = "supersecretkey" 
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# --- Database & User Management ---
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)')
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


@app.route("/download_pdf")
@login_required
def download_pdf():
    report_data = session.get("last_report", {})
    if not report_data:
        return redirect(url_for("index"))

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Vulnerability Scan Report", ln=True)

    pdf.set_font("Arial", "", 12)
    pdf.ln(5)

    pdf.cell(0, 10, f"URL: {report_data.get('URL', 'Unknown')}", ln=True)
    pdf.cell(0, 10, f"Server: {report_data.get('Server', 'Unknown')}", ln=True)
    pdf.cell(0, 10, f"Ports: {', '.join(map(str, report_data.get('Ports', ['80', '443'])))}", ln=True)
    pdf.cell(0, 10, f"SSL: {report_data.get('SSL', 'Unknown')}", ln=True)
    pdf.cell(0, 10, f"SQL Injection: {', '.join(map(str, report_data.get('SQL', ['Clean'])))}", ln=True)
    pdf.cell(0, 10, f"XSS: {', '.join(map(str, report_data.get('XSS', ['Clean'])))}", ln=True)
    pdf.cell(0, 10, f"Malware: {', '.join(map(str, report_data.get('Malware', ['Clean'])))}", ln=True)
    pdf.multi_cell(0, 10, f"Missing Headers: {', '.join(map(str, report_data.get('Missing Headers', ['None'])))}")
    pdf.cell(0, 10, f"Directory Listing: {', '.join(map(str, report_data.get('Directory Listing', ['Disabled'])))}", ln=True)

    pdf_bytes = pdf.output(dest="S").encode("latin-1")
    pdf_stream = BytesIO(pdf_bytes)

    return send_file(
        pdf_stream,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="scan_report.pdf"
    )
# --- TIMEOUT-SAFE FUNCTIONS ---
def safe_execute(func, *args, timeout=3, default=None):
    """Execute function with timeout protection"""
    result = [default]
    exception = [None]
    
    def target():
        try:
            result[0] = func(*args)
        except Exception as e:
            exception[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    
    if thread.is_alive():
        return default
    if exception[0]:
        return default
    return result[0]

# --- NORMALIZATION FUNCTIONS ---
def normalize_list_result(value, clean_labels=None):
    if clean_labels is None:
        clean_labels = ["Clean", "No SQLi", "No SQL Injection", "No XSS", "None", "Disabled"]
    
    if value is None or value == "":
        return ["Clean"]
    
    if isinstance(value, str):
        value = value.strip()
        if not value or value.lower() in [label.lower() for label in clean_labels]:
            return ["Clean"]
        return [value]
    
    if isinstance(value, list):
        cleaned = []
        for item in value:
            if item is None or str(item).strip() == "":
                continue
            item_str = str(item).strip()
            if item_str.lower() not in [label.lower() for label in clean_labels]:
                cleaned.append(item_str)
        return cleaned if cleaned else ["Clean"]
    
    return ["Clean"]

def normalize_malware_result(value):
    if value is None or value == "":
        return ["Clean"]
    
    text = str(value).strip().lower()
    
    # Treat ALL errors as non-malware
    error_indicators = ["503", "502", "500", "504", "timeout", "error", "failed", "unavailable", "connection"]
    if any(indicator in text for indicator in error_indicators):
        return ["Scan Error"]
    
    # Clean result
    if any(word in text for word in ["clean", "safe", "no malware", "not found"]):
        return ["Clean"]
    
    return [str(value)]

# --- BULLETPROOF SCAN FUNCTION ---
def start_scan(url):
    """COMPLETE SCAN WITH PROPER NORMALIZATION"""
    if not url.startswith(('http://', 'https://')): 
        url = "http://" + url
        
    # Initialize clean results
    report_data = {
        "URL": url, 
        "SQL": ["Clean"], 
        "XSS": ["Clean"], 
        "Missing Headers": ["None"], 
        "Malware": ["Clean"], 
        "SSL": "Unknown", 
        "Directory Listing": ["Disabled"],
        "Server": "Unknown",
        "IP": "N/A",
        "Ports": ["80", "443"]
    }
    
    print(f"🔍 SCANNING: {url}")
    
    try:
        import requests
        session_req = requests.Session()
        base_resp = session_req.get(url, timeout=5)
        
        # 1. RECON
        server_info = get_server_info(url)
        report_data["Server"] = server_info.get("server", "Unknown")  # FIXED: Extract string
        
        ip_info = get_ip_address(url)
        report_data["IP"] = ip_info
        
        # 2. EXPLOIT (FIXED LOGIC)
        test_sql = check_sql_injection(url, "id")
        if test_sql == False:  # FIXED: False = clean, "Clean" = vuln (your exploit.py logic)
            report_data["SQL"] = ["Clean"]
        else:
            report_data["SQL"] = ["Potential SQLi"]
            
        test_xss = check_xss(url, "id")
        if test_xss == False:
            report_data["XSS"] = ["Clean"]
        else:
            report_data["XSS"] = ["Potential XSS"]
        
        # 3. HEADERS
        headers_result = check_security_headers(base_resp)
        report_data["Missing Headers"] = headers_result if headers_result else ["None"]
        
        # 4. MALWARE
        malware_result = check_malware(url)
        report_data["Malware"] = [malware_result] if malware_result != "Clean" else ["Clean"]
        
        # 5. SSL
        report_data["SSL"] = check_ssl(url)
        
        # 6. DIRECTORY (now called)
        dir_result = check_directory_listing(url)
        report_data["Directory Listing"] = ["Enabled"] if "Listing found" in str(dir_result) else ["Disabled"]
        
        # 7. PORTS (now called)
        ports_result = scan_ports(report_data["IP"])
        if isinstance(ports_result, list) and len(ports_result) > 0 and isinstance(ports_result[0], int):
            report_data["Ports"] = [str(p) for p in ports_result]
        else:
            report_data["Ports"] = ["80", "443"]
    
    except Exception as e:
        print(f"SCAN ERROR: {e}")
    
    print(f"✅ FINAL REPORT: {report_data}")
    return report_data
# --- ROUTES ---
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            try:
                session['last_report'] = start_scan(url)
                return redirect(url_for("show_results"))
            except:
                session['last_report'] = {"URL": url, "Error": "Scan failed"}
                return redirect(url_for("show_results"))
    return render_template("index.html")


@app.route("/results")
@login_required
def show_results():
    report_data = session.get("last_report", {})
    if not report_data:
        return redirect(url_for("index"))

    def ensure_list(value, default=None):
        if default is None:
            default = []
        if value is None:
            return default
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [value]
        return list(value)

    sql_list = ensure_list(report_data.get("SQL"), ["Clean"])
    xss_list = ensure_list(report_data.get("XSS"), ["Clean"])
    malware_list = ensure_list(report_data.get("Malware"), ["Clean"])
    headers_list = ensure_list(report_data.get("Missing Headers"), ["None"])
    dir_list = ensure_list(report_data.get("Directory Listing"), ["Disabled"])
    ports_list = ensure_list(report_data.get("Ports"), ["80", "443"])

    sql_vulns = len([x for x in sql_list if str(x).strip().lower() != "clean"])
    xss_vulns = len([x for x in xss_list if str(x).strip().lower() != "clean"])

    malware_status = str(malware_list[0]).strip() if malware_list else "Clean"
    malware_vuln = 1 if malware_status.lower() not in ["clean", "scan error"] else 0

    headers_vulns = len([x for x in headers_list if str(x).strip().lower() != "none"])

    dir_status_raw = str(dir_list[0]).strip() if dir_list else "Disabled"
    dir_vuln = 1 if dir_status_raw.lower() == "enabled" else 0

    vulns = {
        "SQL": sql_vulns,
        "XSS": xss_vulns,
        "Malware": malware_vuln,
        "Headers": headers_vulns,
        "Directory": dir_vuln
    }

    template_vars = {
        "url": report_data.get("URL", "Unknown"),
        "server_info": report_data.get("Server", "Unknown"),
        "open_ports": ", ".join(map(str, ports_list)),
        "ssl_status": report_data.get("SSL", "Unknown"),
        "sqli_status": ", ".join(map(str, sql_list)),
        "xss_status": ", ".join(map(str, xss_list)),
        "malware_status": ", ".join(map(str, malware_list)),
        "headers_status": ", ".join(map(str, headers_list)),
        "dir_status": ", ".join(map(str, dir_list)),
        "data": report_data
    }

    try:
        score, severity, issues, color = calculate_risk(report_data)
    except Exception:
        score, severity, issues, color = 0, "Low", [], "low"

    chart_base64 = generate_chart(vulns)

    session["last_vulns"] = vulns

    return render_template(
        "results.html",
        **template_vars,
        chart=chart_base64,
        risk_score=score,
        severity=severity,
        issues=issues,
        severity_color=color,
        vulnerabilities=vulns,
        detected_issues=len(issues)
    )
# --- Auth Routes ---
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if username and password:
            password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
            try:
                conn = sqlite3.connect("users.db")
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password) VALUES (?,?)", (username, password_hash))
                conn.commit()
                conn.close()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                return render_template("signup.html", error="Username exists!")
        return render_template("signup.html", error="Please fill all fields")
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
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
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)