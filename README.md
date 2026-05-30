# Web Penetration Testing Toolkit

A lightweight Flask-based web penetration testing toolkit for reconnaissance and basic vulnerability scanning. This project provides a browser UI with authentication, target scanning, issue reporting, and PDF export.

## Features

- User authentication with signup/login
- Target URL scanning via a web interface
- Reconnaissance: server headers, IP resolution, port scanning, technology detection
- Security checks: HTTP security headers, directory listing discovery
- Exploit checks: basic SQL injection and reflected XSS detection
- Malware scan: suspicious script and page analysis
- SSL validation and certificate inspection
- Risk score calculation with summary chart
- Export scan results to PDF

## Project Structure

- `app.py` – Flask application and route handlers
- `modules/recon.py` – target information gathering and port scanning
- `modules/scanner.py` – security header audit and directory listing checks
- `modules/exploit.py` – SQL injection and XSS detection logic
- `modules/malware.py` – malware signature scanning
- `modules/ssl_check.py` – SSL certificate and TLS validation
- `modules/charts.py` – chart generation for scan results
- `modules/risk_engine.py` – risk scoring and severity classification
- `templates/` – HTML templates for signup, login, index, and results
- `static/style.css` – application styling

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ashrithakadarla/web-pentest-toolkit.git
   cd web-pentest-toolkit
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the Flask app:
   ```bash
   python app.py
   ```

2. Open your browser and go to:
   ```text
   http://localhost:5000
   ```

3. Create an account via the signup page, then log in.
4. Enter a target URL and submit the form to run the scan.
5. Review the results page and download the PDF report if needed.

## Deployment

The project includes a `Procfile` for deployment on platforms like Heroku.

Example command:
```bash
gunicorn app:app
```

## Notes

- This toolkit is intended for educational and authorized testing only.
- Do not use it against systems without explicit permission.
- The scan logic is basic and should not replace full professional penetration testing tools.

## Requirements

- Flask
- requests
- beautifulsoup4
- python-nmap
- gunicorn
- flask-login
- flask-bcrypt
- fpdf
- matplotlib

## License

This repository does not include a license file. Add one if you plan to distribute or reuse the code publicly.
