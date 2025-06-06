from flask import Flask, render_template, request, redirect, session
from utils.pdf_generator import generate_pdf_report
from flask_cors import CORS  # ✅ Add this
import requests
import sqlite3
import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '51689a99b9c591b6e2eaf45b33e319252fab06fd7bd11841c7db64b5021948b4')

# ✅ Allow only your frontend origin
CORS(app, origins=["https://sqlidetect.onrender.com"], supports_credentials=True)

# --- DB INIT ---
def init_db():
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        method TEXT,
        payload TEXT,
        result TEXT,
        timestamp TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )''')
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'admin123'))
    conn.commit()
    conn.close()

init_db()

# --- SQLi Detection Logic ---
def is_vulnerable(url):
    payloads = ["'", "' OR 1=1 --", "' OR 'a'='a", '" OR "1"="1', "'; DROP TABLE users; --"]
    for payload in payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url, timeout=5)
            if any(error in response.text.lower() for error in ["sql syntax", "mysql", "error in your", "query failed"]):
                return payload, "VULNERABLE"
        except:
            pass
    return "", "SAFE"

# --- Routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    method = request.form.get('method', 'GET')
    payload, result = is_vulnerable(url)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute("INSERT INTO logs (url, method, payload, result, timestamp) VALUES (?, ?, ?, ?, ?)",
              (url, method, payload, result, timestamp))
    conn.commit()
    conn.close()

    scan_data = {
        'url': url,
        'method': method,
        'payload': payload,
        'result': result,
        'timestamp': timestamp
    }
    pdf_path = generate_pdf_report(scan_data)

    return render_template("index.html", result=result, payload=payload, pdf=pdf_path)

@app.route('/logs')
def logs():
    if not session.get('logged_in') or session.get('user') != 'admin':
        return redirect('/login')
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return render_template("logs.html", logs=rows)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        if u != 'admin':
            return render_template("login.html", error="Only admin can log in.")
        
        conn = sqlite3.connect("scans.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p))
        user = c.fetchone()
        conn.close()

        if user:
            session['logged_in'] = True
            session['user'] = u
            return redirect('/')
        else:
            return render_template("login.html", error="Invalid credentials.")
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/admin')
def admin():
    if not session.get('logged_in') or session.get('user') != 'admin':
        return redirect('/login')
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    logs = c.fetchall()
    conn.close()
    return render_template("admin.html", logs=logs)

@app.route('/delete-log/<int:id>')
def delete_log(id):
    if not session.get('logged_in') or session.get('user') != 'admin':
        return redirect('/login')
    conn = sqlite3.connect("scans.db")
    c = conn.cursor()
    c.execute("DELETE FROM logs WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect('/admin')

@app.route('/test-http')
def test_http():
    import requests
    try:
        r = requests.get("https://example.com", timeout=5)
        return f"Success! Status code: {r.status_code}"
    except Exception as e:
        return f"Failed: {str(e)}"

@app.route('/toggle-theme')
def toggle_theme():
    theme = session.get('theme', 'light')
    session['theme'] = 'dark' if theme == 'light' else 'light'
    return redirect(request.referrer or '/')

# --- Run Server ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))  # 10000 is a Render-safe default
    app.run(host='0.0.0.0', port=port)
