from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from scanner import scan_url
from flask_cors import CORS
import datetime

app = Flask(__name__)
CORS(app)

app.secret_key = '51689a99b9c591b6e2eaf45b33e319252fab06fd7bd11841c7db64b5021948b4'  # Required for session

# Simulated in-memory log storage
logs_store = []

# Hardcoded admin login (you can replace with DB later)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

# -----------------------------
# API for scanning
# -----------------------------
@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    target_url = data.get('url')

    if not target_url:
        return jsonify({'error': 'No URL provided'}), 400

    results = scan_url(target_url)
    vulnerable = len(results) > 0
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Save to logs_store
    log_entry = [
        len(logs_store) + 1,      # ID
        target_url,               # URL
        'GET',                    # Method (for now, assume GET)
        ', '.join(results),       # Payloads
        'Vulnerable' if vulnerable else 'Safe',  # Result
        timestamp                 # Time
    ]
    logs_store.append(log_entry)

    return jsonify({
        'vulnerable': vulnerable,
        'details': results
    })

# -----------------------------
# Admin Routes
# -----------------------------
@app.route('/admin')
def admin_panel():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('admin.html', logs=logs_store)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['username'] = username
            return redirect(url_for('admin_panel'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/delete-log/<int:log_id>', methods=['POST'])
def delete_log(log_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    global logs_store
    logs_store = [log for log in logs_store if log[0] != log_id]
    return redirect(url_for('admin_panel'))




@app.route('/test-http')
def test_http():
    import requests
    try:
        r = requests.get("https://example.com", timeout=5)
        return f"Success! Status code: {r.status_code}"
    except Exception as e:
        return f"Failed: {str(e)}"

# -----------------------------
# Home Route
# -----------------------------
@app.route('/')
def home():
    return render_template('index.html')  # Optional landing page

if __name__ == '__main__':
    app.run(debug=True)
