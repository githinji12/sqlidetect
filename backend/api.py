from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from scanner import scan_url
import datetime

app = Flask(__name__)

# Use your provided secret key (in production, use environment variable instead)
app.secret_key = "51689a99b9c591b6e2eaf45b33e319252fab06fd7bd11841c7db64b5021948b4"

# CORS setup to allow frontend hosted on Render
CORS(app, origins=["https://sqlidetect.onrender.com"], supports_credentials=True)

# In-memory log store (temporary - use DB later)
logs_store = []

# Admin login credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

# -----------------------------
# API Endpoint for SQLi Scan
# -----------------------------
@app.route('/api/scan', methods=['POST', 'OPTIONS'])
def scan():
    # Handle preflight
    if request.method == 'OPTIONS':
        return '', 200

    data = request.get_json()
    target_url = data.get('url')

    if not target_url:
        return jsonify({'error': 'No URL provided'}), 400

    results = scan_url(target_url)
    vulnerable = len(results) > 0
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    log_entry = [
        len(logs_store) + 1,
        target_url,
        'GET',
        ', '.join(results),
        'Vulnerable' if vulnerable else 'Safe',
        timestamp
    ]
    logs_store.append(log_entry)

    return jsonify({
        'vulnerable': vulnerable,
        'details': results
    })

# -----------------------------
# Admin Dashboard Routes
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

# -----------------------------
# Optional Home Page
# -----------------------------
@app.route('/')
def home():
    return render_template('index.html')

# -----------------------------
# Run Local Dev Server
# -----------------------------
if __name__ == '__main__':
    app.run(debug=True)
