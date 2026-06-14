from flask import Flask, request, jsonify, render_template, redirect, url_for,Blueprint,send_from_directory
from flask_cors import CORS
import json
from flask import session
import os
import matplotlib.pyplot as plt
import bcrypt
from extensions import socketio  # Import the socketio instance
from server import server_api
from flask_socketio import SocketIO
import uuid  # For generating unique file IDs
from protocol import protocol_api  # Import the Blueprint from protocol.py
from pcap import pcap_api  # Import the Blueprint from pcap.py
from analyzer import analyze_pcap_for_web

app = Flask(__name__,static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret')
CORS(app)  # Allow frontend to communicate
socketio.init_app(app, cors_allowed_origins='*')
app.register_blueprint(server_api)
app.register_blueprint(protocol_api, url_prefix='/api/protocol')
app.register_blueprint(pcap_api, url_prefix='/api/pcap')

# Path for JSON file
USERS_FILE = "users.json"

# --- USER AUTHENTICATION HANDLING ---

# Load users from JSON file
def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

# Save users to JSON file
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)


# --- ROUTES ---

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

# API: User Login
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    users = load_users()

    if email not in users:
        return jsonify({"success": False, "message": "User not found"}), 401

    stored_hashed_password = users[email].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        return jsonify({"success": False, "message": "Invalid password"}), 401

    return jsonify({"success": True, "message": "Login successful"}), 200


# API: User Signup
@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    users = load_users()

    if email in users:
        return jsonify({"success": False, "message": "Email already registered"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users[email] = hashed_password
    save_users(users)

    return jsonify({"success": True, "message": "User registered successfully"}), 201


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route('/profile')
def profile():
    return render_template('profile.html')


@app.route("/protocol")
def protocol():
    return render_template("protocol.html")

@app.route("/pcap_index")
def pcap_index():
    return render_template("pcap_index.html")


@app.route('/homepage')
def homepage():
    return render_template("homepage.html")


# --- PCAP UPLOAD & ANALYSIS SYSTEM ---

# Render PCAP upload page

# Render Analysis page
@app.route('/analyze')
def analyze_page():
    return render_template('analyze.html')


@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

# --- SOCKET IO TEST (Optional, if used elsewhere) ---
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

    # --- MAIN RUN ---
if __name__ == '__main__':
    # Bind to 0.0.0.0 to allow external connections on Tencent Cloud
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)