import os
import secrets
from flask import Flask, request, jsonify, redirect, session, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import date
import logging

# Google OAuth imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
from email.mime.text import MIMEText

# FIX for InsecureTransportError (for local HTTP testing only)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# --- App Configuration ---
app = Flask(__name__)
CORS(app, supports_credentials=True)
# FLASK_SECRET_KEY ko environment variable se lena sabse best hai
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default-super-secret-key-for-local-dev')
logging.basicConfig(level=logging.INFO)

# --- Reading Secrets from Environment Variables ---
NEON_DATABASE_URL = os.environ.get('NEON_DATABASE_URL')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://mailpilott.netlify.app') # Aapka Netlify URL
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
PRO_ACTIVATION_CODE = "DEVLAKHAN_PRO_2025"


# Google OAuth config, ab file ki zaroorat nahi
google_oauth_config = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris": [], # Isko hum dynamically set karenge
    }
}

def get_db_connection():
    """Establishes a connection to the Neon.tech PostgreSQL database."""
    try:
        conn = psycopg2.connect(NEON_DATABASE_URL)
        return conn
    except psycopg2.OperationalError as e:
        logging.error(f"Database connection error: {e}")
        return None

def get_user_from_token(return_full_user=False):
    """Helper function to get user from Bearer token"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '): return None
    
    token = auth_header.split(' ')[1]
    conn = get_db_connection()
    if not conn: return None
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM users WHERE token = %s', (token,))
    user = cursor.fetchone()
    conn.close()
    return user if return_full_user else None

# --- Main API Routes ---

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not all(k in data for k in ('name', 'email', 'password')):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    name, email, password = data['name'], data['email'], data['password']
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT id FROM users WHERE email = %s', (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"success": False, "message": "Email address is already registered"}), 409

    hashed_password = generate_password_hash(password)
    cursor.execute(
        'INSERT INTO users (name, email, password) VALUES (%s, %s, %s)',
        (name, email, hashed_password)
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Signup successful! Please log in."}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
    user = cursor.fetchone()
    
    if not user or not check_password_hash(user['password'], password):
        conn.close()
        return jsonify({"success": False, "message": "Invalid credentials"}), 401
        
    token = secrets.token_hex(20)
    cursor.execute('UPDATE users SET token = %s WHERE id = %s', (token, user['id']))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "token": token, "username": user['name']}), 200

@app.route('/api/dashboard-data', methods=['GET'])
def get_dashboard_data():
    user = get_user_from_token(return_full_user=True)
    if not user:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 401

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    cursor.execute("SELECT * FROM contacts WHERE user_id = %s ORDER BY name", (user['id'],))
    contacts = cursor.fetchall()
    cursor.execute("SELECT * FROM templates WHERE user_id = %s ORDER BY template_name", (user['id'],))
    templates = cursor.fetchall()
    
    conn.close()

    quota = 50 if user['plan'] == 'free' else 5000
    
    return jsonify({
        "success": True, "username": user['name'], "plan": user['plan'],
        "emailsSent": user['emails_sent_today'], "quota": quota,
        "isGmailConnected": bool(user.get('gmail_refresh_token')),
        "contacts": contacts,
        "templates": templates
    }), 200

# --- Google OAuth Routes ---

@app.route('/authorize-gmail')
def authorize_gmail():
    user = get_user_from_token(return_full_user=True)
    if not user:
        return jsonify({"success": False, "message": "User not authenticated"}), 401
    
    flow = Flow.from_client_config(
        client_config=google_oauth_config,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline', include_granted_scopes='true', state=str(user['id'])
    )
    session['state'] = state
    return jsonify({'authorization_url': authorization_url})

@app.route('/oauth2callback')
def oauth2callback():
    user_id = request.args.get('state')
    flow = Flow.from_client_config(
        client_config=google_oauth_config, scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET gmail_access_token = %s, gmail_refresh_token = %s WHERE id = %s",
        (credentials.token, credentials.refresh_token, user_id)
    )
    conn.commit()
    conn.close()
    return redirect(f"{FRONTEND_URL}/account.html?gmail=connected")

@app.route('/api/send-email', methods=['POST'])
def send_email():
    user = get_user_from_token(return_full_user=True)
    if not user or not user['gmail_refresh_token']:
        return jsonify({"success": False, "message": "Gmail not connected or invalid user"}), 401

    data = request.get_json()
    to_email, subject, message_text = data.get('to'), data.get('subject'), data.get('message')

    credentials = Credentials(
        token=user['gmail_access_token'],
        refresh_token=user['gmail_refresh_token'],
        token_uri='https://oauth2.googleapis.com/token',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET
    )

    try:
        service = build('gmail', 'v1', credentials=credentials)
        message = MIMEText(message_text)
        message['to'] = to_email
        message['subject'] = subject
        create_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
        
        service.users().messages().send(userId='me', body=create_message).execute()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET emails_sent_today = emails_sent_today + 1 WHERE id = %s", (user['id'],))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Email sent successfully!"}), 200

    except HttpError as error:
        logging.error(f'An error occurred: {error}')
        return jsonify({"success": False, "message": "Failed to send email."}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
    
