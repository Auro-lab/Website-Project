from flask import Flask, flash, render_template, request, redirect, url_for, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import os
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Use environment variables for better security
app.secret_key = os.getenv("FLASK_SECRET_KEY", "ss123")  # Default value if not found

# Flask mail configuration (use environment variables for security)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER"),
)
mail = Mail(app)

# Database connection using environment variables
db = mysql.connector.connect(
    host=os.getenv("DB_HOST", "localhost"),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME")
)
cursor = db.cursor()

# Initialize the serializer once with the app's secret key
serializer = URLSafeTimedSerializer(app.secret_key)

# Function to generate a random verification token
def generate_verification_token():
    return secrets.token_hex(16)  # More secure random token generation

# Function to send verification email
def send_verification_email(email, token):
    verification_url = url_for('verify_email', token=token, _external=True)
    msg = Message('Email Verification', recipients=[email])
    msg.body = f"Please verify your email by clicking the following link: {verification_url}"
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

# Routes (login, signup, etc.) go here...
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("user_name")
        password = request.form.get("user_pass")

        cursor = db.cursor()
        cursor.execute("SELECT password, is_verified, verification_token_expires FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            hashed_password, is_verified, verification_token_expires = result

            if check_password_hash(hashed_password, password):
                if is_verified:
                    session['username'] = username
                    flash("Logged in successfully!", "success")
                    return redirect(url_for('dashboard'))  # or 'successful' if that’s your route
                else:
                    if datetime.utcnow() > verification_token_expires:
                        cursor.execute("UPDATE users SET verification_token = NULL WHERE username = %s", (username,))
                        db.commit()
                        flash("Your verification link has expired. Please request a new one.", "warning")
                        return redirect(url_for('resend_verification'))
                    else:
                        flash("Please verify your email before logging in.", "warning")
                        return redirect(url_for('login'))
            else:
                flash("Invalid username or password.", "error")
                return redirect(url_for('login'))
        else:
            flash("Invalid username or password.", "error")
            return redirect(url_for('login'))

    return render_template("login.html")

# Resend verification logic
@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form['email']
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            if user['is_verified']:
                flash("Your account is already verified!", "success")
                return redirect(url_for('login'))

            # Clear any old token and expiration time
            cursor.execute("UPDATE users SET verification_token = NULL, verification_token_expires = NULL WHERE email = %s", (email,))
            db.commit()

            # Generate a new token and set expiration
            new_token = generate_verification_token()  # Create a new token
            expiration_time = datetime.utcnow() + timedelta(hours=24)

            cursor.execute("""
                UPDATE users
                SET verification_token = %s, verification_token_expires = %s
                WHERE email = %s
            """, (new_token, expiration_time, email))
            db.commit()

            send_verification_email(user['email'], new_token)  # send email

            flash("A new verification email has been sent.", "success")
            return redirect(url_for('login'))

        else:
            flash("No user found with this email address.", "error")
            return redirect(url_for('resend_verification'))

    return render_template('resend_verification.html')

# Email confirmation logic
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=300)  # 5 minutes expiry
    except SignatureExpired:
        flash('The confirmation link has expired.', 'error')
        return redirect(url_for('signup'))
    except BadSignature:
        flash('Invalid confirmation token.', 'error')
        return redirect(url_for('signup'))

    cursor = db.cursor()
    cursor.execute("SELECT is_verified FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user is None:
        flash('User not found.', 'error')
        return redirect(url_for('signup'))

    if user[0]:
        flash('Account already verified. Please log in.', 'info')
        return redirect(url_for('login'))

    cursor.execute("UPDATE users SET is_verified = 1 WHERE email = %s", (email,))
    db.commit()
    cursor.close()

    flash('Your account has been verified! You can now log in.', 'success')
    return redirect(url_for('login'))

# Signup logic and other routes follow...
