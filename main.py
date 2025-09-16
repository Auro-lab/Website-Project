from flask import Flask, flash, render_template, request, redirect, url_for, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message



app = Flask(__name__)
app.secret_key = "ss123"

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='laes.monsale.ui@phinmaed.com',
    MAIL_PASSWORD='hwavwpnxbdmfcqcb',  # <-- add this comma
    MAIL_DEFAULT_SENDER='laes.monsale.ui@phinmaed.com',
)
mail = Mail(app)


serializer = URLSafeTimedSerializer(app.secret_key)


db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Blue4Star!9",
    database="users_db"
)

cursor = db.cursor()


@app.route('/')
def home():
    return render_template("landing2.html")


    #**********************Log in route************************* #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("user_name")
        password = request.form.get("user_pass")

        cursor = db.cursor()
        cursor.execute("SELECT password, is_verified FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()

        if result:
            hashed_password, is_verified = result
            if check_password_hash(hashed_password, password):
                if is_verified:
                    session['username'] = username
                    flash("Logged in successfully!", "success")
                    return redirect(url_for('dashboard'))  # or 'successful' if that’s your route
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



      #**********************sign up route************************* #
from werkzeug.security import generate_password_hash
from flask import flash, redirect, render_template, request, url_for
import re
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))

        if not is_strong_password(password):
            flash("Password is too weak. It must be at least 8 characters, include an uppercase letter and a number.", "error")
            return redirect(url_for('signup'))

        cursor = db.cursor()

        # Check if email already exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user_email = cursor.fetchone()

        # Check if username already exists
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user_username = cursor.fetchone()

        if existing_user_email:
            flash("Email already registered. Please log in.", "error")
            return redirect(url_for("login"))
        if existing_user_username:
            flash("Username already taken. Please choose another.", "error")
            return redirect(url_for("signup"))

        # Hash password before storing
        hashed_password = generate_password_hash(password)

        # Insert user into DB with is_verified defaulting to 0
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, hashed_password)
        )
        db.commit()
        cursor.close()

        # ---------------- Email Verification ----------------
        try:
            token = serializer.dumps(email, salt='email-confirm')
            confirm_url = url_for('confirm_email', token=token, _external=True)

            html = f"""
            <html>
            <body>
                <p>Hi <strong>{username}</strong>,</p>
                <p>Thanks for registering!</p>
                <p>Please click the link below to verify your email address:</p>
                <p><a href="{confirm_url}">Verify Email</a></p>
                <br>
                <p>If you did not request this, just ignore this email.</p>
            </body>
            </html>
            """

            msg = Message("Please confirm your email", recipients=[email], html=html)
            mail.send(msg)
            print("✅ Verification email sent to:", email)
        except Exception as e:
            print("❌ Failed to send email:", str(e))
            flash("Error sending confirmation email. Please try again.", "error")
            return redirect(url_for("signup"))
        # -----------------------------------------------------

        flash("Registration successful! Please check your email to verify your account.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")



   #*********************email confirmation*************************#

# Initialize serializer somewhere in your app setup (only once)
serializer = URLSafeTimedSerializer(app.secret_key)

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

        


#**********************successful html************************* #
@app.route('/successful')
def successful():
    return render_template("successful.html")


#**********************dashboard route************************* #
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template("dashboard.html", username=session['username'])
    else:
        return redirect(url_for('login'))
    
    
    
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' in session:
        username = session['username']
        
        

        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Photosynthesis123",  
            database="users_db"
        )
        cursor = conn.cursor()

        
        cursor.execute("DELETE FROM students WHERE user_name = %s", (username,))
        conn.commit()

        cursor.close()
        conn.close()
        
        session.pop('username', None)

        return redirect(url_for('home'))  # back to landing
    else:
        return redirect(url_for('login'))





if __name__ == '__main__':
    app.run(debug=True)
