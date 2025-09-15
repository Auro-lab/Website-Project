from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector

app = Flask(__name__)
app.secret_key = "ss123"

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Photosynthesis123",
    database="users_db"
)

# --------------------------------------------------------------------------------------------------------------------

@app.route('/')
def home():
    return render_template("landing2.html")

# --------------------------------------------------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("user_name")
        password = request.form.get("user_pass")

        cursor = db.cursor()
        cursor.execute("SELECT * FROM students WHERE user_name = %s AND user_pass = %s", (username, password))
        user = cursor.fetchone()   # just fetch one row
        cursor.close()

        if user:
            session['username'] = username
            print("DEBUG: Logged in as", session['username'])
            return redirect(url_for('successful'))
        else:
            return "<h3>❌ INVALID CREDENTIALS</h3><a href='/login'>TRY AGAIN</a>"

    return render_template("login.html")

# --------------------------------------------------------------------------------------------------------------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        cursor = db.cursor()
        # check if username already exists
        cursor.execute("SELECT * FROM students WHERE user_name = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            return "<h3>⚠️ USERNAME ALREADY TAKEN</h3><a href='/signup'>TRY AGAIN</a>"

        # insert new user into DB
        cursor.execute("INSERT INTO students (user_name, user_pass) VALUES (%s, %s)", (username, password))
        db.commit()
        cursor.close()

        # ✅ after signup, go to login page (not auto-login)
        return redirect(url_for('login'))

    return render_template("signup.html")

# --------------------------------------------------------------------------------------------------------------------
@app.route('/successful')
def successful():
    return render_template("successful.html")

# --------------------------------------------------------------------------------------------------------------------
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template("dashboard.html", username=session['username'])
    else:
        return redirect(url_for('login'))

# --------------------------------------------------------------------------------------------------------------------
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# --------------------------------------------------------------------------------------------------------------------
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
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

# --------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
