from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from auth import add_user, login_user, get_passwords_for_user
from database import init_db
from password_generator import decrypt_with_private_key

import base64
import os

import sqlite3 as sq

DB_NAME = "database.db"

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'frontend'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
app.secret_key = os.urandom(24)

# Start database
init_db()

# Route for default page
@app.route("/")
def home():
    return redirect(url_for("register"))


# Route for register page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Fetch username and password input from the registration form (frontend)
        username = request.form["username"]
        password = request.form["password"]

        # Fetch the private key after creating user
        private_key = add_user(username, password)

        if private_key is None:
            flash("[ERROR] Registration failed: Username may already exist", "danger")
            return redirect(url_for("register"))
        
        # If private key is retrieved successfully, render page with private key passed as an argument
        return render_template("show_private_key.html", private_key=private_key)
    
    return render_template("register.html")

# Route for login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Fetch username and password from the login form (frontend)
        username = request.form["username"]
        password = request.form["password"]

        # Fetch user id after user login
        user_id = login_user(username, password)

        if user_id:
            # Save username and user id to display on the dashboard
            session["username"] = username
            session["user_id"] = user_id
            return redirect(url_for("dashboard"))
        else:
            flash("[ERROR] Invalid credentials", "danger")
        

    return render_template("login.html")

# Route for dashboard page
@app.route("/dashboard")
def dashboard():
    # Check if user is logged in and redirect to login page if not true
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    passwords = get_passwords_for_user(session["user_id"])
    return render_template("dashboard.html", username=session.get("username"), passwords=passwords)

# Route for add-password page
@app.route("/add-password", methods=["GET", "POST"])
def add_password():
    # Check if user is logged in and redirect to login page if not true
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        # Fetch password name and password itself from the add-password form (frontend)
        password_name = request.form["password_name"]
        encrypted_password = request.form["password_text"]

        try:
            encrypted_password_bytes = base64.b64decode(encrypted_password)

            # Each encrypted password has to be exactly 256 bytes
            # Validate encrypted password
            if len(encrypted_password_bytes) != 256:
                flash(f"Invalid ciphertext length: {len(encrypted_password_bytes)} bytes, expected 256 bytes", "danger")
                return redirect(url_for("add-password"))
            
            
            conn = sq.connect(DB_NAME)
            cursor = conn.cursor()

            cursor.execute("INSERT INTO passwords (user_id, password_name, password_text) VALUES (?, ?, ?)", (session["user_id"], password_name, encrypted_password))

            conn.commit()
            conn.close()

            flash("Password saved successfully", "success")
        except base64.binascii.Error as e:
            flash(f"Invalid base64 format: {str(e)}", "danger")
            return redirect(url_for("add_password"))
        except Exception as e:
            flash(f"Error saving password: ${str(e)}", "danger")
            return redirect(url_for("add_password"))
        
        return redirect(url_for("dashboard"))
    
    return render_template("add_password.html")

# Helper endpoint for password decryption
@app.route("/decrypt-password/<password_id>", methods=["POST"])
def decrypt_password(password_id):
    # Check if user is logged in the session and throw error if not true
    if "user_id" not in session:
        return jsonify({ "success": False, "error": "Unauthorized" }), 401
    
    # Fetch private key
    data = request.get_json()
    private_key = data.get("private_key")

    if not private_key:
        return jsonify({ "success": False, "error": "Missing private key" }), 400
    
    conn = sq.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT password_text FROM passwords WHERE id = ? AND user_id = ?", (password_id, session["user_id"]))
    result = cursor.fetchone()

    conn.close()

    if not result:
        return jsonify({ "success": False, "error": "Password not found for user" }), 404
    

    encrypted_password = result[0]

    try:
        decrypted = decrypt_with_private_key(encrypted_password, private_key)
        return jsonify({ "success": True, "password": decrypted })
    except Exception as e:
        return jsonify({ "success": False, "error": str(e) }), 400
    
# Helper endpoint for public key fetching
@app.route("/get-public-key")
def get_public_key():
    # Check if user is logged in the session and throw error if not true
    if "user_id" not in session:
        return jsonify({ "error": "Unauthorized" }), 401
    
    conn = sq.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT public_key FROM users WHERE id = ?", (session["user_id"],))
    result = cursor.fetchone()

    conn.close()

    if not result:
        return jsonify({ "error": "User not found" }), 404
    
    public_key_pem = result[0]

    return jsonify({ "public_key": public_key_pem.decode("utf-8") })

# Helper endpoint to logout the user
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("login"))


# Start up the project
if __name__ == "__main__":
    app.run(debug=True)

        