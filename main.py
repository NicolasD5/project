# Import Flask and its core components for web application functionality
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
# Import Bcrypt for secure password hashing
from flask_bcrypt import Bcrypt
# Import SQLite3 for database operations
import sqlite3
# Import logging for application event tracking
import logging
# Import custom encryption functions for data security
from encryption import encrypt_data, decrypt_data
# Import timedelta for session duration management
from datetime import timedelta
# Import random and string for verification code generation
import random
import string
# Import OS for file path operations
import os
# Import secure_filename for safe file uploads
from werkzeug.utils import secure_filename
# Import custom password validation class
from password_validation import PasswordValidator
# Import rate limiting functionality
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect
from flask_limiter.util import get_remote_address

import base64

# Create Flask application instance
app = Flask(__name__)

# Initialise CSRF protection
csrf = CSRFProtect(app)

# Initialise rate limiter with IP-based tracking and stricter limits
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],  # Set default rate limits
    storage_uri="memory://",  # Store rate limit data in memory
)

app.secret_key = 'jRFfOua3p9yNAVv6d8ygf-d3g1OTcCnQw4_GZ0kwBag='  #Hardcoded secret key for encryption
bcrypt = Bcrypt(app)  # Initialise Bcrypt for password hashing
logger = logging.getLogger(__name__)
logging.basicConfig(filename='security_log.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s')

# Configure session settings
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.permanent_session_lifetime = timedelta(minutes=15)

# Hardcoded admin credentials would be changed in production environment but for simplicity and demonstrating the roles it is hardcoded
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Store the generated admin verification code
admin_verification_code = None

# Configure file upload settings and only allow image file extensions and set the images to upload in the static folder
UPLOAD_FOLDER = 'static/profile_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True) #Ensure the upload folder exists as it makes a directory of it doesn't exist in the directory set in UPLOAD_FOLDER

@app.before_request
def before_request():
    #Generate a new nonce for each request which is part of the content security policy
    if 'nonce' not in g:
        g.nonce = base64.b64encode(os.urandom(16)).decode('utf-8')

@app.context_processor
def inject_nonce():
    #Make nonce available to all templates
    return dict(nonce=g.nonce)

@app.after_request
def add_security_headers(response):
    #Content Security Policy
    nonce = g.get('nonce', '')
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "                    #Only allow resources from same origin
        f"script-src 'self' 'nonce-{nonce}'; "     #Scripts only from same origin and with nonce
        "style-src 'self' 'unsafe-inline'; "      #Styles from same origin and inline (for Flask-WTF)
        "img-src 'self' data: blob:; "            #Images from same origin, data URIs, and blob
        "font-src 'self'; "                       #Fonts only from same origin
        "connect-src 'self'; "                    #AJAX/WebSocket only from same origin
        "media-src 'self'; "                      #Media only from same origin
        "frame-src 'none'; "                      #Deny iframe usage
        "frame-ancestors 'none'; "                #Prevent site from being embedded
        "object-src 'none'; "                     #Prevent object/embed/applet
        "base-uri 'self'; "                       #Restrict base tag
        "form-action 'self'; "                    #Forms can only submit to same origin
        "manifest-src 'self'; "                   #Web app manifest from same origin
        "worker-src 'self' blob:; "               #Workers only from same origin and blob
        "upgrade-insecure-requests; "             #Upgrade HTTP to HTTPS
    )
    
    #Additional Security Headers
    response.headers['X-Frame-Options'] = 'DENY'  #Prevent clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff'  #Prevent MIME type sniffing
    response.headers['X-XSS-Protection'] = '1; mode=block'  #Enable XSS filter
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  #Force HTTPS
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'  #Control referrer information
    response.headers['Permissions-Policy'] = (
        "accelerometer=(), "
        "camera=(), "
        "geolocation=(), "
        "gyroscope=(), "
        "magnetometer=(), "
        "microphone=(), "
        "payment=(), "
        "usb=()"
    )
    
    return response

def allowed_file(filename): #Check if the uploaded file has an allowed extension only allowing jpg and png as seen in the ALLOWED EXTENSIONS variable
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db(): #Create a database connection
    db = sqlite3.connect('database.db')
    db.row_factory = sqlite3.Row  # Allows accessing columns by name
    return db

def close_db(db): #Close the database connection 
    if db is not None:
        db.close()

def generate_verification_code(length=6): # Generate a random verification code for the admin login, "string.ascii_uppercase" ensures that the code is only uppercase letters and digits
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def username_exists(username): #Check if a username already exists in the database
    try:
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users")  # Get all users
        users = cursor.fetchall()
        
        for user in users:
            if decrypt_data(user['username']) == username:  #Compare decrypted usernames
                return True
        return False
    finally:
        close_db(connection)

def sanitise_input(value): #Escapes the html characters and stops XSS attacks
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
        .replace("/", "&#x2F;")
    )

def execute_safe_query(query, params=(), fetch_one=False): #Execute a parameterised SQL query safely."""
    try:
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute(query, params)
        
        if fetch_one:
            result = cursor.fetchone()
        else:
            result = cursor.fetchall()
            
        connection.commit()
        return result
    except Exception as e:
        logger.error(f"Database error in execute_safe_query function (main.py): {e}")
        raise
    finally:
        close_db(connection)

def validate_user_id(user_id): #Validate that user_id is a positive integer ensuring there are no invaild user ids
    try:
        user_id = int(user_id)
        if user_id <= 0:
            raise ValueError("Invalid user ID")
        return user_id
    except (ValueError, TypeError):
        raise ValueError("Invalid user ID")

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  #Limit login attempts
def login(): #Handle user login having the input fields of username and password
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        #Checks for admin login first before going to the database
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            global admin_verification_code
            admin_verification_code = generate_verification_code()
            print(f"\n=== ADMIN VERIFICATION CODE: {admin_verification_code} ===\n")
            return redirect(url_for('admin_dashboard'))
        
        try:
            conn = get_db()
            cursor = conn.cursor()

            #Get all users and compare decrypted usernames
            cursor.execute('SELECT * FROM users')
            users = cursor.fetchall()
            
            user = None
            for u in users:
                if decrypt_data(u['username']) == username:
                    user = u
                    break

            if user and bcrypt.check_password_hash(user['password'], password): #Checks if the password hash matches the hash of the password entered
                session['user_id'] = user['id'] #Sets the user id for the session
                session['username'] = username #Sets the session variables for displaying the user data on the customer dashboard
                session['mobile'] = decrypt_data(user['mobile']) if user['mobile'] else 'Not provided'
                session['address'] = decrypt_data(user['address']) if user['address'] else 'Not provided'
                session.permanent = True
                close_db(conn)
                return redirect(url_for('customer_dashboard'))
            
            logger.debug("User not found or invalid password")
            close_db(conn)
            flash('Invalid username or password')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Database error during login: {e}")
            close_db(conn)
            flash('An error occurred during login')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/customer_dashboard")
def customer_dashboard(): 
    user_id = session.get("user_id") #Gets the user id from the session to display the user data, and if not logged in it takes the user back to the login page
    if not user_id:
        logger.debug("No user_id in session. Redirecting to login.")
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))

    try:
        cursor = get_db().cursor()
        cursor.execute("SELECT profile_image FROM users WHERE id = ?", (user_id,)) #Fetches the image that is associated with the user id
        result = cursor.fetchone()
        
        user_data = {
            "id": user_id,
            "username": session.get("username"),
            "mobile": session.get("mobile"),
            "address": session.get("address"),
            "profile_image": result[0] if result and result[0] else "default.png"
        }
        logger.debug(f"User data fetched from session: {user_data}")
        return render_template("customer_dashboard.html", user_data=user_data)

    except Exception as e: #Handles the error if there is an error in fetching user data and redirects the user back to the login page to login again
        logger.error(f"Error fetching user data: {e}")
        flash("An error occurred while fetching user data.", "danger")
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    if session.get('is_admin'):
        try:
            connection = get_db()
            cursor = connection.cursor()
            cursor.execute("""
                UPDATE users 
                SET is_being_edited = 0, edited_by = NULL 
                WHERE edited_by = ?
            """, (ADMIN_USERNAME,))
            connection.commit()
        except Exception as e:
            logger.error(f"Error stopping SQL injection {e}")
    
    session.clear() #Ensures the session is removed when the user logs out
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/create_account", methods=["GET", "POST"])
@limiter.limit("10 per minute")  #Limit account creation
def create_account(): #Handle user account creation
    if request.method == "POST":
        username = sanitise_input(request.form.get("username", ""))
        password = request.form.get("password", "")
        email = sanitise_input(request.form.get("email", ""))
        mobile = sanitise_input(request.form.get("mobile", ""))
        address = sanitise_input(request.form.get("address", ""))
        security_answer_1 = request.form.get("security_question_1", "")
        security_answer_2 = request.form.get("security_question_2", "")

        #Validate required fields
        if not username or not password or not security_answer_1 or not security_answer_2:
            flash("All fields, including security answers, are required", "danger")
            return render_template("create_account.html")

        #Validate password using PasswordValidator to check if it meets the requirements for a secure password
        validation_result = PasswordValidator.validate_password(password)
        if not validation_result["valid"]:
            for error in validation_result["errors"]:
                flash(error, "danger")
            return render_template("create_account.html")

        
        if username_exists(username): #Check if username already exists so users cannot have the same username
            flash("Username is already taken. Please choose another.", "danger")
            return render_template("create_account.html")

        try:
            #Encrypt sanitised user data and hash the password
            encrypted_username = encrypt_data(username)
            encrypted_email = encrypt_data(email) if email else ""
            encrypted_mobile = encrypt_data(mobile) if mobile else ""
            encrypted_address = encrypt_data(address) if address else ""
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            #Handle profile image upload
            profile_image = None
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"{username}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename)) #Saves the file to the upload folder
                    profile_image = filename

            # Use execute_safe_query for inserting the user data in the database
            execute_safe_query(
                """INSERT INTO users (
                    username, password, email, mobile, address, 
                    profile_image, security_answer_1, security_answer_2
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (encrypted_username, hashed_password, encrypted_email, 
                 encrypted_mobile, encrypted_address, profile_image, 
                 security_answer_1, security_answer_2)
            )

            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            logger.error(f"Error creating account: {e}")
            flash("An error occurred while creating the account.", "danger")
            return redirect(url_for("create_account"))

    return render_template("create_account.html")

@app.route("/forgot_login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Limit password reset attempts
def forgot_login(): #Forgot login functionality allows users to change their password through verifying their identity through security questions
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        security_answer_1 = request.form.get("security_answer_1", "").strip()
        security_answer_2 = request.form.get("security_answer_2", "").strip()
        new_password = request.form.get("new_password", "").strip()

        if not username or not security_answer_1 or not security_answer_2 or not new_password: #Ensures all fields are filled in
            flash("All fields are required.", "danger")
            return redirect(url_for("forgot_login"))

        validation_result = PasswordValidator.validate_password(new_password) #Validates the new password
        if not validation_result["valid"]:
            for error in validation_result["errors"]:
                flash(error, "danger")
            return redirect(url_for("forgot_login"))

        try:
            user = execute_safe_query( #Fetches the user data from the database safely
                "SELECT * FROM users WHERE username = ?",
                (encrypt_data(username),),
                fetch_one=True
            )

            if not user:
                flash("Invalid username.", "danger")
                return redirect(url_for("forgot_login"))

            #Checks security answers to match the ones in the database
            if user['security_answer_1'] != security_answer_1 or user['security_answer_2'] != security_answer_2:
                flash("Security answers do not match.", "danger")
                return redirect(url_for("forgot_login"))

            #Update password using parameterised query
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            execute_safe_query(
                "UPDATE users SET password = ? WHERE username = ?",
                (hashed_password, user['username'])
            )

            flash("Password reset successfully! Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            logger.error(f"Error during password reset: {e}")
            flash("An error occurred while resetting your password.", "danger")
            return redirect(url_for("forgot_login"))

    return render_template("forgot_login.html")

@app.route("/admin_dashboard", methods=["GET", "POST"])
def admin_dashboard(): #Handle the admin login and verification
    if request.method == "POST":
        entered_code = request.form.get("verification_code")
        if entered_code == admin_verification_code:
            session['is_admin'] = True  #Establish admin session
            session['username'] = ADMIN_USERNAME
            flash("Admin verified successfully!", "success")
            return redirect(url_for("view_users"))
        else:
            flash("Invalid verification code. Please try again.", "danger")
    return render_template("admin_dashboard.html")

@app.route("/view_users")
def view_users(): #Display list of all users for the admin
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for("login"))

    try:
        #Ensure that it is executing a safe query and also ensures two cannot edit it at the same time
        execute_safe_query("""
            UPDATE users 
            SET is_being_edited = 0, edited_by = NULL 
            WHERE is_being_edited = 1
        """)
        
        # Fetch users with parameterised query
        users = execute_safe_query("""
            SELECT id, username, mobile, address, is_being_edited, edited_by 
            FROM users
        """)

        decrypted_users = []
        for user in users:
            decrypted_users.append({
                'id': user['id'],
                'username': decrypt_data(user['username']),
                'mobile': decrypt_data(user['mobile']),
                'address': decrypt_data(user['address']),
                'is_being_edited': bool(user['is_being_edited']),
                'edited_by': user['edited_by']
            })

        return render_template("view_users.html", users=decrypted_users)
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        flash("An error occurred while fetching user data.", "danger")
        return redirect(url_for("admin_dashboard"))

@app.route("/edit_user/<int:user_id>") 
def edit_user(user_id): #Allows admin to edit user data, taking the user id that was selected and giving the details and the ability to change them
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for("login"))

    try:
        #Validates user_id
        user_id = validate_user_id(user_id)
        
        execute_safe_query(""" 
            UPDATE users 
            SET is_being_edited = 0, edited_by = NULL 
            WHERE edited_by = ?
        """, (ADMIN_USERNAME,))
        
        # Get user data
        user = execute_safe_query(
            "SELECT * FROM users WHERE id = ?", 
            (user_id,), 
            fetch_one=True
        )

        if not user:
            flash("User not found", "danger")
            return redirect(url_for("view_users"))
        
        execute_safe_query("""
            UPDATE users 
            SET is_being_edited = 1, edited_by = ? 
            WHERE id = ?
        """, (ADMIN_USERNAME, user_id))

        user_data = {
            'id': user['id'],
            'username': decrypt_data(user['username']),
            'mobile': decrypt_data(user['mobile']),
            'address': decrypt_data(user['address'])
        }
        
        return render_template("edit_user.html", user=user_data)
    except ValueError as ve:
        flash(str(ve), "danger") #Handles error if user id is invalid
        return redirect(url_for("view_users"))
    except Exception as e:
        logger.error(f"Error accessing user data: {e}")
        flash("An error occurred", "danger")
        return redirect(url_for("view_users"))

@app.route("/update_user/<int:user_id>", methods=["POST"])
@limiter.limit("10 per minute")  #Limit update attempts
def update_user(user_id):
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for("login"))

    try:
        user_id = validate_user_id(user_id)
        
        #Validates input data
        new_mobile = sanitise_input(request.form.get("new_mobile", "").strip())
        new_address = sanitise_input(request.form.get("new_address", "").strip())
        
        if not new_mobile or not new_address:
            flash("Mobile and address cannot be empty", "danger")
            return redirect(url_for("edit_user", user_id=user_id))

        #Update user data with parameterised queries
        execute_safe_query(
            "UPDATE users SET mobile = ? WHERE id = ?", 
            (encrypt_data(new_mobile), user_id)
        )
        execute_safe_query(
            "UPDATE users SET address = ? WHERE id = ?", 
            (encrypt_data(new_address), user_id)
        )
        
        execute_safe_query("""
            UPDATE users 
            SET is_being_edited = 0, edited_by = NULL 
            WHERE id = ?
        """, (user_id,))
        
        flash("User data updated successfully!", "success")
        
    except ValueError as ve:
        flash(str(ve), "danger")
    except Exception as e:
        logger.error(f"Error updating user data: {e}")
        flash("An error occurred while updating user data.", "danger")
    
    return redirect(url_for("view_users"))

@app.route("/manage_users")
def manage_users(): #Displays the list of users
    if 'username' not in session or session['username'] != ADMIN_USERNAME:
        flash("Admin access required", "danger")
        return redirect(url_for("login"))

    try:
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT id, username, mobile, address, is_being_edited, edited_by 
            FROM users
        """)
        users = cursor.fetchall()

        decrypted_users = []
        for user in users:
            decrypted_users.append({
                'id': user['id'],
                'username': decrypt_data(user['username']),
                'mobile': decrypt_data(user['mobile']),
                'address': decrypt_data(user['address']),
                'is_being_edited': user['is_being_edited'],
                'edited_by': user['edited_by']
            })

        return render_template("manage_users.html", users=decrypted_users)
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        flash("An error occurred while fetching user data.", "danger")
        return redirect(url_for("admin_dashboard"))



@app.route("/") #Home page route
def home(): 
    nonce = base64.b64encode(os.urandom(16)).decode('utf-8')
    return render_template('home.html', nonce=nonce)

@app.errorhandler(404)
def page_not_found(e): #When a page is not found render the customer 404 page instead of rendering the default browser 404 error
    return render_template("404.html"), 404

@app.errorhandler(Exception)
def unhandled_exception(e):
    logger.error(f"Unhandled exception: {e}")
    return render_template("404.html"), 500

@app.errorhandler(429)  #Handles the exception when the rate limit is exceeded
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {e.description}")
    flash("Too many requests. Please try again later.", "danger")
    return redirect(url_for('login')), 429

@app.errorhandler(400) #Handles errors caused by CSRF token issues
def handle_csrf_error(e):
    logger.warning(f"CSRF token error: {e.description}")
    flash("Invalid form submission. Please try again.", "danger")
    return redirect(url_for('login')), 400

if __name__ == "__main__":
    app.run(debug=True)
