from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from extensions import limiter
from database import db

auth_bp = Blueprint('auth', __name__)


# Add login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        user = db.get_user_by_id(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def password_meets_requirements(password):
    """Check if password meets minimum security requirements"""
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters")
    if not any(char.isupper() for char in password):
        errors.append("Password must contain at least one uppercase letter")
    if not any(char.islower() for char in password):
        errors.append("Password must contain at least one lowercase letter")
    if not any(char.isdigit() for char in password):
        errors.append("Password must contain at least one number")
    if not any(char in "!@#$%^&*()-_=+[]{}|;:,.<>?/`~" for char in password):
        errors.append("Password must contain at least one special character")

    if errors:
        return False, "• " + "<br>• ".join(errors)
    return True, ""

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # Check password match
        if password != confirmation:
            return render_template('register.html', error="Passwords do not match")

        # Check password strength
        is_valid, error_msg = password_meets_requirements(password)
        if not is_valid:
            return render_template('register.html', error=error_msg)

        # Check if username exists
        if db.get_user_by_username(username):
            return render_template('register.html', error="Username already exists")

        # Create user with empty public key (generate later)
        if db.create_user(username, password, None):
            return redirect(url_for('auth.login'))
        else:
            return render_template('register.html', error="Registration failed")

    # GET request - show registration form
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/5 minute", methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = db.verify_user(username, password)

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for('encryption.index'))

        return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('encryption.index'))

@auth_bp.route('/password-generator')
def password_generator():
    return render_template('password_generator.html')

@auth_bp.route('/newpassword', methods=['GET', 'POST'])
@login_required
def newpassword():
    if request.method == 'POST':
        current_password = request.form.get('currentpassword')
        new_password = request.form.get('newpassword')
        confirmation = request.form.get('confirmation')

        user = db.get_user_by_username(session["username"])

        if not check_password_hash(user['hash'], current_password):
            return render_template('newpassword.html', error="Current password is incorrect")

        if new_password != confirmation:
            return render_template('newpassword.html', error="New passwords don't match")

        db.execute("UPDATE users SET hash = ? WHERE id = ?",
                   generate_password_hash(new_password), session["user_id"])
        return render_template('newpassword.html', success=True)

    return render_template('newpassword.html')
