from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify, send_file
import sqlite3
from io import BytesIO
import base64
from database import db
from auth import login_required

key_bp = Blueprint('keys', __name__)


@key_bp.route('/keys', methods=['GET', 'POST'])
@login_required
def keys():
    user_id = session["user_id"]

    if request.method == 'POST':
        # New key storage
        if 'store_key' in request.form:
            key_name = request.form.get('key_name')
            key_value = request.form.get('key_value')
            algorithm = request.form.get('algorithm')
            try:
                if algorithm == 'AES':
                    key_length = len(key_value.encode('utf-8'))
                    if key_length not in [16, 24, 32]:
                        flash('AES key must be 16, 24, or 32 bytes.', 'danger')
                        return redirect(url_for('keys.keys'))
                elif algorithm == 'Blowfish':
                    key_length = len(key_value.encode('utf-8'))
                    if not (4 <= key_length <= 56):
                        flash('Blowfish key must be 4-56 bytes.', 'danger')
                        return redirect(url_for('keys.keys'))
                elif algorithm == 'ChaCha20':
                    if len(key_value) != 64 or not all(c in '0123456789abcdefABCDEF' for c in key_value):
                        flash('ChaCha20 key must be 64 hex characters.', 'danger')
                        return redirect(url_for('keys.keys'))
                    # Add database insertion
                db.execute('''INSERT INTO user_keys
                            (user_id, key_name, key_value, algorithm)
                            VALUES (?, ?, ?, ?)''',
                        user_id, key_name, key_value, algorithm)
                flash('Key stored successfully!', 'success')

            except sqlite3.IntegrityError as e:  # Add this except clause
                flash(f'Error: {str(e)}', 'danger')

            return redirect(url_for('keys.keys'))  # Add redirect here






    # Get user data
    user = db.get_user_by_id(user_id)
    stored_keys = db.execute("SELECT * FROM user_keys WHERE user_id = ?", user_id)

    return render_template('keys.html',
                         stored_keys=stored_keys)

@key_bp.route('/delete_key/<int:key_id>', methods=['POST'])
@login_required
def delete_key(key_id):
    user_id = session["user_id"]

    # Verify the key belongs to the user before deleting
    key = db.execute('SELECT * FROM user_keys WHERE id = ? AND user_id = ?', key_id, user_id)
    if not key:
        flash("Key not found or access denied", "danger")
        return redirect(url_for('keys.keys'))

    db.execute('DELETE FROM user_keys WHERE id = ?', key_id)
    flash("Key deleted successfully", "success")
    return redirect(url_for('keys.keys'))

@key_bp.route('/download', methods=['POST'])
def download_result():
    result_data = request.form.get('result_data')
    if not result_data:
        return "No data to download", 400

    buffer = BytesIO(base64.b64decode(result_data))
    return send_file(
        buffer,
        as_attachment=True,
        download_name="secret_image.png",
        mimetype="image/png"
    )

@key_bp.route('/history')
@login_required
def history():
    user_id = session["user_id"]
    messages = db.get_user_messages(user_id)
    return render_template('history.html', messages=messages)

@key_bp.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    user_id = session["user_id"]
    db.delete_message(message_id, user_id)
    return redirect(url_for('keys.history'))

@key_bp.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    user_id = session["user_id"]
    db.clear_user_history(user_id)
    return redirect(url_for('keys.history'))

@key_bp.route('/get_keys')
@login_required
def get_keys():
    algorithm = request.args.get('algorithm', '')
    keys = db.execute('''SELECT key_name, key_value FROM user_keys
                      WHERE user_id = ? AND algorithm = ?''',
                    session["user_id"], algorithm)
    return jsonify([dict(k) for k in keys])
