import base64
import logging
from encryption_methods.aes import aes_handler
from encryption_methods.base64 import encrypt as base64_encrypt, decrypt as base64_decrypt
from encryption_methods.blowfish import encrypt as blowfish_encrypt, decrypt as blowfish_decrypt
from encryption_methods.caesar_cipher import encrypt as caesar_encrypt, decrypt as caesar_decrypt
from encryption_methods.chacha20 import encrypt as chacha20_encrypt, decrypt as chacha20_decrypt
from encryption_methods.rot13 import encrypt as rot13_encrypt, decrypt as rot13_decrypt
from encryption_methods.vigenere import encrypt as vigenere_encrypt, decrypt as vigenere_decrypt
from extensions import limiter
from flask import Blueprint, render_template, request, jsonify, send_file, session
from PIL import Image
from database import db
from io import BytesIO

encryption_bp = Blueprint('encryption', __name__)


# Mapping for encryption methods with their corresponding functions
encryption_methods = {
    "aes": {
        "encrypt": lambda data, key: aes_handler.encrypt(data, key),
        "decrypt": lambda data, key: aes_handler.decrypt(data, key)
    },
    "base64": {
        "encrypt": base64_encrypt,
        "decrypt": base64_decrypt
    },
    "blowfish": {
        "encrypt": lambda data, key: blowfish_encrypt(data, key),
        "decrypt": lambda data, key: blowfish_decrypt(data, key)
    },
    "caesar": {
        "encrypt": lambda msg, shift: caesar_encrypt(msg, shift),
        "decrypt": lambda msg, shift: caesar_decrypt(msg, shift)
    },
    "chacha20": {
        "encrypt": lambda data, key: chacha20_encrypt(data, key),
        "decrypt": lambda data, key: chacha20_decrypt(data, key)
    },
    "rot13": {
        "encrypt": rot13_encrypt,
        "decrypt": rot13_decrypt
    },
    "vigenere": {
        "encrypt": lambda msg, key: vigenere_encrypt(msg, key),
        "decrypt": lambda msg, key: vigenere_decrypt(msg, key)
    }
}

@encryption_bp.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    original_message = None

    if request.method == 'POST':
        file = request.files.get('file')
        message = request.form.get('message', '').strip()
        encryption_type = request.form.get('encryption_type')
        action = request.form.get('action')

        # Validation block
        error = None  # Initialize error variable

        # Get required form data
        encryption_type = request.form.get('encryption_type')
        action = request.form.get('action')

        if not error:
            try:
                # Read input data
                input_data = message.encode('utf-8') if message else file.read()

                # Process data based on selected encryption type and action
                if encryption_type in encryption_methods:
                    if action in encryption_methods[encryption_type]:
                        func = encryption_methods[encryption_type][action]

                        # Handle AES
                        if encryption_type == 'aes':
                            key = request.form.get('aes_key', '').strip()
                            if not key:
                                error = "AES key is required"
                            else:
                                key = key.encode('utf-8')
                                if len(key) not in [16, 24, 32]:
                                    error = "AES key must be 16, 24 or 32 bytes"
                                else:
                                    processed_data = func(input_data, key)

                        # Handle Base64
                        elif encryption_type == 'base64':
                            if action == 'encrypt':
                                processed_data = base64_encrypt(input_data)
                                if file:
                                    processed_data = processed_data.encode('utf-8')  # Convert to bytes for file
                            elif action == 'decrypt':
                                processed_data = base64_decrypt(input_data)
                            # Handle text output
                            if not file and isinstance(processed_data, bytes):
                                try:
                                    processed_data = processed_data.decode('utf-8')
                                except UnicodeDecodeError:
                                    processed_data = base64_encrypt(processed_data)

                        elif encryption_type == 'blowfish':
                                key = request.form.get('blowfish_key', '').strip()
                                if not key:
                                    error = "Blowfish key is required"
                                else:
                                    key_bytes = key.encode('utf-8')
                                    if len(key_bytes) < 4 or len(key_bytes) > 56:
                                        error = f"Blowfish key must be 4-56 bytes (current: {len(key_bytes)})"
                                    else:
                                        try:
                                            if action == 'encrypt':
                                                # Handle encryption
                                                processed_data = blowfish_encrypt(input_data, key)
                                            else:
                                                # Handle decryption
                                                processed_data = blowfish_decrypt(input_data, key)

                                        except ValueError as e:
                                            error = f"Invalid ciphertext: {str(e)}"
                                        except Exception as e:
                                            error = f"Blowfish error: {str(e)}"
                                            logging.error("Blowfish operation failed: %s", e)

                        # Handle Chacha20
                        elif encryption_type == 'chacha20':
                                key = request.form.get('chacha20_key', '').strip()
                                if not key:
                                    error = "ChaCha20 key is required"
                                else:
                                    try:
                                        key_bytes = bytes.fromhex(key)
                                        if len(key_bytes) != 32:
                                            error = "ChaCha20 key must be 64 hex characters (32 bytes)"
                                        else:
                                            # Handle text decryption input
                                            if action == 'decrypt' and message:
                                                input_data = base64.b64decode(input_data)

                                            processed_data = func(input_data, key_bytes)

                                            if not file and action == 'encrypt':
                                                processed_data = base64_encrypt(processed_data)
                                    except ValueError:
                                        error = "Invalid hexadecimal key format"
                                    except Exception as e:
                                        error = f"ChaCha20 error: {str(e)}"
                                        logging.error("ChaCha20 operation failed: %s", e)

                        # Handle Caesar Cipher
                        elif encryption_type == 'caesar':
                            shift = request.form.get('shift', type=int, default=3)
                            if isinstance(input_data, bytes):
                                input_data = input_data.decode('utf-8')
                            processed_data = func(input_data, shift)

                        # Handle Rot13
                        elif encryption_type == 'rot13':
                            if isinstance(input_data, bytes):
                                input_data = input_data.decode('utf-8')
                            processed_data = func(input_data)


                        # Handle Vigenère Cipher
                        elif encryption_type == 'vigenere':
                            key = request.form.get('vigenere_key', '').strip()
                            if not key:
                                error = "Vigenère key is required"
                            elif not key.isalpha():
                                error = "Vigenère key must contain only letters"
                            else:
                                if isinstance(input_data, bytes):
                                    input_data = input_data.decode('utf-8')
                                processed_data = func(input_data, key)

                        else:
                            error = "Selected encryption method not implemented yet."

                    else:
                        error = "Invalid action selected."

                # Return result
                if not error:
                    # Store in history if logged in
                    if 'user_id' in session:
                        try:
                            # Retrieve shift value only for Caesar cipher
                            encryption_params = None
                            if encryption_type == 'caesar':
                                encryption_params = request.form.get('shift', type=int, default=3)
                            elif encryption_type == 'vigenere':
                                encryption_params = request.form.get('vigenere_key')

                            original = message if message else (file.filename if file else "")
                            result_value = processed_data.decode('utf-8') if isinstance(processed_data, bytes) else str(processed_data)


                            db.store_message(
                                session["user_id"],
                                original,
                                encryption_type,
                                result_value,
                                encryption_params
                            )
                        except Exception as e:
                            logging.error("Error saving to history: %s", e)

                    # If a file is uploaded
                    if file:
                            # Existing file handling for other encryption methods
                            if isinstance(processed_data, str):
                                processed_data = processed_data.encode('utf-8')
                            buffer = BytesIO(processed_data)
                            return send_file(buffer, as_attachment=True, download_name=f"{action}ed_{file.filename}")
                    else:
                        if isinstance(processed_data, bytes):
                            # Handle byte results for text output
                            try:
                                result = processed_data.decode('utf-8')
                            except UnicodeDecodeError:
                                # For binary data that can't be decoded, show as base64
                                result = base64.b64encode(processed_data).decode('utf-8')
                        else:
                            result = processed_data
            except Exception as e:
                logging.error("Error during encryption/decryption: %s", e)
                error = f"An error occurred: {str(e)}"

    return render_template('index.html', result=result, error=error, original_message=original_message)

@encryption_bp.route("/learn-more")
def learn_more():
    return render_template("learn_more.html")

@encryption_bp.route('/download/<filename>')
def download_file(filename):
    return send_file(filename, as_attachment=True)


@encryption_bp.route('/api/crypt', methods=['POST'])
@limiter.limit("10/minute")
def api_crypt():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input."}), 400

    message = data.get('message')
    encryption_type = data.get('encryption_type')
    action = data.get('action')

    # Get shift value correctly from JSON, defaulting to 3
    shift = data.get('shift', 3)

    # Ensure AES and Base64 input is handled as bytes, others as strings
    input_data = message.encode('utf-8') if encryption_type in ['aes', 'base64'] else message

    if not message:
        return jsonify({"error": "Please enter a message."}), 400

    try:
        # Ensure AES input is handled as bytes, others as strings
        input_data = message.encode('utf-8') if encryption_type == 'aes' else message

        if encryption_type in encryption_methods:
            if action in encryption_methods[encryption_type]:
                func = encryption_methods[encryption_type][action]

                if encryption_type == "caesar":
                    processed_data = func(input_data, shift)

                elif encryption_type == 'blowfish':
                    key = data.get('key', '')
                    if not key or len(key) < 4 or len(key) > 56:
                        return jsonify({"error": "Invalid Blowfish key"}), 400
                    processed_data = func(input_data, key)

                elif encryption_type == "vigenere":
                    key = data.get('key', '')
                    processed_data = func(input_data, key)
                else:
                    processed_data = func(input_data)

                # Ensure result is always a string
                if isinstance(processed_data, bytes):
                    result = base64_encrypt(processed_data)
                else:
                    result = processed_data

                return jsonify({"result": result})

            return jsonify({"error": "Invalid action selected."}), 400
        return jsonify({"error": "Method not implemented."}), 400

    except Exception as e:
        logging.error("API Error during encryption/decryption: %s", e)
        return jsonify({"error": "An error occurred during processing. Please try again."}), 500
