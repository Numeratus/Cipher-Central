# Cipher Central

**Cipher Central** is a comprehensive web application built as a final project for CS50x, offering a centralized platform for encryption, decryption, and cryptographic key management. Designed with security and usability in mind, it supports multiple encryption algorithms, user authentication, and historical tracking of operations. Built using Flask and Bootstrap, the application emphasizes modularity and extensibility while maintaining a clean, modern interface.

## Features

### Core Functionality
- **7 Encryption/Encoding Methods**:
  - *Symmetric Ciphers*: AES, Blowfish, ChaCha20
  - *Historical Ciphers*: Caesar Cipher, Vigenère, ROT13
  - *Encoding*: Base64
- **Dual Input Modes**: Process text directly or encrypt/decrypt files
- **Key Management**:
  - Secure storage of encryption keys
  - Default key generation for AES/Blowfish/ChaCha20
  - User-specific key storage with default key designation
- **Operation History**: Track all encryption/decryption activities with parameters
- **REST API**: Programmatic access via `/api/crypt` endpoint

### Security & Usability
- **User Authentication**:
  - Secure password storage with PBKDF2-SHA256 hashing
  - Session management with CSRF protection
  - Password complexity requirements (special chars, length, etc.)
- **Key Security**:
  - AES keys hashed with SHA-256 if not 16/24/32 bytes
  - Environment variable support for production keys
  - Client-side key generation for sensitive algorithms
- **UI Features**:
  - Dark/Light mode toggle
  - Responsive Bootstrap design
  - Copy-to-clipboard functionality
  - Interactive method descriptions
  - File download handling for encrypted assets

## Installation & Usage

### Requirements
- Python 3.10+
- SQLite3
- System build essentials (for Crypto dependencies)

### Setup
1. Clone repository:
   ```bash
   git clone https://github.com/DoctorBooty/Cipher-Central/cipher-central.git
   cd cipher-central
   ```

### Install dependencies:
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

### Configure environment:
```
echo "SECRET_KEY=your_secure_key_here" > .env
```

### Execution
```
flask run
```

### Core Modules
| File                  | Description                                                                |
|-----------------------|----------------------------------------------------------------------------|
| `app.py`              | Flask application factory and main entry point                             |
| `auth.py`             | Authentication blueprint (login/registration/password management)          |
| `database.py`         | SQLite ORM with user/message/key management methods                        |
| `encryption_routes.py`| Core encryption/decryption logic and API endpoint implementation           |
| `extensions.py`       | Flask extension initializations (CSRF, rate limiting)                      |
| `key_management.py`   | Key storage/retrieval operations and history management                    |

### Encryption Implementations
Directory: `encryption_methods/`

| File                | Description                                                                |
|---------------------|----------------------------------------------------------------------------|
| `aes.py`            | AES-CBC implementation with PKCS7 padding and key validation               |
| `base64.py`         | Base64 encoding/decoding with binary file support                          |
| `blowfish.py`       | Blowfish ECB mode implementation with dynamic key generation               |
| `caesar_cipher.py`  | Caesar cipher with configurable shift value (1-25)                         |
| `chacha20.py`       | ChaCha20 stream cipher implementation with nonce management                |
| `rot13.py`          | ROT13 implementation (special case of Caesar cipher with fixed shift 13)   |
| `vigenere.py`       | Vigenère cipher implementation with alphabetic key validation              |

### Templates
Directory: `templates/`

| File                      | Description                                                                |
|---------------------------|----------------------------------------------------------------------------|
| `history.html`            | Operation history table with encrypted parameter previews                  |
| `index.html`              | Main encryption interface with dynamic form controls                       |
| `keys.html`               | Key management dashboard with generation tools                             |
| `layout.html`             | Base template with navigation bar, dark mode toggle, and footer            |
| `learn_more.html`         | Detailed cryptographic method documentation with security assessments      |
| `login.html`              | User authentication form with CSRF protection                              |
| `newpassword.html`        | Password change interface with current password verification               |
| `password_generator.html` | Interactive password generator (WIP)                                       |
| `register.html`           | Registration form with password complexity checks                          |


## Security Implementation

- **CSRF Protection**: Integrated via Flask-WTF for all POST endpoints
- **Rate Limiting**: 5 attempts/5 minutes on login endpoint
- **Session Security**:
  - Server-side session storage
  - Automatic session invalidation on password change
- **Input Validation**:
  - Strict regex checks for key formats
  - Byte-length verification for binary operations


## API Documentation

### Endpoint
`POST /api/crypt` - Process encryption/decryption operations programmatically

### Parameters (JSON Body)
| Field | Type | Required | Description | Valid Values |
|-------|------|----------|-------------|--------------|
| `message` | string | Yes | Input text to process | Any UTF-8 string |
| `encryption_type` | string | Yes | Algorithm selection | `aes`, `blowfish`, `chacha20`, `caesar`, `vigenere`, `rot13`, `base64` |
| `action` | string | Yes | Operation type | `encrypt`, `decrypt` |
| `key` | string | Conditional | Algorithm-specific key | - AES: 16/24/32-byte key<br>- Blowfish: 4-56 chars<br>- ChaCha20: 64 hex chars<br>- Vigenère: Letters only |
| `shift` | integer | Caesar only | Shift value (1-25) | Number between 1-25 |

### Request Example
```json
{
  "message": "TopSecret123!",
  "encryption_type": "aes",
  "action": "encrypt",
  "key": "32_byte_aes_key_here"
}
```
### Response
```json
{
  "result": "IhkeFOUYyxzYbO4sCWViEjprVrUviQeNKQVUIB1KXVg=",
  "error": null
}
```

## Future Enhancements

### Authentication Improvements
- **Email Verification**: Mandatory email confirmation during registration
- **Password Recovery**: Secure "Forgot Password" flow with token expiration
- **SMTP Integration**: Email notifications for security events
- **Default Key Selection**: Users will be able to assign one of their stored keys as the default for each supported algorithm, streamlining future encryption/decryption operations.

### Cryptographic Expansion
- **New Algorithms**:
  - RSA (Asymmetric encryption)
  - Twofish (Symmetric block cipher)
  - HMAC (Message authentication codes)
- **Key Exchange**: Diffie-Hellman key exchange implementation
- **TLS Support**: HTTPS enforcement and HSTS headers
- **Steganography**: Hide encrypted messages within image files for covert data transmission

### UI/UX Upgrades
- **Visualization Tools**: Encryption process flow diagrams
- **Batch Processing**: Bulk file encryption/decryption support

### Contributions
Feel free to open issues and give suggestions. If you'd like to contribute directly, you're very welcome!
