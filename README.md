Cipher Central - A centralized hub for all your encryption and decryption needs
Video Demo: <URL HERE>
Description:

Cipher Central is a Flask-based web application that provides a centralized platform for encryption/decryption operations using various cryptographic algorithms. It combines modern security practices with user-friendly features for both technical and non-technical users.

Key Features:
    - 7 encryption methods (AES, Base64, Blowfish, Caesar, ChaCha20, ROT13, Vigenère)
    - User authentication system with secure password requirements
    - Encrypted message history tracking
    - Cryptographic key management
    - File encryption/decryption capabilities
    - Password generator tool
    - Rate limiting and CSRF protection
    - Responsive web interface

File Structure Breakdown:
    app.py
    - The application entry point. Initializes Flask, configures extensions (CSRF protection, rate limiting), registers blueprints, and sets up logging. Uses python-dotenv for environment variables.

    auth.py
    - Handles user authentication routes:
    - Registration with password complexity validation
    - Login / Logout functionality
    - Password change feature
    - Secure session management
    - Password generator endpoint

    database.py
    - SQLite database handler with methods for:
    - User management (CRUD operations)
    - Encrypted message storage
    - Key management
    - Automatic schema migrations
    - Uses werkzeug.security for password hashing

    encryption_routes.py
      Core encryption/decryption logic:
        - Handles both text and file operations
        - Unified interface for multiple algorithms
        - API endpoint for programmatic access
        - History tracking integration
        - Input validation and error handling

    key_management.py
      Manages cryptographic keys:
        - Secure key storage/retrieval
        - Algorithm-specific validation
        - Key generation utilities
        - History clearing functionality

    /encryption_methods
      Contains algorithm implementations:
        - aes.py: AES-CBC implementation with PKCS7 padding
        - base64.py: Base64 encoding/decoding
        - blowfish.py: ECB mode implementation
        - caesar_cipher.py: Classic substitution cipher
        - chacha20.py: Modern stream cipher
        - rot13.py: Letter shifting implementation
        - vigenere.py: Polyalphabetic cipher

    /templates
      Jinja2 templates using Bootstrap 5:
        - Responsive layout with dark mode support
        - Interactive forms with client-side validation
        - History tracking interface
        - Educational content about encryption methods

Design Decisions:
    Modular Architecture
      - Used Flask blueprints to separate concerns (auth, encryption, keys) for better maintainability

    Security First
      - Implemented CSRF protection on all forms
      - Rate-limited authentication endpoints
      - Password complexity requirements (8+ chars, mixed cases, special chars)
      - Secure session management with server-side storage

    Database Design
      - Separate tables for users, messages, and keys
      - Uses SQLite for simplicity but structured for potential migration to PostgreSQL
      - Automatic schema upgrades using PRAGMA table_info

    Algorithm Selection
      Chose a mix of:
        - Modern standards (AES, ChaCha20)
        - Legacy algorithms (Blowfish)
        - Educational ciphers (Caesar, Vigenère)
        - Encoding schemes (Base64)

    Error Handling
      - Comprehensive input validation
      - Graceful error recovery
      - Detailed logging configuration
      - User-friendly error messages

    UI/UX Considerations
      - Responsive design works on mobile/desktop
      - Interactive encryption method descriptions
      - Copy-to-clipboard functionality
      - Visual feedback for all actions
      - Dark/light mode toggle

Development Challenges:

    Algorithm Integration
      - Unifying different cryptographic interfaces into a consistent API required careful parameter handling and error checking
    File Encryption
      - Implementing streaming encryption/decryption while maintaining compatibility with both text and binary files
    Key Management
      - Developing a secure yet user-friendly system for key storage that works across different algorithms
    History Tracking
      - Designing a flexible storage system that works for both simple ciphers (like Caesar) and complex ones (like AES) with different parameter requirements

Acknowledgments

This project would not have been possible without CS50x - my first formal introduction to computer science. To Professor David J. Malan and the incredible CS50 team: thank you for creating this life-changing educational experience that I discovered through YouTube. Your engaging lectures, challenging problem sets, and supportive community taught me not just how to code, but how to think computationally and facilitated my entry in the world that is Computer Science.

This was CS50x.

