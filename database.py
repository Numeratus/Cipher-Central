import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()  # Initialize the database and create required tables

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            # Create tables
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    hash TEXT NOT NULL
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    original_message TEXT NOT NULL,
                    encryption_method TEXT NOT NULL,
                    result TEXT NOT NULL,
                    encryption_param TEXT DEFAULT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            cur.execute('''
                CREATE TABLE IF NOT EXISTS user_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    key_name TEXT NOT NULL,
                    key_value TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            self._add_missing_columns(cur, conn)
            conn.commit()

    def _add_missing_columns(self, cur, conn):
        """Add missing columns"""
        try:
            # Check users table
            cur.execute("PRAGMA table_info(users)")
            user_columns = {col[1] for col in cur.fetchall()}
            if 'public_key' not in user_columns:
                cur.execute("ALTER TABLE users ADD COLUMN public_key TEXT")

            # Check messages table
            cur.execute("PRAGMA table_info(messages)")
            msg_columns = {col[1] for col in cur.fetchall()}
            if 'encryption_param' not in msg_columns:
                cur.execute("ALTER TABLE messages ADD COLUMN encryption_param TEXT DEFAULT NULL")

            conn.commit()
        except Exception as e:
            print(f"Error adding missing columns: {e}")

    def execute(self, query, *args):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(query, args)
            conn.commit()
            return cur.fetchall()

    def create_user(self, username, password, public_key):
        pw_hash = generate_password_hash(password)
        try:
            self.execute("INSERT INTO users (username, hash, public_key) VALUES (?, ?, ?)",
                        username, pw_hash, public_key)
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user_by_username(self, username):
        result = self.execute("SELECT * FROM users WHERE username = ?", username)
        return result[0] if result else None

    def get_user_by_id(self, user_id):
        result = self.execute("SELECT * FROM users WHERE id = ?", user_id)
        return result[0] if result else None

    def verify_user(self, username, password):
        user = self.get_user_by_username(username)
        if user and check_password_hash(user['hash'], password):
            return user
        return None

    def store_message(self, user_id, original, method, result, encryption_param=None):
        self.execute('''
            INSERT INTO messages
            (user_id, original_message, encryption_method, result, encryption_param)
            VALUES (?, ?, ?, ?, ?)
        ''', user_id, original, method, result, encryption_param)

    def get_user_messages(self, user_id):
        return self.execute('''
            SELECT id, original_message, encryption_method, result, timestamp, encryption_param
            FROM messages WHERE user_id = ? ORDER BY timestamp DESC
        ''', user_id)

    def delete_message(self, message_id, user_id):
        self.execute('''
            DELETE FROM messages WHERE id = ? AND user_id = ?
        ''', message_id, user_id)

    def delete_key(self, key_id, user_id):
        self.execute('''
            DELETE FROM user_keys
            WHERE id = ? AND user_id = ?
        ''', key_id, user_id)

    def clear_user_history(self, user_id):
        self.execute('''
            DELETE FROM messages WHERE user_id = ?
        ''', user_id)


# Initialize database instance
db = Database("database.db")
