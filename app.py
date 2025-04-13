import logging
import os
from flask import Flask
from dotenv import load_dotenv
from extensions import limiter, csrf

# Load environment variables
load_dotenv()

# Initialize core Flask app
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

    # Initialize extensions
    csrf.init_app(app)
    limiter.init_app(app)

    # Configure logging
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(levelname)s %(message)s')

    # Import blueprints
    from auth import auth_bp
    from encryption_routes import encryption_bp
    from key_management import key_bp

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(encryption_bp)
    app.register_blueprint(key_bp)

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
