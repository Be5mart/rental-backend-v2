from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
load_dotenv()
import sys
import os
import redis
from config.database import SessionLocal

# Add backend modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from routes.device_routes import device_routes
from routes.dev_routes import dev_routes
from routes.conversation_routes import conversation_bp

# ----------------------------------------------------------------------
# App + CORS
# ----------------------------------------------------------------------
app = Flask(__name__)
CORS(app)  # TODO: tighten origins later

# JWT setup (env-driven secret)
app.config.setdefault("JWT_SECRET_KEY", os.getenv("JWT_SECRET_KEY", "change-me"))
jwt = JWTManager(app)

# ----------------------------------------------------------------------
# Rate limiting (fallback storage so health/liveness never flap)
# ----------------------------------------------------------------------
storage_uri = (
    os.getenv("FLASK_LIMITER_STORAGE_URI")
    or os.getenv("REDIS_URL")
    or "memory://"
)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per hour"],
    storage_uri=storage_uri
)

# Dev secret for debug endpoints
app.config.setdefault("DEBUG_SECRET", os.getenv("DEBUG_SECRET", "changeme"))

# ----------------------------------------------------------------------
# Redis (shared for REST→WS publish)
# ----------------------------------------------------------------------
try:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    redis_client = redis.from_url(redis_url, decode_responses=True)
    redis_client.ping()  # Test connection
    print("✅ Redis connected successfully")
except Exception as e:
    print(f"⚠️ Redis connection failed: {e}")
    redis_client = None

# ----------------------------------------------------------------------
# Set up blueprint dependencies
# ----------------------------------------------------------------------
from routes.auth_routes import auth_bp, init_limiter as auth_init_limiter
from routes.property_routes import property_bp
from routes.message_routes import message_bp, init_dependencies as message_init_dependencies

# Initialize dependencies
auth_init_limiter(limiter)
message_init_dependencies(redis_client, limiter)

# ----------------------------------------------------------------------
# Register blueprints
# ----------------------------------------------------------------------
app.register_blueprint(device_routes)
app.register_blueprint(dev_routes)
app.register_blueprint(auth_bp)
app.register_blueprint(property_bp)
app.register_blueprint(message_bp)
app.register_blueprint(conversation_bp)




# ----------------------------------------------------------------------
# Basic routes / health
# ----------------------------------------------------------------------
@app.route('/')
def hello():
    return "Flask server running!"

@app.route("/healthz", methods=["GET"])
@limiter.exempt
def healthz():
    return jsonify({"status": "ok"}), 200

# Always release DB sessions back to the pool
@app.teardown_appcontext
def remove_session(exception=None):
    try:
        SessionLocal.remove()
    except Exception:
        pass



if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
