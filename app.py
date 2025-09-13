from flask import Flask, request, jsonify, current_app
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_identity
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
load_dotenv()
import time
import json
import sys
import os
import redis
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
from config.database import SessionLocal

# Add backend modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from services.messaging_service import MessagingService
from routes.device_routes import device_routes
from routes.dev_routes import dev_routes

# Import models 
from models.user import User
from models.property import Property
from models.message import Message
from models.user_device import UserDevice

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
# Register blueprints
# ----------------------------------------------------------------------
app.register_blueprint(device_routes)
app.register_blueprint(dev_routes)

# ----------------------------------------------------------------------
# (Temporary) in-memory dicts to avoid NameErrors in legacy routes
# ----------------------------------------------------------------------
users_storage = {}
properties_storage = {}
messages_storage = {}

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def hash_password(password: str) -> str:
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def property_to_dict(prop: Property) -> dict:
    return {
        'propertyId': prop.property_id,
        'userId': prop.user_id,
        'title': prop.title,
        'description': prop.description or '',
        'price': prop.price,
        'location': prop.location or {},
        'photos': prop.photos or [],
        'bedrooms': prop.bedrooms,
        'bathrooms': prop.bathrooms,
        'propertyType': prop.property_type,
        'createdAt': int(prop.created_at.timestamp() * 1000) if prop.created_at else None,
        'expiresAt': int(prop.expires_at.timestamp() * 1000) if prop.expires_at else None,
        'status': prop.status
    }

def message_to_dict(msg: Message) -> dict:
    return {
        'messageId': msg.message_id,
        'senderId': msg.sender_id,
        'receiverId': msg.receiver_id,
        'propertyId': msg.property_id,
        'content': msg.content,
        'messageType': msg.message_type,
        'sentAt': int(msg.sent_at.timestamp() * 1000) if msg.sent_at else None,
        'readAt': int(msg.read_at.timestamp() * 1000) if msg.read_at else None
    }

# Conversation visibility flags (kept in memory for now)
conversation_visibility = {}

def visibility_key(property_id: int, tenant_id: int) -> str:
    return f"{property_id}_{tenant_id}"

def get_visibility_flags(property_id: int, tenant_id: int):
    flags = conversation_visibility.get(visibility_key(property_id, tenant_id), {})
    return {
        "canSeeStreet": bool(flags.get("canSeeStreet", False)),
        "canSeeExactAddress": bool(flags.get("canSeeExactAddress", False)),
    }

def _normalize_property(prop: dict) -> dict:
    p = dict(prop)
    p['description'] = p.get('description', '') or ''
    raw = p.get('photos', [])
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = []
    if raw is None:
        raw = []
    p['photos'] = list(raw)
    return p

def teaser_of(prop: dict) -> dict:
    p = _normalize_property(prop)
    return {
        'propertyId': p['propertyId'],
        'userId': p.get('userId'),
        'title': p['title'],
        'description': p['description'],
        'price': p['price'],
        'location': p['location'],
        'photos': p['photos'],
        'propertyType': p['propertyType'],
        'bedrooms': p['bedrooms'],
        'bathrooms': p['bathrooms'],
        'createdAt': p.get('createdAt'),
        'expiresAt': p.get('expiresAt'),
        'status': p.get('status', 'active'),
    }

def is_current(prop_dict: dict) -> bool:
    now_ms = int(time.time() * 1000)
    return prop_dict.get('status') == 'active' and prop_dict.get('expiresAt', now_ms) > now_ms

def is_property_current(prop: Property) -> bool:
    now = datetime.now()
    return prop.status == 'active' and (prop.expires_at is None or prop.expires_at > now)

def validate_role(role):
    if not role:
        return None
    role_lower = role.lower().strip()
    valid_roles = ['tenant', 'landlord']
    return role_lower if role_lower in valid_roles else None

def conversation_id_for(property_id: int, u1: int, u2: int) -> str:
    a, b = sorted([int(u1), int(u2)])
    return f"c_{int(property_id)}_{a}_{b}"

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

# ----------------------------------------------------------------------
# Authentication Routes
# ----------------------------------------------------------------------
@app.route('/auth/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    db = SessionLocal()
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        phone_number = data.get('phoneNumber')
        role = data.get('role')
        if not email or not password or not phone_number:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        validated_role = validate_role(role)
        if validated_role is None:
            return jsonify({'success': False, 'message': 'Invalid role. Must be tenant or landlord'}), 400

        existing_user = db.query(User).filter(User.email.ilike(email)).first()
        if existing_user:
            return jsonify({'success': False, 'message': 'User already exists'}), 400

        display_name = data.get('displayName')
        if not display_name or not display_name.strip():
            email_local = email.split('@')[0]
            display_name = email_local.replace('.', ' ').replace('_', ' ').title()

        user = User(
            email=email.lower(),
            password_hash=hash_password(password),
            phone_number=phone_number,
            role=validated_role,
            display_name=display_name.strip()
        )
        db.add(user); db.commit(); db.refresh(user)

        return jsonify({
            'success': True,
            'message': 'Registration successful!',
            'token': create_access_token(identity=str(user.user_id)),
            'userId': user.user_id,
            'role': user.role,
            'displayName': user.display_name
        }), 200
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': f'Registration error: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    db = SessionLocal()
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password required'}), 400

        user = db.query(User).filter(User.email.ilike(email)).first()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 401
        if not verify_password(password, user.password_hash):
            return jsonify({'success': False, 'message': 'Invalid password'}), 401

        token = create_access_token(identity=str(user.user_id))
        print(f"🔑 Generated token for {email}: len={len(token)}")
        return jsonify({
            'success': True,
            'message': 'Login successful!',
            'token': token,
            'userId': user.user_id,
            'role': user.role,
            'displayName': user.display_name or user.email.split('@')[0]
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Login error: {str(e)}'}), 500
    finally:
        db.close()

def get_authenticated_user_id():
    """Return int user_id from JWT or None."""
    try:
        verify_jwt_in_request(optional=True)
        uid = get_jwt_identity()
        if uid is not None:
            return int(uid)
    except Exception as e:
        print("JWT verify error:", e)
    return None

@app.route('/auth/verify-token', methods=['POST'])
def verify_token():
    db = SessionLocal()
    try:
        verify_jwt_in_request(optional=False)
        uid = get_jwt_identity()
        if uid is None:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        user = db.query(User).filter(User.user_id == int(uid)).first()
        if not user:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        return jsonify({'success': True, 'message': 'Token is valid'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Token verification error: {str(e)}'}), 401
    finally:
        db.close()

@app.route('/auth/logout', methods=['POST'])
def logout():
    try:
        return jsonify({'success': True, 'message': 'Logout successful'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Logout error: {str(e)}'}), 500

@app.route('/auth/me', methods=['GET'])
def me():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        return jsonify({
            'success': True,
            'userId': user.user_id,
            'email': user.email,
            'displayName': user.display_name or '',
            'role': user.role
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
    finally:
        db.close()

# ----------------------------------------------------------------------
# Property Management (DB-backed create/list remains as in your file)
# ----------------------------------------------------------------------
@app.route('/properties', methods=['POST'])
def create_property():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user or user.role != 'landlord':
            print(f"🚫 403 CREATE_LISTING_DENIED: user_id={user_id}, role={user.role if user else 'None'}")
            return jsonify({'success': False, 'message': 'Create Listing is for landlords'}), 403

        data = request.get_json()
        required = ['title', 'description', 'price', 'location', 'bedrooms', 'bathrooms', 'propertyType']
        for f in required:
            if f not in data:
                return jsonify({'success': False, 'message': f'Missing required field: {f}'}), 400

        photos_raw = data.get('photos', [])
        if isinstance(photos_raw, str):
            try:
                photos = json.loads(photos_raw)
            except Exception:
                photos = []
        else:
            photos = list(photos_raw) if photos_raw is not None else []

        expires_at = datetime.now() + timedelta(days=30)

        location_data = data.get('location', {})
        if isinstance(location_data, str):
            try:
                location_data = json.loads(location_data)
            except:
                location_data = {}
        for f in ['addressStreet', 'addressNumber', 'neighborhood', 'lat', 'lon']:
            if f in data:
                location_data[f] = data[f]

        property_obj = Property(
            user_id=user_id,
            title=data['title'],
            description=data['description'],
            price=data['price'],
            location=location_data,
            photos=photos,
            bedrooms=data['bedrooms'],
            bathrooms=data['bathrooms'],
            property_type=data['propertyType'],
            expires_at=expires_at,
            status='active'
        )
        db.add(property_obj); db.commit(); db.refresh(property_obj)
        return jsonify({'success': True, 'message': 'Property created successfully', 'property': property_to_dict(property_obj)}), 201
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': f'Property creation error: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/properties', methods=['GET'])
def get_all_active_properties():
    db = SessionLocal()
    try:
        caller_id = get_authenticated_user_id()
        is_authenticated = bool(caller_id)
        active_properties = db.query(Property).filter(
            Property.status == 'active',
            or_(Property.expires_at.is_(None), Property.expires_at > datetime.now())
        ).all()
        if is_authenticated:
            safe_props = []
            for prop in active_properties:
                prop_dict = property_to_dict(prop)
                if prop.user_id == caller_id:
                    safe_props.append(prop_dict)
                else:
                    safe_props.append(teaser_of(prop_dict))
            return jsonify({'success': True, 'message': 'Properties retrieved successfully', 'properties': safe_props}), 200
        else:
            guest_props = [teaser_of(property_to_dict(prop)) for prop in active_properties]
            return jsonify({'success': True, 'message': 'Properties retrieved successfully (guest view)', 'properties': guest_props}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error retrieving properties: {str(e)}'}), 500
    finally:
        db.close()

# ----------------------------------------------------------------------
# Messaging Routes (DB-backed + Redis publish)
# ----------------------------------------------------------------------
@app.route('/messages', methods=['POST'])
@limiter.limit("60 per minute")
def send_message():
    db = SessionLocal()
    try:
        sender_id = get_authenticated_user_id()
        if not sender_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        sender = db.query(User).filter(User.user_id == sender_id).first()
        if not sender:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        data = request.get_json()
        required_fields = ['receiverId', 'propertyId', 'content', 'messageType']
        for f in required_fields:
            if f not in data:
                return jsonify({'success': False, 'message': f'Missing required field: {f}'}), 400

        receiver_id = int(data['receiverId'])
        receiver = db.query(User).filter(User.user_id == receiver_id).first()
        if not receiver:
            return jsonify({'success': False, 'message': 'Receiver not found'}), 400

        property_id = int(data['propertyId'])
        property_obj = db.query(Property).filter(Property.property_id == property_id).first()
        if not property_obj:
            return jsonify({'success': False, 'message': 'Property not found'}), 400

        message_obj = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            property_id=property_id,
            content=data['content'],
            message_type=data['messageType']
        )
        db.add(message_obj); db.commit(); db.refresh(message_obj)

        # Publish to WS via Redis with canonical conversationId
        if redis_client:
            try:
                conv_id = conversation_id_for(property_id, sender_id, receiver_id)
                ws_message = {
                    'type': 'external_message',
                    'data': {
                        'conversationId': conv_id,
                        'type': 'message',
                        'messageId': str(message_obj.message_id),
                        'senderId': sender_id,
                        'receiverId': receiver_id,
                        'propertyId': property_id,
                        'content': data['content'],
                        'messageType': data['messageType'],
                        'sentAt': int(message_obj.sent_at.timestamp() * 1000) if message_obj.sent_at else None,
                        'status': 'sent'
                    }
                }
                redis_client.publish('messaging_events', json.dumps(ws_message))
                print("📡 Message broadcasted to WebSocket users")
            except Exception as e:
                print(f"⚠️  WebSocket broadcast failed: {e}")

        # Push notification
        try:
            sender_name = MessagingService.get_sender_display_name_from_db(sender_id)
            message_data = message_to_dict(message_obj) | {'localId': data.get('localId')}
            MessagingService.send_message_with_push(message_data, sender_name)
        except Exception as e:
            print(f"⚠️  Push notification failed: {e}")

        return jsonify({'success': True, 'message': 'Message sent successfully', 'messageId': message_obj.message_id}), 201
    except Exception as e:
        db.rollback()
        print(f"❌ Send message error: {str(e)}")
        return jsonify({'success': False, 'message': f'Send message error: {str(e)}'}), 500
    finally:
        db.close()

@app.route('/messages/conversation', methods=['GET'])
def get_conversation_messages():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        property_id = request.args.get('propertyId', type=int)
        other_user_id = request.args.get('otherUserId', type=int)
        if not property_id or not other_user_id:
            return jsonify({'success': False, 'message': 'propertyId and otherUserId are required'}), 400

        q = db.query(Message).filter(
            Message.property_id == property_id,
            (
                (Message.sender_id == user_id) & (Message.receiver_id == other_user_id)
            ) | (
                (Message.sender_id == other_user_id) & (Message.receiver_id == user_id)
            )
        ).order_by(Message.sent_at.asc())
        rows = q.all()
        conversation_messages = [message_to_dict(m) for m in rows]

        # Emit ack_delivered for messages sent by other_user -> current user
        if redis_client and conversation_messages:
            conv_id = conversation_id_for(property_id, user_id, other_user_id)
            for m in conversation_messages:
                if m['senderId'] == other_user_id and m['receiverId'] == user_id and m['readAt'] is None:
                    redis_client.publish('messaging_events', json.dumps({
                        'type': 'ack_delivered',
                        'data': {
                            'messageId': str(m['messageId']),
                            'conversationId': conv_id,
                            'deliveredBy': str(user_id)
                        }
                    }))

        return jsonify({'success': True, 'message': 'Conversation retrieved successfully', 'messages': conversation_messages}), 200
    except Exception as e:
        print(f"❌ Get conversation error: {e}")
        return jsonify({'success': False, 'message': f'Get conversation error: {e}'}), 500
    finally:
        db.close()

@app.route('/messages/conversations', methods=['GET'])
def get_user_conversations():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        rows = db.query(Message).filter(
            (Message.sender_id == user_id) | (Message.receiver_id == user_id)
        ).order_by(Message.sent_at.desc()).all()

        seen = set()
        conversations = []
        for m in rows:
            other_user = m.receiver_id if m.sender_id == user_id else m.sender_id
            key = (m.property_id, other_user)
            if key in seen:
                continue
            seen.add(key)
            conversations.append({
                'propertyId': m.property_id,
                'otherUserId': other_user,
                'lastMessageTime': int(m.sent_at.timestamp() * 1000) if m.sent_at else None
            })

        return jsonify({'success': True, 'message': 'Conversations retrieved successfully', 'conversations': conversations}), 200
    except Exception as e:
        print(f"❌ Get conversations error: {e}")
        return jsonify({'success': False, 'message': f'Get conversations error: {e}'}), 500
    finally:
        db.close()

@app.route('/messages/read', methods=['PUT'])
def mark_messages_as_read():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        property_id = request.args.get('propertyId', type=int)
        sender_id = request.args.get('senderId', type=int)
        if not property_id or not sender_id:
            return jsonify({'success': False, 'message': 'propertyId and senderId are required'}), 400

        read_time = datetime.now()
        q = db.query(Message).filter(
            Message.property_id == property_id,
            Message.sender_id == sender_id,
            Message.receiver_id == user_id,
            Message.read_at.is_(None)
        )
        marked = q.update({Message.read_at: read_time}, synchronize_session=False)
        db.commit()

        return jsonify({'success': True, 'message': f'Marked {marked} messages as read'}), 200
    except Exception as e:
        db.rollback()
        print(f"❌ Mark messages read error: {e}")
        return jsonify({'success': False, 'message': f'Mark messages read error: {e}'}), 500
    finally:
        db.close()

@app.route('/messages/conversation', methods=['DELETE'])
def delete_conversation():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        property_id = request.args.get('propertyId', type=int)
        other_user_id = request.args.get('otherUserId', type=int)
        if not property_id or not other_user_id:
            return jsonify({'success': False, 'message': 'propertyId and otherUserId are required'}), 400

        q = db.query(Message).filter(
            Message.property_id == property_id,
            (
                (Message.sender_id == user_id) & (Message.receiver_id == other_user_id)
            ) | (
                (Message.sender_id == other_user_id) & (Message.receiver_id == user_id)
            )
        )
        deleted = q.delete(synchronize_session=False)
        db.commit()

        print(f"✅ Deleted {deleted} messages from conversation")
        return jsonify({'success': True, 'message': f'Deleted {deleted} messages'}), 200
    except Exception as e:
        db.rollback()
        print(f"❌ Delete conversation error: {e}")
        return jsonify({'success': False, 'message': f'Delete conversation error: {e}'}), 500
    finally:
        db.close()

# ----------------------------------------------------------------------
# Visibility + Debug (unchanged)
# ----------------------------------------------------------------------
@app.route('/conversations/share_street', methods=['POST'])
def share_street():
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            print(f"🚫 401 SHARE_STREET_NO_AUTH: IP={request.remote_addr}")
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        data = request.get_json() or {}
        property_id = data.get('propertyId')
        tenant_id = data.get('tenantId')
        if not property_id or not tenant_id:
            return jsonify({'success': False, 'message': 'propertyId and tenantId required'}), 400

        try:
            tenant_id_int = int(tenant_id)
        except Exception:
            return jsonify({'success': False, 'message': 'Invalid tenantId'}), 400
        if tenant_id_int not in users_storage:
            return jsonify({'success': False, 'message': 'Tenant not found'}), 404

        prop = properties_storage.get(int(property_id))
        if not prop:
            return jsonify({'success': False, 'message': 'Property not found'}), 404
        if prop.get('userId') != user_id:
            print(f"🚫 403 SHARE_STREET_NOT_OWNER: user_id={user_id}, property_owner={prop.get('userId')}, property_id={property_id}")
            return jsonify({'success': False, 'message': 'Not authorized for this property'}), 403

        key = visibility_key(int(property_id), int(tenant_id))
        flags = conversation_visibility.setdefault(key, {"canSeeStreet": False, "canSeeExactAddress": False})
        flags["canSeeStreet"] = True

        return jsonify({'success': True, 'message': 'Street shared for this conversation'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/conversations/share_exact', methods=['POST'])
def share_exact():
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            print(f"🚫 401 SHARE_EXACT_NO_AUTH: IP={request.remote_addr}")
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        data = request.get_json() or {}
        property_id = data.get('propertyId')
        tenant_id = data.get('tenantId')
        if not property_id or not tenant_id:
            return jsonify({'success': False, 'message': 'propertyId and tenantId required'}), 400

        try:
            tenant_id_int = int(tenant_id)
        except Exception:
            return jsonify({'success': False, 'message': 'Invalid tenantId'}), 400
        if tenant_id_int not in users_storage:
            return jsonify({'success': False, 'message': 'Tenant not found'}), 404

        prop = properties_storage.get(int(property_id))
        if not prop:
            return jsonify({'success': False, 'message': 'Property not found'}), 404
        if prop.get('userId') != user_id:
            print(f"🚫 403 SHARE_EXACT_NOT_OWNER: user_id={user_id}, property_owner={prop.get('userId')}, property_id={property_id}")
            return jsonify({'success': False, 'message': 'Not authorized for this property'}), 403

        key = visibility_key(int(property_id), int(tenant_id))
        flags = conversation_visibility.setdefault(key, {"canSeeStreet": False, "canSeeExactAddress": False})
        flags["canSeeExactAddress"] = True

        return jsonify({'success': True, 'message': 'Exact address shared for this conversation'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

@app.route('/conversations/visibility', methods=['GET'])
def get_conversation_visibility():
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            print(f"🚫 401 VISIBILITY_NO_AUTH: IP={request.remote_addr}")
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        property_id = request.args.get('propertyId', type=int)
        tenant_id = request.args.get('tenantId', type=int)
        if not property_id or not tenant_id:
            return jsonify({'success': False, 'message': 'propertyId and tenantId required'}), 400

        prop = properties_storage.get(property_id)
        if not prop:
            return jsonify({'success': False, 'message': 'Property not found'}), 404

        is_owner = (prop.get('userId') == user_id)
        is_tenant = (user_id == tenant_id)
        if not (is_owner or is_tenant):
            print(f"🚫 403 VISIBILITY_ACCESS_DENIED: user_id={user_id}, property_owner={prop.get('userId')}, tenant_id={tenant_id}")
            return jsonify({'success': False, 'message': 'Not authorized to view visibility'}), 403

        return jsonify({'success': True, **get_visibility_flags(property_id, tenant_id)}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Debug and Testing Routes
@app.route('/debug/data', methods=['GET'])
def debug_data():
    secret = request.headers.get("X-Debug-Secret")
    if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
        return jsonify({"error": "forbidden"}), 403
    db = SessionLocal()
    try:
        users = db.query(User).all()
        users_data = {
            user.user_id: {
                'userId': user.user_id,
                'email': user.email,
                'displayName': user.display_name,
                'role': user.role,
                'createdAt': int(user.created_at.timestamp() * 1000) if user.created_at else None
            } for user in users
        }
        properties = db.query(Property).all()
        properties_data = {prop.property_id: property_to_dict(prop) for prop in properties}
        messages = db.query(Message).all()
        messages_data = {msg.message_id: message_to_dict(msg) for msg in messages}
        return jsonify({'users': users_data, 'properties': properties_data, 'messages': messages_data})
    finally:
        db.close()

@app.route('/debug/users', methods=['GET'])
def debug_users():
    secret = request.headers.get("X-Debug-Secret")
    if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
        return jsonify({"error": "forbidden"}), 403
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return jsonify({
            'users': [
                {
                    'userId': user.user_id,
                    'email': user.email,
                    'displayName': user.display_name or 'No Name',
                    'role': user.role,
                    'createdAt': int(user.created_at.timestamp() * 1000) if user.created_at else None
                } for user in users
            ]
        })
    finally:
        db.close()

@app.route('/debug/test-push', methods=['POST'])
def test_push_notification():
    try:
        secret = request.headers.get("X-Debug-Secret")
        if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
            return jsonify({"error": "forbidden"}), 403

        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        data = request.get_json() or {}
        title = data.get('title', 'Test Notification')
        body = data.get('body', 'This is a test notification from the rental platform')
        success = MessagingService.send_test_push(user_id, title, body)
        return jsonify({'success': success, 'message': 'Test notification sent' if success else 'Failed to send test notification'}), 200 if success else 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'Test push error: {str(e)}'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
