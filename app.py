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


app = Flask(__name__)
CORS(app)  # tighten origins later

# JWT setup (env-driven secret)
app.config.setdefault("JWT_SECRET_KEY", os.getenv("JWT_SECRET_KEY", "change-me"))
jwt = JWTManager(app)

# Rate limiting setup
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per hour"],
    storage_uri=os.getenv('REDIS_URL', 'redis://localhost:6379')
)


# Dev secret for debug endpoints
app.config.setdefault("DEBUG_SECRET", os.getenv("DEBUG_SECRET", "changeme"))

# Initialize Redis for WebSocket communication
try:
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
    redis_client = redis.from_url(redis_url, decode_responses=True)
    redis_client.ping()  # Test connection
    print("✅ Redis connected successfully")
except Exception as e:
    print(f"⚠️ Redis connection failed: {e}")
    redis_client = None


# Register blueprints
app.register_blueprint(device_routes)
app.register_blueprint(dev_routes)

# Helper functions
def hash_password(password: str) -> str:
    """Simple password hashing - in production use bcrypt or similar"""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == hashed

def property_to_dict(prop: Property) -> dict:
    """Convert Property model to dictionary"""
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
    """Convert Message model to dictionary"""
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


# Conversation visibility flags (keep in memory for now):
# key: f"{property_id}_{tenant_id}" -> {"canSeeStreet": bool, "canSeeExactAddress": bool}
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
    """Return a copy with stable shapes for optional fields."""
    p = dict(prop)

    # description: always a string
    p['description'] = p.get('description', '') or ''

    # photos: always a JSON array (list), never string/null
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
        'userId': p.get('userId'),           # ok to expose owner id
        'title': p['title'],
        'description': p['description'],     # now present
        'price': p['price'],
        'location': p['location'],
        'photos': p['photos'],               # now a JSON array
        'propertyType': p['propertyType'],
        'bedrooms': p['bedrooms'],
        'bathrooms': p['bathrooms'],
        'createdAt': p.get('createdAt'),
        'expiresAt': p.get('expiresAt'),
        'status': p.get('status', 'active'),
    }

def is_current(prop_dict: dict) -> bool:
    """Check if a property dict is currently active"""
    now_ms = int(time.time() * 1000)
    return prop_dict.get('status') == 'active' and prop_dict.get('expiresAt', now_ms) > now_ms

def is_property_current(prop: Property) -> bool:
    """Check if a Property model instance is currently active"""
    now = datetime.now()
    return prop.status == 'active' and (prop.expires_at is None or prop.expires_at > now)

def validate_role(role):
    """Validate user role for registration - must be explicit choice"""
    if not role:
        return None  # Registration requires role selection
    
    role_lower = role.lower().strip()
    valid_roles = ['tenant', 'landlord']
    
    return role_lower if role_lower in valid_roles else None

@app.route('/')
def hello():
    return "Flask server running!"

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"}), 200

# NEW: always release DB sessions back to the pool
@app.teardown_appcontext
def remove_session(exception=None):
    try:
        SessionLocal.remove()
    except Exception:
        # Avoid raising during teardown; log if you prefer
        pass


# Authentication Routes
@app.route('/auth/register', methods=['POST'])
@limiter.limit("10 per hour")  # Rate limit registration attempts
def register():
    db = SessionLocal()
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        phone_number = data.get('phoneNumber')
        role = data.get('role')
        
        # Basic validation
        if not email or not password or not phone_number:
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
        
        # Validate role (must be tenant or landlord)
        validated_role = validate_role(role)
        if validated_role is None:
            return jsonify({
                'success': False,
                'message': 'Invalid role. Must be tenant or landlord'
            }), 400
        
        # Check if user already exists
        existing_user = db.query(User).filter(User.email.ilike(email)).first()
        if existing_user:
            return jsonify({
                'success': False,
                'message': 'User already exists'
            }), 400
        
        # Generate display name (from provided or email default)
        display_name = data.get('displayName')
        if not display_name or not display_name.strip():
            # Default: extract name from email and format nicely
            email_local = email.split('@')[0]
            display_name = email_local.replace('.', ' ').replace('_', ' ').title()
        
        # Create user in database
        user = User(
            email=email.lower(),
            password_hash=hash_password(password),
            phone_number=phone_number,
            role=validated_role,
            display_name=display_name.strip()
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        
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
        return jsonify({
            'success': False,
            'message': f'Registration error: {str(e)}'
        }), 500
    finally:
        db.close()

@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    db = SessionLocal()
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        # Basic validation
        if not email or not password:
            return jsonify({
                'success': False,
                'message': 'Email and password required'
            }), 400
        
        # Find user and verify password
        user = db.query(User).filter(User.email.ilike(email)).first()
        if not user:
            return jsonify({
                'success': False,
                'message': 'User not found'
            }), 401
        
        if not verify_password(password, user.password_hash):
            return jsonify({
                'success': False,
                'message': 'Invalid password'
            }), 401
        
        token = create_access_token(identity=str(user.user_id))
        # Avoid logging full JWTs in any environment
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
        return jsonify({
            'success': False,
            'message': f'Login error: {str(e)}'
        }), 500
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
        # Enforce JWT presence/validity explicitly
        verify_jwt_in_request(optional=False)
        uid = get_jwt_identity()
        # Check if user exists in database
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
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Logout error: {str(e)}'
        }), 500

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

# Property Management Routes
@app.route('/properties', methods=['POST'])
def create_property():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Ensure only landlords can create listings
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user or user.role != 'landlord':
            print(f"🚫 403 CREATE_LISTING_DENIED: user_id={user_id}, role={user.role if user else 'None'}")
            return jsonify({
                'success': False,
                'message': 'Create Listing is for landlords'
            }), 403
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'description', 'price', 'location', 'bedrooms', 'bathrooms', 'propertyType']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'message': f'Missing required field: {field}'
                }), 400
        
        # Normalize photos into a real list
        photos_raw = data.get('photos', [])
        if isinstance(photos_raw, str):
            try:
                photos = json.loads(photos_raw)
            except Exception:
                photos = []
        else:
            photos = list(photos_raw) if photos_raw is not None else []
        
        # Create property with expiry 30 days from now
        expires_at = datetime.now() + timedelta(days=30)
        
        # Parse location - store as JSONB
        location_data = data.get('location', {})
        if isinstance(location_data, str):
            try:
                location_data = json.loads(location_data)
            except:
                location_data = {}
        
        # Accept optional structured address fields
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
        
        db.add(property_obj)
        db.commit()
        db.refresh(property_obj)
        
        property_data = property_to_dict(property_obj)
        
        return jsonify({
            'success': True,
            'message': 'Property created successfully',
            'property': property_data
        }), 201
        
    except Exception as e:
        db.rollback()
        return jsonify({
            'success': False,
            'message': f'Property creation error: {str(e)}'
        }), 500
    finally:
        db.close()

@app.route('/properties', methods=['GET'])
def get_all_active_properties():
    db = SessionLocal()
    try:
        caller_id = get_authenticated_user_id()
        is_authenticated = bool(caller_id)

        # Query active properties
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
        return jsonify({
            'success': False,
            'message': f'Error retrieving properties: {str(e)}'
        }), 500
    finally:
        db.close()

@app.route('/properties/user/<int:user_id>', methods=['GET'])
def get_user_properties(user_id):
    try:
        requester_id = get_authenticated_user_id()
        if not requester_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        if requester_id == user_id:
            owned_active = [p for p in properties_storage.values() if p.get('userId') == user_id and is_current(p)]
            return jsonify({'success': True, 'message': 'User properties retrieved successfully', 'properties': owned_active}), 200
        else:
            public_active = [teaser_of(p) for p in properties_storage.values() if p.get('userId') == user_id and is_current(p)]
            return jsonify({'success': True, 'message': 'User properties retrieved successfully', 'properties': public_active}), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error retrieving user properties: {str(e)}'
        }), 500

@app.route('/properties/<int:property_id>', methods=['GET'])
def get_property_by_id(property_id):
    try:
        prop = properties_storage.get(property_id)
        if not prop:
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 404
        
        # Extract caller & params
        caller_id = get_authenticated_user_id()
        other_user_id = request.args.get('otherUserId', type=int)  # tenant id, when caller is the tenant
        
        # Hide expired from non-owners
        if not is_current(prop):
            if not caller_id or caller_id != prop.get('userId'):
                return jsonify({'success': False, 'message': 'Property not found'}), 404
        
        # Owner sees full
        if caller_id and prop.get('userId') == caller_id:
            return jsonify({'success': True, 'property': prop}), 200

        # Guest (no auth): return teaser view only
        if not caller_id:
            return jsonify({'success': True, 'property': teaser_of(prop)}), 200

        # Authenticated non-owner: apply conversation flags if provided
        if other_user_id:
            if other_user_id != caller_id:
                print(f"🚫 403 PROPERTY_DETAIL_FOREIGN_USER: caller_id={caller_id}, other_user_id={other_user_id}, property_id={property_id}")
                return jsonify({'success': False, 'message': 'otherUserId must be your userId'}), 403
            flags = get_visibility_flags(property_id, other_user_id)
            resp = dict(prop)

            if not flags['canSeeExactAddress'] and not flags['canSeeStreet']:
                # strip everything precise
                for f in ['addressStreet', 'addressNumber', 'lat', 'lon']:
                    resp.pop(f, None)
                return jsonify({'success': True, 'property': resp}), 200

            if flags['canSeeStreet'] and not flags['canSeeExactAddress']:
                # allow street only; strip number & precise coords
                resp.pop('addressNumber', None)
                resp.pop('lat', None); resp.pop('lon', None)
                return jsonify({'success': True, 'property': resp}), 200

            if flags['canSeeExactAddress']:
                # full details allowed
                return jsonify({'success': True, 'property': resp}), 200

        # Fallback (no otherUserId provided): behave like guest teaser
        return jsonify({'success': True, 'property': teaser_of(prop)}), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error retrieving property: {str(e)}'
        }), 500

@app.route('/properties/<int:property_id>', methods=['PUT'])
def update_property(property_id):
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        property_data = properties_storage.get(property_id)
        if not property_data:
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 404
        
        if property_data['userId'] != user_id:
            return jsonify({
                'success': False,
                'message': 'Not authorized to update this property'
            }), 403
        
        data = request.get_json()
        
        # Update property fields (exclude 'photos' here)
        for field in ['title', 'description', 'price', 'location', 'bedrooms', 'bathrooms', 'propertyType']:
            if field in data:
                property_data[field] = data[field]
        
        # Handle photos explicitly with normalization
        if 'photos' in data:
            pr = data['photos']
            if isinstance(pr, str):
                try:
                    photos = json.loads(pr)
                except Exception:
                    photos = []
            else:
                photos = list(pr) if pr is not None else []
            property_data['photos'] = photos
        
        # Accept optional structured address fields
        for f in ['addressStreet', 'addressNumber', 'neighborhood', 'lat', 'lon']:
            if f in data:
                property_data[f] = data[f]
        
        properties_storage[property_id] = property_data
        
        return jsonify({
            'success': True,
            'message': 'Property updated successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Property update error: {str(e)}'
        }), 500

@app.route('/properties/<int:property_id>', methods=['DELETE'])
def delete_property(property_id):
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        property_data = properties_storage.get(property_id)
        if not property_data:
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 404
        
        if property_data['userId'] != user_id:
            return jsonify({
                'success': False,
                'message': 'Not authorized to delete this property'
            }), 403
        
        # Mark as deleted instead of actually deleting
        property_data['status'] = 'deleted'
        properties_storage[property_id] = property_data
        
        return jsonify({
            'success': True,
            'message': 'Property deleted successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Property deletion error: {str(e)}'
        }), 500

@app.route('/properties/search', methods=['GET'])
def search_properties():
    try:
        # Get query parameters
        search_term = request.args.get('q')
        min_price = request.args.get('minPrice', type=int)
        max_price = request.args.get('maxPrice', type=int)
        min_bedrooms = request.args.get('minBedrooms', type=int)
        property_type = request.args.get('propertyType')
        
        # Check authentication status
        user_id = get_authenticated_user_id()
        is_authenticated = user_id and user_id in users_storage
        
        # Filter properties based on search criteria
        results = []
        for prop in properties_storage.values():
            if not is_current(prop):
                continue
            
            # Search term filter
            if search_term:
                if (search_term.lower() not in prop.get('title', '').lower() and 
                    search_term.lower() not in prop.get('description', '').lower()):
                    continue
            
            # Price filters
            if min_price and prop.get('price', 0) < min_price:
                continue
            if max_price and prop.get('price', 0) > max_price:
                continue
            
            # Bedroom filter
            if min_bedrooms and prop.get('bedrooms', 0) < min_bedrooms:
                continue
            
            # Property type filter
            if property_type and prop.get('propertyType', '').lower() != property_type.lower():
                continue
            
            # Add filtered result
            if is_authenticated and prop.get('userId') == user_id:
                results.append(prop)
            else:
                results.append(teaser_of(prop))
        
        return jsonify({
            'success': True,
            'message': 'Search completed successfully',
            'properties': results
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Search error: {str(e)}'
        }), 500

@app.route('/properties/<int:property_id>/renew', methods=['POST'])
def renew_property(property_id):
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        property_data = properties_storage.get(property_id)
        if not property_data:
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 404
        
        if property_data['userId'] != user_id:
            return jsonify({
                'success': False,
                'message': 'Not authorized to renew this property'
            }), 403
        
        # Extend expiry by 30 days
        current_time = int(time.time() * 1000)
        property_data['expiresAt'] = current_time + (30 * 24 * 60 * 60 * 1000)
        properties_storage[property_id] = property_data
        
        return jsonify({
            'success': True,
            'message': 'Property renewed successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Property renewal error: {str(e)}'
        }), 500

@app.route('/properties/user/<int:user_id>/expiring', methods=['GET'])
def get_expiring_properties(user_id):
    try:
        requester_id = get_authenticated_user_id()
        if not requester_id or requester_id not in users_storage:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Get properties expiring within 5 days
        current_time = int(time.time() * 1000)
        five_days = 5 * 24 * 60 * 60 * 1000
        
        expiring_properties = [
            prop for prop in properties_storage.values()
            if (prop.get('userId') == user_id and 
                is_current(prop) and  # Proper status + expiry validation
                prop.get('expiresAt', 0) - current_time <= five_days)  # Expiring within 5 days
        ]
        
        if requester_id == user_id:
            # Owner sees full details
            return jsonify({
                'success': True,
                'message': 'Expiring properties retrieved successfully',
                'properties': expiring_properties
            }), 200
        else:
            # Non-owner sees teasers only
            expiring_teasers = [teaser_of(prop) for prop in expiring_properties]
            return jsonify({
                'success': True,
                'message': 'Expiring properties retrieved successfully',
                'properties': expiring_teasers
            }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error retrieving expiring properties: {str(e)}'
        }), 500

# Messaging Routes (authentication required for all)
@app.route('/messages', methods=['POST'])
@limiter.limit("60 per minute")  # Rate limit message sending
def send_message():
    db = SessionLocal()
    try:
        # Extract user ID from token (sender)
        sender_id = get_authenticated_user_id()
        if not sender_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Validate sender exists
        sender = db.query(User).filter(User.user_id == sender_id).first()
        if not sender:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['receiverId', 'propertyId', 'content', 'messageType']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'message': f'Missing required field: {field}'
                }), 400
        
        # Validate receiver exists
        receiver_id = data['receiverId']
        receiver = db.query(User).filter(User.user_id == receiver_id).first()
        if not receiver:
            return jsonify({
                'success': False,
                'message': 'Receiver not found'
            }), 400
        
        # Validate property exists
        property_id = data['propertyId']
        property_obj = db.query(Property).filter(Property.property_id == property_id).first()
        if not property_obj:
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 400
        
        # Create message in database
        message_obj = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            property_id=property_id,
            content=data['content'],
            message_type=data['messageType']
        )
        
        db.add(message_obj)
        db.commit()
        db.refresh(message_obj)
        
        # Convert to dict for response and push notification
        message_data = message_to_dict(message_obj)
        message_data['localId'] = data.get('localId')  # For offline sync support
        
        print(f"✅ Message sent: {sender_id} → {receiver_id} (Property {property_id}): {data['content']}")
        
        # Broadcast to WebSocket users if Redis is available
        if redis_client:
            try:
                ws_message = {
                    'type': 'external_message',
                    'data': {
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
                print(f"📡 Message broadcasted to WebSocket users")
            except Exception as e:
                print(f"⚠️  WebSocket broadcast failed: {e}")
        
        # Send push notification using UserDevice.get_active_tokens_for_user()
        try:
            sender_name = MessagingService.get_sender_display_name_from_db(sender_id)
            MessagingService.send_message_with_push(message_data, sender_name)
        except Exception as e:
            print(f"⚠️  Push notification failed: {e}")
            # Continue even if push notification fails
        
        return jsonify({
            'success': True,
            'message': 'Message sent successfully',
            'messageId': message_obj.message_id
        }), 201
        
    except Exception as e:
        db.rollback()
        print(f"❌ Send message error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Send message error: {str(e)}'
        }), 500
    finally:
        db.close()

@app.route('/messages/conversation', methods=['GET'])
def get_conversation_messages():
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Get query parameters
        property_id = request.args.get('propertyId', type=int)
        other_user_id = request.args.get('otherUserId', type=int)
        
        if not property_id or not other_user_id:
            return jsonify({
                'success': False,
                'message': 'propertyId and otherUserId are required'
            }), 400
        
        # Find messages between these users for this property
        conversation_messages = []
        for message in messages_storage.values():
            # Messages where current user is sender OR receiver
            # AND other user is the opposite party
            # AND property matches
            if (message['propertyId'] == property_id and
                ((message['senderId'] == user_id and message['receiverId'] == other_user_id) or
                 (message['senderId'] == other_user_id and message['receiverId'] == user_id))):
                conversation_messages.append({
                    'messageId': message['messageId'],
                    'senderId': message['senderId'],
                    'receiverId': message['receiverId'],
                    'propertyId': message['propertyId'],
                    'content': message['content'],
                    'messageType': message['messageType'],
                    'sentAt': message['sentAt'],
                    'readAt': message['readAt']
                })
        
        # Sort by sent time (oldest first)
        conversation_messages.sort(key=lambda x: x['sentAt'])
        
        print(f"✅ Retrieved {len(conversation_messages)} messages for conversation: User {user_id} ↔ User {other_user_id} (Property {property_id})")
        
        # Emit ack_delivered for messages sent by other_user_id to current user
        conversation_id = f"c_{property_id}_{other_user_id}"
        for message in conversation_messages:
            if message['senderId'] == other_user_id and message['receiverId'] == user_id:
                # Emit ack_delivered to WebSocket room
                if redis_client:
                    redis_message = {
                        'type': 'ack_delivered',
                        'data': {
                            'messageId': str(message['messageId']),
                            'conversationId': conversation_id,
                            'deliveredBy': str(user_id)
                        }
                    }
                    redis_client.publish('messaging_events', json.dumps(redis_message))
                    print(f"📨 Emitted ack_delivered for message {message['messageId']} to room conv:{conversation_id}")
        
        return jsonify({
            'success': True,
            'message': 'Conversation retrieved successfully',
            'messages': conversation_messages
        }), 200
        
    except Exception as e:
        print(f"❌ Get conversation error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Get conversation error: {str(e)}'
        }), 500

@app.route('/messages/conversations', methods=['GET'])
def get_user_conversations():
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Find all conversations for this user
        conversations = {}
        
        for message in messages_storage.values():
            if message['senderId'] == user_id or message['receiverId'] == user_id:
                # Determine other user ID
                other_user_id = message['receiverId'] if message['senderId'] == user_id else message['senderId']
                property_id = message['propertyId']
                
                # Create conversation key
                conv_key = f"{property_id}_{other_user_id}"
                
                # Track latest message time for each conversation
                if conv_key not in conversations or message['sentAt'] > conversations[conv_key]['lastMessageTime']:
                    conversations[conv_key] = {
                        'propertyId': property_id,
                        'otherUserId': other_user_id,
                        'lastMessageTime': message['sentAt']
                    }
        
        # Convert to list and sort by last message time (newest first)
        conversation_list = list(conversations.values())
        conversation_list.sort(key=lambda x: x['lastMessageTime'], reverse=True)
        
        print(f"✅ Retrieved {len(conversation_list)} conversations for user {user_id}")
        
        return jsonify({
            'success': True,
            'message': 'Conversations retrieved successfully',
            'conversations': conversation_list
        }), 200
        
    except Exception as e:
        print(f"❌ Get conversations error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Get conversations error: {str(e)}'
        }), 500

@app.route('/messages/read', methods=['PUT'])
def mark_messages_as_read():
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Get query parameters
        property_id = request.args.get('propertyId', type=int)
        sender_id = request.args.get('senderId', type=int)
        
        if not property_id or not sender_id:
            return jsonify({
                'success': False,
                'message': 'propertyId and senderId are required'
            }), 400
        
        # Mark messages as read
        read_time = int(time.time() * 1000)
        marked_count = 0
        
        for message in messages_storage.values():
            # Mark messages FROM sender_id TO current user for this property
            if (message['propertyId'] == property_id and
                message['senderId'] == sender_id and
                message['receiverId'] == user_id and
                message['readAt'] is None):
                
                message['readAt'] = read_time
                marked_count += 1
        
        print(f"✅ Marked {marked_count} messages as read for user {user_id}")
        
        return jsonify({
            'success': True,
            'message': f'Marked {marked_count} messages as read'
        }), 200
        
    except Exception as e:
        print(f"❌ Mark messages read error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Mark messages read error: {str(e)}'
        }), 500

@app.route('/messages/conversation', methods=['DELETE'])
def delete_conversation():
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Get query parameters
        property_id = request.args.get('propertyId', type=int)
        other_user_id = request.args.get('otherUserId', type=int)
        
        if not property_id or not other_user_id:
            return jsonify({
                'success': False,
                'message': 'propertyId and otherUserId are required'
            }), 400
        
        # Delete messages in this conversation
        messages_to_delete = []
        for message_id, message in messages_storage.items():
            if (message['propertyId'] == property_id and
                ((message['senderId'] == user_id and message['receiverId'] == other_user_id) or
                 (message['senderId'] == other_user_id and message['receiverId'] == user_id))):
                messages_to_delete.append(message_id)
        
        # Remove messages
        for message_id in messages_to_delete:
            del messages_storage[message_id]
        
        print(f"✅ Deleted {len(messages_to_delete)} messages from conversation")
        
        return jsonify({
            'success': True,
            'message': f'Deleted {len(messages_to_delete)} messages'
        }), 200
        
    except Exception as e:
        print(f"❌ Delete conversation error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Delete conversation error: {str(e)}'
        }), 500

@app.route('/messages/ack', methods=['POST'])
def acknowledge_message():
    """Acknowledge message delivery (updates status to DELIVERED)"""
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        data = request.get_json()
        message_id = data.get('messageId')
        
        if not message_id:
            return jsonify({
                'success': False,
                'message': 'messageId is required'
            }), 400
        
        # Update message status (this would require updating the Message model)
        # For now, we'll publish the status update to Redis for WebSocket users
        if redis_client:
            try:
                status_update = {
                    'type': 'status_update',
                    'data': {
                        'messageId': str(message_id),
                        'status': 'delivered',
                        'acknowledged_by': user_id,
                        'timestamp': int(time.time() * 1000),
                        'affected_users': [user_id]  # Users who should see this update
                    }
                }
                redis_client.publish('messaging_events', json.dumps(status_update))
                print(f"📨 Message {message_id} acknowledged as delivered by user {user_id}")
            except Exception as e:
                print(f"⚠️ Redis publish failed: {e}")
        
        return jsonify({
            'success': True,
            'message': 'Message acknowledged'
        }), 200
        
    except Exception as e:
        print(f"❌ Acknowledge message error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Acknowledge message error: {str(e)}'
        }), 500

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

        # Validate ownership
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

        # Validate ownership
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

# Debug and Testing Routes (secured with X-Debug-Secret)
@app.route('/debug/data', methods=['GET'])
def debug_data():
    secret = request.headers.get("X-Debug-Secret")
    if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
        return jsonify({"error": "forbidden"}), 403
    
    db = SessionLocal()
    try:
        # Get all users
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
        
        # Get all properties
        properties = db.query(Property).all()
        properties_data = {prop.property_id: property_to_dict(prop) for prop in properties}
        
        # Get all messages
        messages = db.query(Message).all()
        messages_data = {msg.message_id: message_to_dict(msg) for msg in messages}
        
        return jsonify({
            'users': users_data,
            'properties': properties_data,
            'messages': messages_data
        })
    finally:
        db.close()

@app.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug endpoint to see all users and their roles"""
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
                }
                for user in users
            ]
        })
    finally:
        db.close()

@app.route('/debug/test-push', methods=['POST'])
def test_push_notification():
    """Test endpoint for push notifications"""
    try:
        # Guard with debug secret
        secret = request.headers.get("X-Debug-Secret")
        if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
            return jsonify({"error": "forbidden"}), 403
        
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        data = request.get_json() or {}
        title = data.get('title', 'Test Notification')
        body = data.get('body', 'This is a test notification from the rental platform')
        
        success = MessagingService.send_test_push(user_id, title, body)
        
        return jsonify({
            'success': success,
            'message': 'Test notification sent' if success else 'Failed to send test notification'
        }), 200 if success else 500
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Test push error: {str(e)}'
        }), 500

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)