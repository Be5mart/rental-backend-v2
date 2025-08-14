from flask import Flask, request, jsonify


from flask_cors import CORS
import time
import json

app = Flask(__name__)


CORS(app)  # tighten origins later

# In-memory storage (will be replaced with database later)
property_counter = 1
user_counter = 1
message_counter = 1
properties_storage = {}
users_storage = {}
messages_storage = {}



# Conversation visibility flags:
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

def teaser_of(prop: dict) -> dict:
    return {
        'propertyId': prop['propertyId'],
        'title': prop['title'],
        'price': prop['price'],
        'location': prop['location'],
        'propertyType': prop['propertyType'],
        'bedrooms': prop['bedrooms'],
        'bathrooms': prop['bathrooms'],
    }

def is_current(prop: dict) -> bool:
    now_ms = int(time.time() * 1000)
    return prop.get('status') == 'active' and prop.get('expiresAt', now_ms) > now_ms

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

# Authentication Routes
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        global user_counter
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
        for user_id, user_data in users_storage.items():
            if user_data['email'] == email:
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
        
        # Store user with role and display name
        user_id = user_counter
        users_storage[user_id] = {
            'userId': user_id,
            'email': email,
            'displayName': display_name.strip(),  # Store display name
            'password': password,  # In production, this would be hashed
            'phoneNumber': phone_number,
            'role': validated_role,  # Store validated role
            'createdAt': int(time.time() * 1000)
        }
        user_counter += 1
        
        return jsonify({
            'success': True,
            'message': 'Registration successful!',
            'token': f'token_user_{user_id}_{int(time.time())}',
            'userId': user_id,
            'role': validated_role,  # Return validated role
            'displayName': display_name.strip()  # Return display name
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Registration error: {str(e)}'
        }), 500

@app.route('/auth/login', methods=['POST'])
def login():
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
        for user_id, user_data in users_storage.items():
            if user_data['email'] == email:
                if user_data['password'] == password:
                    token = f'token_user_{user_id}_{int(time.time())}'
                    print(f"🔑 Generated token for {email}: {token}")
                    return jsonify({
                        'success': True,
                        'message': 'Login successful!',
                        'token': token,
                        'userId': user_id,
                        'role': user_data.get('role', 'tenant'),  # Return stored role
                        'displayName': user_data.get('displayName', user_data.get('email', '').split('@')[0])  # Return display name
                    }), 200
                else:
                    return jsonify({
                        'success': False,
                        'message': 'Invalid password'
                    }), 401
        
        return jsonify({
            'success': False,
            'message': 'User not found'
        }), 401
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Login error: {str(e)}'
        }), 500

def extract_user_id_from_token(token):
    """Extract user ID from token format: token_user_{id}_{timestamp}"""
    try:

        print(f"🔍 DEBUG: Raw token: {token}")
        
        if token.startswith('Bearer '):
            token = token[7:]  # Remove "Bearer " prefix
            print(f"🔍 DEBUG: Token after Bearer removal: {token}")
        
        parts = token.split('_')
        print(f"🔍 DEBUG: Token parts: {parts}")
        
        if len(parts) >= 3 and parts[0] == 'token' and parts[1] == 'user':
            user_id = int(parts[2])
            print(f"🔍 DEBUG: Extracted user_id: {user_id}")
            return user_id
        else:
            print(f"❌ DEBUG: Invalid token format - expected 'token_user_X_timestamp'")
            return None
    except Exception as e:
        print(f"❌ DEBUG: Token extraction error: {str(e)}")
        return None

        if token.startswith('Bearer '):
            token = token[7:]
        parts = token.split('_')
        if len(parts) >= 3 and parts[0] == 'token' and parts[1] == 'user':
            return int(parts[2])
    except:
        pass
    return None

@app.route('/auth/verify-token', methods=['POST'])
def verify_token():
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'No token provided'
            }), 401
        
        user_id = extract_user_id_from_token(auth_header)
        if user_id and user_id in users_storage:
            return jsonify({
                'success': True,
                'message': 'Token is valid'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid token'
            }), 401
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Token verification error: {str(e)}'
        }), 500

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
    try:
        auth_header = request.headers.get('Authorization')
        user_id = extract_user_id_from_token(auth_header) if auth_header else None
        if not user_id or user_id not in users_storage:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        u = users_storage[user_id]
        return jsonify({
            'success': True,
            'userId': user_id,
            'email': u.get('email'),
            'displayName': u.get('displayName', ''),
            'role': u.get('role', 'tenant')
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Property Management Routes
@app.route('/properties', methods=['POST'])
def create_property():
    try:
        global property_counter
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Extract user ID from token
        user_id = extract_user_id_from_token(auth_header)
        if not user_id or user_id not in users_storage:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
            }), 401
        


        # Ensure only landlords can create listings
        user = users_storage.get(user_id)
        if not user or user.get('role') != 'landlord':
            print(f"🚫 403 CREATE_LISTING_DENIED: user_id={user_id}, role={user.get('role') if user else 'None'}")
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
        
        # Create property object with unique ID
        current_time = int(time.time() * 1000)
        expires_at = current_time + (30 * 24 * 60 * 60 * 1000)  # 30 days from now
        
        property_id = property_counter
        property_data = {
            'propertyId': property_id,  # UNIQUE ID generated
            'userId': user_id,  # Real user ID from token
            'title': data['title'],
            'description': data['description'],
            'price': data['price'],
            'location': data['location'],
            'photos': data.get('photos', '[]'),
            'bedrooms': data['bedrooms'],
            'bathrooms': data['bathrooms'],
            'propertyType': data['propertyType'],
            'createdAt': current_time,
            'expiresAt': expires_at,
            'status': 'active'
        }
        


        # Accept optional structured address fields
        for f in ['addressStreet', 'addressNumber', 'neighborhood', 'lat', 'lon']:
            if f in data:
                property_data[f] = data[f]
        
        # Store property in memory
        properties_storage[property_id] = property_data
        property_counter += 1
        
        return jsonify({
            'success': True,
            'message': 'Property created successfully',
            'property': property_data
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Property creation error: {str(e)}'
        }), 500

@app.route('/properties', methods=['GET'])
def get_all_active_properties():
    try:

        # Debug: Print all headers and auth check
        auth_header = request.headers.get('Authorization')
        print(f"🔍 DEBUG: Auth header received: {auth_header}")
        
        is_authenticated = False
        user_id = None
        
        if auth_header:
            user_id = extract_user_id_from_token(auth_header)
            print(f"🔍 DEBUG: Extracted user_id: {user_id}")
            
            if user_id:
                is_authenticated = user_id in users_storage
                print(f"🔍 DEBUG: User {user_id} in storage: {is_authenticated}")
                if is_authenticated:
                    user_data = users_storage[user_id]
                    print(f"🔍 DEBUG: User role: {user_data.get('role', 'unknown')}")
        
        # Get all active properties
        active_properties = [
            prop for prop in properties_storage.values() 
            if prop.get('status') == 'active'
        ]
        
        print(f"🔍 DEBUG: Found {len(active_properties)} active properties")
        print(f"🔍 DEBUG: Authenticated: {is_authenticated}")
        
        if is_authenticated:
            # Authenticated user - return full property data
            print("✅ Returning FULL property data for authenticated user")
            return jsonify({
                'success': True,
                'message': 'Properties retrieved successfully',
                'properties': active_properties
            }), 200
        else:
            # Guest user - return limited property data
            print("⚠️ Returning LIMITED property data for guest user")
            guest_properties = []
            for prop in active_properties:
                guest_properties.append({
                    'propertyId': prop['propertyId'],
                    'userId': prop['userId'],  # Include userId (guest won't see contact info in UI)
                    'title': prop['title'],
                    'description': 'Register to see full details',  # Safe default
                    'price': prop['price'],
                    'location': prop['location'],  # Basic location
                    'photos': '[]',  # Empty photos array
                    'propertyType': prop['propertyType'],
                    'bedrooms': prop['bedrooms'],
                    'bathrooms': prop['bathrooms'],
                    'createdAt': prop['createdAt'],  # Include for sorting
                    'expiresAt': prop['expiresAt'],  # Include for validity
                    'status': prop['status']  # Include for filtering
                    # Hidden from guests in UI layer, not API layer
                })
            
            return jsonify({
                'success': True,
                'message': 'Properties retrieved successfully (guest view)',
                'properties': guest_properties
            }), 200
        
    except Exception as e:
        print(f"❌ ERROR in get_all_active_properties: {str(e)}")

        auth_header = request.headers.get('Authorization')
        caller_id = extract_user_id_from_token(auth_header) if auth_header else None
        is_authenticated = bool(caller_id and caller_id in users_storage)

        active_properties = [p for p in properties_storage.values() if is_current(p)]

        if is_authenticated:
            safe_props = [p if p.get('userId') == caller_id else teaser_of(p) for p in active_properties]
            return jsonify({'success': True, 'message': 'Properties retrieved successfully', 'properties': safe_props}), 200
        else:
            guest_props = [teaser_of(p) for p in active_properties]
            return jsonify({'success': True, 'message': 'Properties retrieved successfully (guest view)', 'properties': guest_props}), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error retrieving properties: {str(e)}'
        }), 500

@app.route('/properties/user/<int:user_id>', methods=['GET'])
def get_user_properties(user_id):
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        

        # Get properties for specific user
        user_properties = [
            prop for prop in properties_storage.values() 
            if prop.get('userId') == user_id and prop.get('status') == 'active'
        ]
        
        return jsonify({
            'success': True,
            'message': 'User properties retrieved successfully',
            'properties': user_properties
        }), 200

        requester_id = extract_user_id_from_token(auth_header)
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

        property_data = properties_storage.get(property_id)
        if not property_data:

        prop = properties_storage.get(property_id)
        if not prop:
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 404
        

        # Check if request is from authenticated user or guest
        auth_header = request.headers.get('Authorization')
        print(f"🔍 DEBUG: Single property auth header: {auth_header}")
        
        is_authenticated = False
        
        if auth_header:
            user_id = extract_user_id_from_token(auth_header)
            is_authenticated = user_id and user_id in users_storage
            print(f"🔍 DEBUG: Single property authenticated: {is_authenticated}")
        
        if is_authenticated:
            # Authenticated user - full property details
            print("✅ Returning FULL single property data")
            return jsonify({
                'success': True,
                'message': 'Property retrieved successfully',
                'property': property_data
            }), 200
        else:
            # Guest user - limited property details
            print("⚠️ Returning LIMITED single property data")
            guest_property = {
                'propertyId': property_data['propertyId'],
                'userId': property_data['userId'],  # Include (hidden in UI)
                'title': property_data['title'],
                'description': 'Register to see full details',  # Safe default
                'price': property_data['price'],
                'location': property_data['location'],
                'photos': '[]',  # Empty photos array
                'propertyType': property_data['propertyType'],
                'bedrooms': property_data['bedrooms'],
                'bathrooms': property_data['bathrooms'],
                'createdAt': property_data['createdAt'],
                'expiresAt': property_data['expiresAt'],
                'status': property_data['status']
                # Content filtering happens in UI, not API
            }
            
            return jsonify({
                'success': True,
                'message': 'Property retrieved successfully (guest view)',
                'property': guest_property
            }), 200

        # Extract caller & params
        auth_header = request.headers.get('Authorization')
        caller_id = extract_user_id_from_token(auth_header) if auth_header else None
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
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        user_id = extract_user_id_from_token(auth_header)
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
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
        
        # Update property fields
        for field in ['title', 'description', 'price', 'location', 'photos', 'bedrooms', 'bathrooms', 'propertyType']:
            if field in data:
                property_data[field] = data[field]
        


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
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        user_id = extract_user_id_from_token(auth_header)
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
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
        auth_header = request.headers.get('Authorization')
        is_authenticated = False
        
        if auth_header:
            user_id = extract_user_id_from_token(auth_header)
            is_authenticated = user_id and user_id in users_storage
        
        # Filter properties based on search criteria
        results = []
        for prop in properties_storage.values():

            if prop.get('status') != 'active':

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

            if is_authenticated:
                results.append(prop)
            else:
                # Guest view - limited data
                results.append({
                    'propertyId': prop['propertyId'],
                    'userId': prop['userId'],  # Include (UI controls visibility)
                    'title': prop['title'],
                    'description': 'Register to see full details',  # Safe default
                    'price': prop['price'],
                    'location': prop['location'],
                    'photos': '[]',  # Empty photos
                    'propertyType': prop['propertyType'],
                    'bedrooms': prop['bedrooms'],
                    'bathrooms': prop['bathrooms'],
                    'createdAt': prop['createdAt'],
                    'expiresAt': prop['expiresAt'], 
                    'status': prop['status']
                })

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
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        user_id = extract_user_id_from_token(auth_header)
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
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
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        


        requester_id = extract_user_id_from_token(auth_header)
        if not requester_id or requester_id not in users_storage:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
            }), 401
        
        # Get properties expiring within 5 days
        current_time = int(time.time() * 1000)
        five_days = 5 * 24 * 60 * 60 * 1000
        
        expiring_properties = [
            prop for prop in properties_storage.values()
            if (prop.get('userId') == user_id and 

                prop.get('status') == 'active' and
                prop.get('expiresAt', 0) - current_time <= five_days)
        ]
        
        return jsonify({
            'success': True,
            'message': 'Expiring properties retrieved successfully',
            'properties': expiring_properties
        }), 200

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
def send_message():
    try:
        global message_counter
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Extract user ID from token (sender)
        sender_id = extract_user_id_from_token(auth_header)
        if not sender_id or sender_id not in users_storage:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
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
        if receiver_id not in users_storage:
            return jsonify({
                'success': False,
                'message': 'Receiver not found'
            }), 400
        
        # Validate property exists
        property_id = data['propertyId']
        if property_id not in properties_storage:
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 400
        
        # Create message
        current_time = int(time.time() * 1000)
        message_id = message_counter
        
        message_data = {
            'messageId': message_id,
            'senderId': sender_id,
            'receiverId': receiver_id,
            'propertyId': property_id,
            'content': data['content'],
            'messageType': data['messageType'],
            'sentAt': current_time,
            'readAt': None,
            'localId': data.get('localId')  # For offline sync support
        }
        
        # Store message
        messages_storage[message_id] = message_data
        message_counter += 1
        
        print(f"✅ Message sent: {sender_id} → {receiver_id} (Property {property_id}): {data['content']}")
        
        return jsonify({
            'success': True,
            'message': 'Message sent successfully',
            'messageId': message_id
        }), 201
        
    except Exception as e:
        print(f"❌ Send message error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Send message error: {str(e)}'
        }), 500

@app.route('/messages/conversation', methods=['GET'])
def get_conversation_messages():
    try:
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Extract user ID from token
        user_id = extract_user_id_from_token(auth_header)
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
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
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Extract user ID from token
        user_id = extract_user_id_from_token(auth_header)
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
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
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Extract user ID from token
        user_id = extract_user_id_from_token(auth_header)
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
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
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        # Extract user ID from token
        user_id = extract_user_id_from_token(auth_header)
        if not user_id:
            return jsonify({
                'success': False,
                'message': 'Invalid authentication'
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



@app.route('/conversations/share_street', methods=['POST'])
def share_street():
    try:
        auth_header = request.headers.get('Authorization')
        user_id = extract_user_id_from_token(auth_header) if auth_header else None
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
        auth_header = request.headers.get('Authorization')
        user_id = extract_user_id_from_token(auth_header) if auth_header else None
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
        auth_header = request.headers.get('Authorization')
        user_id = extract_user_id_from_token(auth_header) if auth_header else None
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
    return jsonify({
        'users': users_storage,
        'properties': properties_storage,
        'messages': messages_storage
    })

@app.route('/debug/users', methods=['GET'])
def debug_users():
    """Debug endpoint to see all users and their roles"""
    return jsonify({
        'users': [
            {
                'userId': user['userId'],
                'email': user['email'],
                'displayName': user.get('displayName', 'No Name'),
                'role': user.get('role', 'tenant'),
                'createdAt': user['createdAt']
            }
            for user in users_storage.values()
        ]
    })

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)