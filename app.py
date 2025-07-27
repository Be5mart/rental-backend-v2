# TODO: As project grows, move routes to routes/ folder
# TODO: Move database config to config/ folder
# etc.

from flask import Flask, request, jsonify
import time
import json

app = Flask(__name__)

# In-memory storage (will be replaced with database later)
property_counter = 1
user_counter = 1
message_counter = 1
properties_storage = {}
users_storage = {}
messages_storage = {}

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
        
        # Basic validation
        if not email or not password or not phone_number:
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
        
        # Check if user already exists
        for user_id, user_data in users_storage.items():
            if user_data['email'] == email:
                return jsonify({
                    'success': False,
                    'message': 'User already exists'
                }), 400
        
        # Store user (simple in-memory storage)
        user_id = user_counter
        users_storage[user_id] = {
            'userId': user_id,
            'email': email,
            'password': password,  # In production, this would be hashed
            'phoneNumber': phone_number,
            'createdAt': int(time.time() * 1000)
        }
        user_counter += 1
        
        return jsonify({
            'success': True,
            'message': 'Registration successful!',
            'token': f'token_user_{user_id}_{int(time.time())}',
            'userId': user_id
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
                        'userId': user_id
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
        # Return all active properties from storage
        active_properties = [
            prop for prop in properties_storage.values() 
            if prop.get('status') == 'active'
        ]
        
        return jsonify({
            'success': True,
            'message': 'Properties retrieved successfully',
            'properties': active_properties
        }), 200
        
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
            return jsonify({
                'success': False,
                'message': 'Property not found'
            }), 404
        
        return jsonify({
            'success': True,
            'message': 'Property retrieved successfully',
            'property': property_data
        }), 200
        
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
        
        # Filter properties based on search criteria
        results = []
        for prop in properties_storage.values():
            if prop.get('status') != 'active':
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
            
            results.append(prop)
        
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
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error retrieving expiring properties: {str(e)}'
        }), 500

# Messaging Routes
@app.route('/messages', methods=['POST'])
def send_message():
    try:
        global message_counter
        
        # DEBUG: Print the request data
        print(f"🔍 DEBUG: Received message request")
        print(f"🔍 Headers: {dict(request.headers)}")
        print(f"🔍 Body: {request.get_json()}")

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

@app.route('/debug/data', methods=['GET'])
def debug_data():
    return jsonify({
        'users': users_storage,
        'properties': properties_storage,
        'messages': messages_storage
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)