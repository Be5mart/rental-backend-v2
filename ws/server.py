"""
WebSocket server for real-time messaging using Flask-SocketIO and Redis pub/sub.
Handles JWT authentication, room-based messaging, and message status updates.
"""

import os
import json
import logging
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_jwt_extended import JWTManager, decode_token, get_jwt_identity
from flask_cors import CORS
import redis
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app for WebSocket
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'change-me')

# Configure CORS for WebSocket
CORS(app, origins="*")

# Initialize JWT
jwt = JWTManager(app)

# Initialize Redis for pub/sub
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
redis_client = redis.from_url(redis_url, decode_responses=True)

# Initialize SocketIO with Redis adapter for scalability
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    async_mode='eventlet',
    message_queue=redis_url,  # Use Redis as message queue for multi-instance support
    logger=True,
    engineio_logger=True
)

# Store active connections: {user_id: {property_id: sid}}
active_connections = {}

def authenticate_token(token):
    """Validate JWT token and return user_id"""
    try:
        decoded = decode_token(token)
        return int(decoded['sub'])  # user_id is stored in 'sub' claim
    except Exception as e:
        logger.error(f"Token validation failed: {e}")
        return None

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection with JWT authentication"""
    token = request.args.get('token')
    conversation_id = request.args.get('conversationId')
    
    if not token or not conversation_id:
        logger.warning(f"Missing parameters - Token: {bool(token)}, ConversationId: {bool(conversation_id)}")
        emit('error', {'message': 'Missing required parameters: token and conversationId'})
        disconnect()
        return
    
    # Authenticate user
    user_id = authenticate_token(token)
    if not user_id:
        logger.warning(f"Authentication failed for token: {token[:20]}...")
        emit('error', {'message': 'Authentication failed'})
        disconnect()
        return
    
    # Store connection info
    if user_id not in active_connections:
        active_connections[user_id] = {}
    
    active_connections[user_id][conversation_id] = {
        'sid': request.sid,
        'connected_at': datetime.now().isoformat()
    }
    
    # Join conversation room using contract format: conv:{conversationId}
    room = f"conv:{conversation_id}"
    join_room(room)
    
    logger.info(f"User {user_id} connected to room {room}")
    
    # Confirm connection
    emit('connected', {
        'status': 'connected',
        'room': room,
        'user_id': user_id,
        'conversation_id': conversation_id
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    # Find and remove user connection
    user_to_remove = None
    conversation_to_remove = None
    
    for user_id, conversations in active_connections.items():
        for conversation_id, conn_info in conversations.items():
            if conn_info['sid'] == request.sid:
                user_to_remove = user_id
                conversation_to_remove = conversation_id
                break
        if user_to_remove:
            break
    
    if user_to_remove and conversation_to_remove:
        del active_connections[user_to_remove][conversation_to_remove]
        if not active_connections[user_to_remove]:  # Remove user if no connections left
            del active_connections[user_to_remove]
        logger.info(f"User {user_to_remove} disconnected from conversation {conversation_to_remove}")

@socketio.on('send_message')
def handle_send_message(data):
    """Handle message sending through WebSocket with persistence and canonical ID"""
    try:
        # Extract user_id and conversation_id from the connection
        user_id = None
        conversation_id = None
        
        for uid, conversations in active_connections.items():
            for cid, conn_info in conversations.items():
                if conn_info['sid'] == request.sid:
                    user_id = uid
                    conversation_id = cid
                    break
            if user_id:
                break
        
        if not user_id or not conversation_id:
            emit('error', {'message': 'User not authenticated or conversation not found'})
            return
        
        # Validate required fields
        required_fields = ['clientMessageId', 'receiverId', 'propertyId', 'content', 'messageType']
        for field in required_fields:
            if field not in data:
                emit('error', {'message': f'Missing required field: {field}'})
                return
        
        receiver_id = int(data['receiverId'])
        property_id = int(data['propertyId'])
        content = data['content']
        message_type = data['messageType']
        client_message_id = data['clientMessageId']
        
        # TODO: Persist message to database and get canonical messageId
        # For now, we'll simulate this with a timestamp-based ID
        canonical_message_id = f"msg_{int(datetime.now().timestamp() * 1000)}"
        sent_at_ms = int(datetime.now().timestamp() * 1000)
        
        # Emit ack_sent to sender with canonical ID
        emit('ack_sent', {
            'clientMessageId': client_message_id,
            'messageId': canonical_message_id,
            'timestamp': sent_at_ms
        })
        
        # Create message data for broadcast
        message_data = {
            'type': 'message_created',
            'conversationId': conversation_id,
            'messageId': canonical_message_id,
            'senderId': str(user_id),
            'receiverId': str(receiver_id),
            'propertyId': str(property_id),
            'content': content,
            'messageType': message_type,
            'sentAt': sent_at_ms
        }
        
        # Broadcast message_created to conversation room
        room = f"conv:{conversation_id}"
        socketio.emit('message_created', message_data, room=room)
        
        # Publish to Redis for other services (push notifications, etc.)
        redis_message = {
            'type': 'websocket_message',
            'data': message_data
        }
        if redis_client:
            redis_client.publish('messaging_events', json.dumps(redis_message))
        
        logger.info(f"Message {canonical_message_id} sent from {user_id} to {receiver_id} in conversation {conversation_id}")
        
    except Exception as e:
        logger.error(f"Error handling send_message: {e}")
        emit('error', {'message': 'Failed to send message'})

@socketio.on('ping')
def handle_ping(data):
    """Handle heartbeat ping"""
    emit('pong', {'timestamp': datetime.now().isoformat()})

@socketio.on('message_delivered')
def handle_message_delivered(data):
    """Handle message delivered acknowledgment"""
    try:
        message_id = data.get('messageId')
        conversation_id = data.get('conversationId')
        
        if not message_id or not conversation_id:
            emit('error', {'message': 'Missing messageId or conversationId'})
            return
        
        # Find user_id from connection
        user_id = None
        for uid, conversations in active_connections.items():
            for cid, conn_info in conversations.items():
                if conn_info['sid'] == request.sid:
                    user_id = uid
                    break
            if user_id:
                break
        
        if not user_id:
            emit('error', {'message': 'User not authenticated'})
            return
        
        # Broadcast ack_delivered to conversation room
        delivered_data = {
            'messageId': message_id,
            'deliveredBy': str(user_id),
            'timestamp': int(datetime.now().timestamp() * 1000)
        }
        
        room = f"conv:{conversation_id}"
        socketio.emit('ack_delivered', delivered_data, room=room)
        
        # Publish to Redis for persistence
        redis_message = {
            'type': 'message_delivered',
            'data': delivered_data
        }
        if redis_client:
            redis_client.publish('messaging_events', json.dumps(redis_message))
        
        logger.info(f"Message {message_id} delivered by user {user_id} in conversation {conversation_id}")
        
    except Exception as e:
        logger.error(f"Error handling message delivered: {e}")
        emit('error', {'message': 'Failed to mark message as delivered'})

def broadcast_message_to_conversation(conversation_id, message_data):
    """Broadcast message to conversation room"""
    room = f"conv:{conversation_id}"
    socketio.emit('message_created', message_data, room=room)
    logger.info(f"Broadcasted message to conversation room {room}")

def broadcast_delivery_ack(conversation_id, message_id, delivered_by):
    """Broadcast delivery acknowledgment to conversation"""
    delivered_data = {
        'messageId': message_id,
        'deliveredBy': str(delivered_by),
        'timestamp': int(datetime.now().timestamp() * 1000)
    }
    
    room = f"conv:{conversation_id}"
    socketio.emit('ack_delivered', delivered_data, room=room)
    logger.info(f"Broadcasted delivery ack for message {message_id} to room {room}")

# Redis subscriber for external message events
def redis_subscriber():
    """Subscribe to Redis pub/sub for external events"""
    pubsub = redis_client.pubsub()
    pubsub.subscribe('messaging_events')
    
    for message in pubsub.listen():
        if message['type'] == 'message':
            try:
                event_data = json.loads(message['data'])
                event_type = event_data.get('type')
                
                if event_type == 'external_message':
                    # Message sent via REST API, broadcast to WebSocket users
                    data = event_data['data']
                    conversation_id = data.get('conversationId')
                    
                    if conversation_id:
                        broadcast_message_to_conversation(conversation_id, data)
                        logger.info(f"Broadcasted external message to conversation {conversation_id}")
                        
                elif event_type == 'ack_delivered':
                    # Delivery acknowledgment from external source (REST API)
                    data = event_data['data']
                    conversation_id = data.get('conversationId')
                    message_id = data.get('messageId')
                    delivered_by = data.get('deliveredBy')
                    
                    if conversation_id and message_id and delivered_by:
                        # Emit ack_delivered to conversation room
                        room = f"conv:{conversation_id}"
                        delivered_data = {
                            'messageId': message_id,
                            'deliveredBy': delivered_by,
                            'timestamp': int(datetime.now().timestamp() * 1000)
                        }
                        socketio.emit('ack_delivered', delivered_data, room=room)
                        logger.info(f"📨 Broadcasted ack_delivered for message {message_id} to room {room}")
                    
            except Exception as e:
                logger.error(f"Error processing Redis message: {e}")

# Health check endpoint
@app.route('/health')
def health_check():
    return {
        'status': 'healthy',
        'active_connections': len(active_connections),
        'redis_connected': redis_client.ping()
    }

# Status endpoint for monitoring
@app.route('/status')
def status():
    return {
        'active_connections': len(active_connections),
        'total_rooms': sum(len(props) for props in active_connections.values()),
        'redis_connected': redis_client.ping(),
        'timestamp': datetime.now().isoformat()
    }

if __name__ == '__main__':
    # Start Redis subscriber in background thread
    import threading
    subscriber_thread = threading.Thread(target=redis_subscriber, daemon=True)
    subscriber_thread.start()
    
    port = int(os.environ.get('PORT', 5001))  # Different port from main app
    logger.info(f"Starting WebSocket server on port {port}")
    
    # Run with eventlet for production-ready async support
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port, 
        debug=False,
        use_reloader=False  # Disable reloader in production
    )