"""
Messaging service with push notification integration
"""
import time
import sys
import os

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.push_service import PushService
from services.base_service import BaseService
from models.user import User
from models.property import Property
from models.message import Message
from datetime import datetime
from sqlalchemy import and_, or_, desc
import json

def conversation_id_for(property_id: int, u1: int, u2: int) -> str:
    """
    Canonical 1:1 conversation id: c_{propertyId}_{minUserId}_{maxUserId}
    Pure, side-effect free; safe to import anywhere.
    """
    a, b = sorted([int(u1), int(u2)])
    return f"c_{int(property_id)}_{a}_{b}"


class MessagingService:
    @staticmethod
    def send_message_with_push(message_data: dict, sender_name: str = "Someone") -> bool:
        """
        Send a message and trigger push notification
        
        Args:
            message_data: Message data dictionary containing:
                - messageId: int
                - senderId: int  
                - receiverId: int
                - propertyId: int
                - content: str
                - messageType: str
                - sentAt: int (timestamp)
                - readAt: int|None
                - localId: str|None
            sender_name: Display name of the sender
            
        Returns:
            True if push notification was sent successfully
        """
        try:
            # Extract data for push notification
            recipient_user_id = message_data.get('receiverId')
            sender_id = message_data.get('senderId')
            property_id = message_data.get('propertyId')
            content = message_data.get('content', '')
            sent_at = message_data.get('sentAt', int(time.time() * 1000))
            

            # Generate conversation ID (you might want to use a different format)
            conversation_id = conversation_id_for(property_id, sender_id, recipient_user_id)
            message_id = message_data.get('messageId')
            
            # Prepare push notification payload
            push_payload = {
    # required by client contract
    "conversationId": conversation_id,
    "messageId": str(message_id) if message_id is not None else "",
    "senderId": str(sender_id),

    # existing fields you already use
    "propertyId": str(property_id),
    "otherUserId": str(sender_id),
    "senderName": sender_name,
    "preview": (content[:80] if content else "New message"),
    "sentAt": int(sent_at)
}
            
            # Send push notification
            push_success = PushService.send_new_message_push(push_payload)
            
            if push_success:
                print(f"✅ Push notification sent for message {message_data.get('messageId')}")
            else:
                print(f"⚠️  Push notification failed for message {message_data.get('messageId')}")
            
            return push_success
            
        except Exception as e:
            print(f"❌ Error sending push notification: {e}")
            return False
    
    @staticmethod
    def get_sender_display_name_from_db(sender_id: int) -> str:
        """
        Get display name for a sender from database
        
        Args:
            sender_id: ID of the sender
            
        Returns:
            Display name of the sender
        """
        try:
            # Import here to avoid circular imports
            from config.database import SessionLocal
            from models.user import User
            
            with SessionLocal() as db:
                sender = db.query(User).filter(User.user_id == sender_id).first()
                if not sender:
                    return "Someone"
                
                if sender.display_name and sender.display_name.strip():
                    return sender.display_name.strip()
                
                # Fallback to email-based name
                if sender.email:
                    email_local = sender.email.split('@')[0]
                    return email_local.replace('.', ' ').replace('_', ' ').title()
                
                return "Someone"
                
        except Exception as e:
            print(f"❌ Error getting sender display name: {e}")
            return "Someone"
    
    @staticmethod
    def get_sender_display_name(users_storage: dict, sender_id: int) -> str:
        """
        Get display name for a sender (legacy method for compatibility)
        
        Args:
            users_storage: Dictionary of user data (unused, for compatibility)
            sender_id: ID of the sender
            
        Returns:
            Display name of the sender
        """
        return MessagingService.get_sender_display_name_from_db(sender_id)
    
    @staticmethod
    def send_test_push(user_id: int, title: str = "Test Notification", body: str = "This is a test notification") -> bool:
        """
        Send a test push notification
        
        Args:
            user_id: User ID to send test notification to
            title: Notification title
            body: Notification body
            
        Returns:
            True if notification was sent successfully
        """
        return PushService.send_test_notification(user_id, title, body)


class MessageService(BaseService):
    def __init__(self, db, redis_client=None):
        super().__init__(db)
        self.redis_client = redis_client

    def _message_to_dict(self, msg: Message) -> dict:
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

    def send_message(self, sender_id, receiver_id, property_id, content, message_type, local_id=None):
        try:
            sender = self.db.query(User).filter(User.user_id == sender_id).first()
            if not sender:
                return self._error_response('Authentication required')

            receiver = self.db.query(User).filter(User.user_id == receiver_id).first()
            if not receiver:
                return self._error_response('Receiver not found')

            property_obj = self.db.query(Property).filter(Property.property_id == property_id).first()
            if not property_obj:
                return self._error_response('Property not found')

            message_obj = Message(
                sender_id=sender_id,
                receiver_id=receiver_id,
                property_id=property_id,
                content=content,
                message_type=message_type
            )

            self.db.add(message_obj)
            self.db.commit()
            self.db.refresh(message_obj)

            # Publish to WS via Redis with canonical conversationId
            if self.redis_client:
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
                            'content': content,
                            'messageType': message_type,
                            'sentAt': int(message_obj.sent_at.timestamp() * 1000) if message_obj.sent_at else None,
                            'status': 'sent'
                        }
                    }
                    self.redis_client.publish('messaging_events', json.dumps(ws_message))
                    print("📡 Message broadcasted to WebSocket users")
                except Exception as e:
                    print(f"⚠️  WebSocket broadcast failed: {e}")

            # Push notification
            try:
                sender_name = MessagingService.get_sender_display_name_from_db(sender_id)
                message_data = self._message_to_dict(message_obj)
                if local_id:
                    message_data['localId'] = local_id
                MessagingService.send_message_with_push(message_data, sender_name)
            except Exception as e:
                print(f"⚠️  Push notification failed: {e}")

            return self._success_response({
                'message': 'Message sent successfully',
                'messageId': message_obj.message_id
            })

        except Exception as e:
            self.db.rollback()
            print(f"❌ Send message error: {str(e)}")
            return self._error_response(f'Send message error: {str(e)}')

    def get_conversation(self, user_id, property_id, other_user_id):
        try:
            q = self.db.query(Message).filter(
                Message.property_id == property_id,
                (
                    (Message.sender_id == user_id) & (Message.receiver_id == other_user_id)
                ) | (
                    (Message.sender_id == other_user_id) & (Message.receiver_id == user_id)
                )
            ).order_by(Message.sent_at.asc())

            rows = q.all()
            conversation_messages = [self._message_to_dict(m) for m in rows]

            # Emit ack_delivered for messages sent by other_user -> current user
            if self.redis_client and conversation_messages:
                conv_id = conversation_id_for(property_id, user_id, other_user_id)
                for m in conversation_messages:
                    if m['senderId'] == other_user_id and m['receiverId'] == user_id and m['readAt'] is None:
                        self.redis_client.publish('messaging_events', json.dumps({
                            'type': 'ack_delivered',
                            'data': {
                                'messageId': str(m['messageId']),
                                'conversationId': conv_id,
                                'deliveredBy': str(user_id)
                            }
                        }))

            return self._success_response({
                'message': 'Conversation retrieved successfully',
                'messages': conversation_messages
            })

        except Exception as e:
            print(f"❌ Get conversation error: {e}")
            return self._error_response(f'Get conversation error: {e}')

    def get_user_conversations(self, user_id):
        try:
            rows = self.db.query(Message).filter(
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

            return self._success_response({
                'message': 'Conversations retrieved successfully',
                'conversations': conversations
            })

        except Exception as e:
            print(f"❌ Get conversations error: {e}")
            return self._error_response(f'Get conversations error: {e}')

    def mark_messages_as_read(self, user_id, property_id, sender_id):
        try:
            read_time = datetime.now()
            q = self.db.query(Message).filter(
                Message.property_id == property_id,
                Message.sender_id == sender_id,
                Message.receiver_id == user_id,
                Message.read_at.is_(None)
            )
            marked = q.update({Message.read_at: read_time}, synchronize_session=False)
            self.db.commit()

            return self._success_response({
                'message': f'Marked {marked} messages as read'
            })

        except Exception as e:
            self.db.rollback()
            print(f"❌ Mark messages read error: {e}")
            return self._error_response(f'Mark messages read error: {e}')

    def delete_conversation(self, user_id, property_id, other_user_id):
        try:
            q = self.db.query(Message).filter(
                Message.property_id == property_id,
                (
                    (Message.sender_id == user_id) & (Message.receiver_id == other_user_id)
                ) | (
                    (Message.sender_id == other_user_id) & (Message.receiver_id == user_id)
                )
            )
            deleted = q.delete(synchronize_session=False)
            self.db.commit()

            print(f"✅ Deleted {deleted} messages from conversation")
            return self._success_response({
                'message': f'Deleted {deleted} messages'
            })

        except Exception as e:
            self.db.rollback()
            print(f"❌ Delete conversation error: {e}")
            return self._error_response(f'Delete conversation error: {e}')