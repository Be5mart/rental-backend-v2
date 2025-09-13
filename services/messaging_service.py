"""
Messaging service with push notification integration
"""
import time
import sys
import os

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.push_service import PushService

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
            conversation_id = f"{property_id}_{min(sender_id, recipient_user_id)}_{max(sender_id, recipient_user_id)}"
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
    "sentAt": str(sent_at)  # milliseconds, as string
}
            
            # Send push notification
            push_success = PushService.send_new_message_push(recipient_user_id, push_payload)
            
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