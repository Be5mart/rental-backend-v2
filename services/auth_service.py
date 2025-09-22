from services.base_service import BaseService
from flask_jwt_extended import create_access_token
from models.user import User
import hashlib


class AuthService(BaseService):
    def __init__(self, db):
        super().__init__(db)

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def _verify_password(self, password: str, hashed: str) -> bool:
        return self._hash_password(password) == hashed

    def _validate_role(self, role):
        if not role:
            return None
        role_lower = role.lower().strip()
        valid_roles = ['tenant', 'landlord']
        return role_lower if role_lower in valid_roles else None

    def register_user(self, email, password, phone_number, role, display_name=None):
        try:
            if not email or not password or not phone_number:
                return self._error_response('Missing required fields')

            validated_role = self._validate_role(role)
            if validated_role is None:
                return self._error_response('Invalid role. Must be tenant or landlord')

            existing_user = self.db.query(User).filter(User.email.ilike(email)).first()
            if existing_user:
                return self._error_response('User already exists')

            if not display_name or not display_name.strip():
                email_local = email.split('@')[0]
                display_name = email_local.replace('.', ' ').replace('_', ' ').title()

            user = User(
                email=email.lower(),
                password_hash=self._hash_password(password),
                phone_number=phone_number,
                role=validated_role,
                display_name=display_name.strip()
            )

            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)

            return self._success_response({
                'message': 'Registration successful!',
                'token': create_access_token(identity=str(user.user_id)),
                'userId': user.user_id,
                'role': user.role,
                'displayName': user.display_name
            })

        except Exception as e:
            self.db.rollback()
            return self._error_response(f'Registration error: {str(e)}')

    def authenticate_user(self, email, password):
        try:
            if not email or not password:
                return self._error_response('Email and password required')

            user = self.db.query(User).filter(User.email.ilike(email)).first()
            if not user:
                return self._error_response('User not found')

            if not self._verify_password(password, user.password_hash):
                return self._error_response('Invalid password')

            token = create_access_token(identity=str(user.user_id))
            print(f"🔑 Generated token for {email}: len={len(token)}")

            return self._success_response({
                'message': 'Login successful!',
                'token': token,
                'userId': user.user_id,
                'role': user.role,
                'displayName': user.display_name or user.email.split('@')[0]
            })

        except Exception as e:
            return self._error_response(f'Login error: {str(e)}')

    def verify_token(self, user_id):
        try:
            user = self.db.query(User).filter(User.user_id == user_id).first()
            if not user:
                return self._error_response('Invalid token')

            return self._success_response({'message': 'Token is valid'})

        except Exception as e:
            return self._error_response(f'Token verification error: {str(e)}')

    def get_user_profile(self, user_id):
        try:
            user = self.db.query(User).filter(User.user_id == user_id).first()
            if not user:
                return self._error_response('Authentication required')

            return self._success_response({
                'userId': user.user_id,
                'email': user.email,
                'displayName': user.display_name or '',
                'role': user.role
            })

        except Exception as e:
            return self._error_response(f'Error: {str(e)}')