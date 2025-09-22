from services.base_service import BaseService
from models.user import User
from models.property import Property
from datetime import datetime, timedelta
from sqlalchemy import or_
import json


class PropertyService(BaseService):
    def __init__(self, db):
        super().__init__(db)

    def _property_to_dict(self, prop: Property) -> dict:
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

    def _normalize_property(self, prop: dict) -> dict:
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

    def _teaser_of(self, prop: dict) -> dict:
        p = self._normalize_property(prop)
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

    def create_property(self, user_id, property_data):
        try:
            user = self.db.query(User).filter(User.user_id == user_id).first()
            if not user or user.role != 'landlord':
                print(f"🚫 403 CREATE_LISTING_DENIED: user_id={user_id}, role={user.role if user else 'None'}")
                return self._error_response('Create Listing is for landlords')

            required = ['title', 'description', 'price', 'location', 'bedrooms', 'bathrooms', 'propertyType']
            for f in required:
                if f not in property_data:
                    return self._error_response(f'Missing required field: {f}')

            photos_raw = property_data.get('photos', [])
            if isinstance(photos_raw, str):
                try:
                    photos = json.loads(photos_raw)
                except Exception:
                    photos = []
            else:
                photos = list(photos_raw) if photos_raw is not None else []

            expires_at = datetime.now() + timedelta(days=30)

            location_data = property_data.get('location', {})
            if isinstance(location_data, str):
                try:
                    location_data = json.loads(location_data)
                except:
                    location_data = {}

            for f in ['addressStreet', 'addressNumber', 'neighborhood', 'lat', 'lon']:
                if f in property_data:
                    location_data[f] = property_data[f]

            property_obj = Property(
                user_id=user_id,
                title=property_data['title'],
                description=property_data['description'],
                price=property_data['price'],
                location=location_data,
                photos=photos,
                bedrooms=property_data['bedrooms'],
                bathrooms=property_data['bathrooms'],
                property_type=property_data['propertyType'],
                expires_at=expires_at,
                status='active'
            )

            self.db.add(property_obj)
            self.db.commit()
            self.db.refresh(property_obj)

            return self._success_response({
                'message': 'Property created successfully',
                'property': self._property_to_dict(property_obj)
            })

        except Exception as e:
            self.db.rollback()
            return self._error_response(f'Property creation error: {str(e)}')

    def get_properties(self, caller_id=None):
        try:
            is_authenticated = bool(caller_id)
            active_properties = self.db.query(Property).filter(
                Property.status == 'active',
                or_(Property.expires_at.is_(None), Property.expires_at > datetime.now())
            ).all()

            if is_authenticated:
                safe_props = []
                for prop in active_properties:
                    prop_dict = self._property_to_dict(prop)
                    if prop.user_id == caller_id:
                        safe_props.append(prop_dict)
                    else:
                        safe_props.append(self._teaser_of(prop_dict))

                return self._success_response({
                    'message': 'Properties retrieved successfully',
                    'properties': safe_props
                })
            else:
                guest_props = [self._teaser_of(self._property_to_dict(prop)) for prop in active_properties]
                return self._success_response({
                    'message': 'Properties retrieved successfully (guest view)',
                    'properties': guest_props
                })

        except Exception as e:
            return self._error_response(f'Error retrieving properties: {str(e)}')