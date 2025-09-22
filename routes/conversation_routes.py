from flask import Blueprint, request, jsonify
from routes.auth_routes import get_authenticated_user_id
from utils.conversation_helpers import get_visibility_flags, visibility_key, conversation_visibility
from utils.legacy_storage import users_storage, properties_storage

conversation_bp = Blueprint('conversation', __name__)

@conversation_bp.route('/conversations/share_street', methods=['POST'])
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

@conversation_bp.route('/conversations/share_exact', methods=['POST'])
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

@conversation_bp.route('/conversations/visibility', methods=['GET'])
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