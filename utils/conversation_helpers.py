conversation_visibility = {}

def visibility_key(property_id: int, tenant_id: int) -> str:
    return f"{property_id}_{tenant_id}"

def get_visibility_flags(property_id: int, tenant_id: int):
    flags = conversation_visibility.get(visibility_key(property_id, tenant_id), {})
    return {
        "canSeeStreet": bool(flags.get("canSeeStreet", False)),
        "canSeeExactAddress": bool(flags.get("canSeeExactAddress", False)),
    }