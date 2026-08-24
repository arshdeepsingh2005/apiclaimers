"""
Validation utilities for incoming code data.
"""
from app.config import Config


def validate_code_data(data):
    """
    Validate and normalize incoming code data.
    
    Args:
        data: Dictionary or dict-like object containing code data
        
    Returns:
        Dictionary with validated code data, or None if invalid
    """
    if not data or not isinstance(data, dict):
        return None
    
    # Extract code from various possible field names
    code = None
    possible_code_fields = ['code', 'message', 'text', 'data', 'content', 'value']
    
    for field in possible_code_fields:
        if field in data and data[field]:
            code = str(data[field]).strip()
            break
    
    # If no code found, check if data itself is a string
    if not code and len(data) == 1:
        code = str(list(data.values())[0]).strip()
    
    if not code or len(code) > Config.MAX_CODE_LENGTH:
        return None
    
    # Normalize codetype (single supported key)
    raw_code_type = data.get('codetype')
    code_type = str(raw_code_type).strip() if raw_code_type else 'default'
    
    # Build normalized code data
    code_data = {
        'code': code,
    }
    
    # Preserve optional top-level fields (main keys only)
    optional_fields = ('value', 'couponType')
    for field in optional_fields:
        if field in data:
            code_data[field] = data[field]
    
    return code_data


def normalize_username(raw_username):
    """
    Normalize username strings while enforcing basic length + type checks.
    """
    if raw_username is None:
        return None
    username = str(raw_username).strip()
    if not username or len(username) > 64:
        return None
    return username


def extract_username(payload):
    """
    Extract a username field from the incoming payload.
    """
    if not isinstance(payload, dict):
        return None

    candidate_fields = ['username', 'user', 'account', 'principal']
    for field in candidate_fields:
        if field in payload:
            username = normalize_username(payload[field])
            if username:
                return username

    metadata = payload.get('metadata', {})
    if isinstance(metadata, dict):
        for field in candidate_fields:
            if field in metadata:
                username = normalize_username(metadata[field])
                if username:
                    return username

    return None



