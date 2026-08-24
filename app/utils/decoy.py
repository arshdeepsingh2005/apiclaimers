"""
Decoy response generators for fake routes.
"""
from flask import jsonify
import random


def generate_decoy_response():
    """Generate a random decoy response."""
    decoy_responses = [
        {'status': 'ok', 'message': 'Service operational'},
        {'status': 'active', 'data': []},
        {'result': 'success', 'timestamp': '2024-01-01T00:00:00Z'},
        {'code': 200, 'message': 'Request processed'},
        {'status': 'online', 'uptime': '99.9%'}
    ]
    return jsonify(random.choice(decoy_responses))



