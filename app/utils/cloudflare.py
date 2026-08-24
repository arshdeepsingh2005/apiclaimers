"""
Utility functions for handling Cloudflare headers and features.
"""
from flask import request


def get_real_client_ip() -> str:
    """
    Get the real client IP address, handling Cloudflare proxy.
    
    Priority:
    1. CF-Connecting-IP (Cloudflare header) - most reliable
    2. X-Forwarded-For (standard proxy header)
    3. X-Real-IP (nginx/other proxies)
    4. request.remote_addr (direct connection)
    
    Returns:
        str: Client IP address
    """
    # Cloudflare provides the real client IP in this header
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        # CF-Connecting-IP is always a single IP, not a list
        return cf_ip.strip()
    
    # Fallback to X-Forwarded-For (may contain multiple IPs)
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        # The first IP is usually the original client
        ips = [ip.strip() for ip in x_forwarded_for.split(',')]
        if ips:
            return ips[0]
    
    # Fallback to X-Real-IP (nginx and some other proxies)
    x_real_ip = request.headers.get('X-Real-IP')
    if x_real_ip:
        return x_real_ip.strip()
    
    # Last resort: direct connection
    return request.remote_addr or 'unknown'


def is_cloudflare_request() -> bool:
    """
    Check if the request is coming through Cloudflare.
    
    Returns:
        bool: True if request is proxied through Cloudflare
    """
    # Cloudflare sets these headers when proxying requests
    return bool(
        request.headers.get('CF-Connecting-IP') or
        request.headers.get('CF-Ray') or
        request.headers.get('CF-Visitor')
    )


def get_cloudflare_country() -> str:
    """
    Get the client's country code from Cloudflare headers.
    
    Returns:
        str: ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB'), or 'unknown'
    """
    return request.headers.get('CF-IPCountry', 'unknown')


def get_cloudflare_ray_id() -> str:
    """
    Get Cloudflare Ray ID for request tracking.
    
    Returns:
        str: CF-Ray ID or empty string
    """
    return request.headers.get('CF-Ray', '')

