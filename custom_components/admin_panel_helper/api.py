import logging
import os
import hmac
import hashlib
import json
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from homeassistant.components.http import HomeAssistantView
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.core import HomeAssistant
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Base URL for Supervisor API
SUPERVISOR_BASE_URL = "http://supervisor"

# Security configuration
SECURITY_CONFIG = {
    "request_signing_enabled": True,
    "signature_timeout": 300,  # 5 minutes
    "max_request_size": 1024 * 1024,  # 1MB
    "cache_enabled": True,
    "cache_ttl": 60,  # 60 seconds
}

# Configuration for allowed Supervisor endpoints
ALLOWED_ENDPOINTS = {
    "addons": {
        "path": "/addons",
        "methods": ["GET"],
        "description": "Get supervisor addons information",
        "allowed_params": ["filter", "limit", "offset"],
        "cache_ttl": 30  # 30 seconds for addons
    }
    # Future endpoints can be added here like:
    # "snapshots": {
    #     "path": "/snapshots",
    #     "methods": ["GET", "POST"],
    #     "description": "Manage supervisor snapshots",
    #     "allowed_params": ["limit", "offset"],
    #     "cache_ttl": 60
    # }
}

# Rate limiting configuration
RATE_LIMIT = 5  # Max requests per period
RATE_PERIOD = timedelta(minutes=1)  # Time window
SANITIZE_RESPONSE = True  # Strip sensitive data

# In-memory cache for responses
_response_cache = {}
_cache_timestamps = {}


class AdminPanelHelperView(HomeAssistantView):
    """Secure view for proxying Supervisor API endpoints with enhanced security."""
    
    url = "/api/admin_panel_helper/{endpoint}"
    name = "api:admin_panel_helper"
    requires_auth = True

    def __init__(self, hass: HomeAssistant):
        self.hass = hass

    async def get(self, request, endpoint):
        """Handle GET requests to Supervisor endpoints."""
        return await self._handle_request(request, endpoint, "GET")

    async def post(self, request, endpoint):
        """Handle POST requests to Supervisor endpoints."""
        return await self._handle_request(request, endpoint, "POST")

    async def put(self, request, endpoint):
        """Handle PUT requests to Supervisor endpoints."""
        return await self._handle_request(request, endpoint, "PUT")

    async def delete(self, request, endpoint):
        """Handle DELETE requests to Supervisor endpoints."""
        return await self._handle_request(request, endpoint, "DELETE")

    async def _handle_request(self, request, endpoint: str, method: str):
        """Secure request handler with comprehensive security checks."""
        start_time = time.time()
        user_id = None
        
        try:
            # 1. SECURITY: Validate endpoint exists and method is allowed
            if endpoint not in ALLOWED_ENDPOINTS:
                await self._log_security_event("unauthorized_endpoint", {
                    "endpoint": endpoint,
                    "method": method,
                    "ip": request.remote
                })
                return self.json_message("Endpoint not found", status_code=404)

            endpoint_config = ALLOWED_ENDPOINTS[endpoint]
            if method not in endpoint_config["methods"]:
                await self._log_security_event("unauthorized_method", {
                    "endpoint": endpoint,
                    "method": method,
                    "allowed_methods": endpoint_config["methods"]
                })
                return self.json_message("Method not allowed", status_code=405)

            # 2. SECURITY: Validate API key
            expected_key = self.hass.data[DOMAIN].get("api_key")
            provided_key = request.headers.get("x_api_key")

            if not expected_key or expected_key != provided_key:
                await self._log_security_event("invalid_api_key", {
                    "endpoint": endpoint,
                    "method": method,
                    "ip": request.remote
                })
                return self.json_message("Forbidden", status_code=403)

            # 3. SECURITY: Ensure user is admin
            user = request.get("hass_user")
            if not user or not user.is_admin:
                await self._log_security_event("non_admin_access", {
                    "user_id": user.id if user else None,
                    "endpoint": endpoint,
                    "method": method
                })
                return self.json_message("Admin access required", status_code=403)

            user_id = user.id

            # 4. SECURITY: Request signing validation
            if SECURITY_CONFIG["request_signing_enabled"]:
                if not await self._verify_request_signature(request):
                    await self._log_security_event("invalid_signature", {
                        "user_id": user_id,
                        "endpoint": endpoint,
                        "method": method
                    })
                    return self.json_message("Invalid request signature", status_code=401)

            # 5. SECURITY: Check rate limiting with persistent storage
            if not await self._check_rate_limit(user_id):
                await self._log_security_event("rate_limit_exceeded", {
                    "user_id": user_id,
                    "endpoint": endpoint,
                    "method": method
                })
                return self.json_message("Too Many Requests", status_code=429)

            # 6. SECURITY: Check cache for GET requests
            if method == "GET" and SECURITY_CONFIG["cache_enabled"]:
                cache_key = f"{endpoint}_{self._get_cache_key(request)}"
                cached_response = await self._get_cached_response(cache_key, endpoint_config.get("cache_ttl", SECURITY_CONFIG["cache_ttl"]))
                if cached_response:
                    await self._log_request("cache_hit", user_id, endpoint, method, time.time() - start_time)
                    return self.json(cached_response)

            # 7. SECURITY: Validate request size
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > SECURITY_CONFIG["max_request_size"]:
                await self._log_security_event("request_too_large", {
                    "user_id": user_id,
                    "size": content_length,
                    "max_size": SECURITY_CONFIG["max_request_size"]
                })
                return self.json_message("Request too large", status_code=413)

            # 8. SECURITY: Get Supervisor token
            supervisor_token = os.getenv("SUPERVISOR_TOKEN")
            if not supervisor_token:
                _LOGGER.error("SUPERVISOR_TOKEN not available in environment")
                return self.json_message("Internal error", status_code=500)

            # 9. SECURITY: Prepare and validate request to Supervisor
            supervisor_url = f"{SUPERVISOR_BASE_URL}{endpoint_config['path']}"
            
            # Validate and sanitize query parameters
            query_params = await self._validate_parameters(dict(request.query), endpoint_config.get("allowed_params", []))
            
            # Prepare headers with security considerations
            headers = await self._prepare_secure_headers(request, supervisor_token)

            # 10. SECURITY: Validate request body for POST/PUT requests
            body = None
            if method in ["POST", "PUT"]:
                body = await self._validate_request_body(request)

            # 11. Make request to Supervisor
            session = async_get_clientsession(self.hass)
            
            async with session.request(
                method, 
                supervisor_url, 
                headers=headers, 
                params=query_params,
                json=body if isinstance(body, dict) else None,
                data=body if not isinstance(body, dict) else None
            ) as resp:
                response_text = await resp.text()
                
                if resp.status != 200:
                    await self._log_security_event("supervisor_error", {
                        "user_id": user_id,
                        "endpoint": endpoint,
                        "method": method,
                        "status": resp.status,
                        "response": response_text[:200]  # Limit logged response
                    })
                    return self.json_message(
                        f"Failed to fetch supervisor data: {resp.status}", 
                        status_code=resp.status
                    )

                # 12. SECURITY: Parse and validate response
                try:
                    data = await resp.json()
                except:
                    data = {"data": response_text}

                # 13. SECURITY: Sanitize response
                if SANITIZE_RESPONSE:
                    data = self._sanitize_response(endpoint, data)

                # 14. SECURITY: Cache successful GET responses
                if method == "GET" and SECURITY_CONFIG["cache_enabled"]:
                    cache_key = f"{endpoint}_{self._get_cache_key(request)}"
                    await self._cache_response(cache_key, data, endpoint_config.get("cache_ttl", SECURITY_CONFIG["cache_ttl"]))

                # 15. Log successful request
                await self._log_request("success", user_id, endpoint, method, time.time() - start_time)

                return self.json(data)

        except Exception as e:
            await self._log_security_event("unexpected_error", {
                "user_id": user_id,
                "endpoint": endpoint,
                "method": method,
                "error": str(e)
            })
            _LOGGER.exception(f"Error in AdminPanelHelperView for endpoint {endpoint}")
            return self.json_message("Internal Server Error", status_code=500)

    async def _verify_request_signature(self, request) -> bool:
        """Verify HMAC-based request signature for additional security."""
        try:
            signature = request.headers.get("x-signature")
            timestamp = request.headers.get("x-timestamp")
            
            if not signature or not timestamp:
                return False
            
            # Check timestamp to prevent replay attacks
            current_time = int(time.time())
            if abs(current_time - int(timestamp)) > SECURITY_CONFIG["signature_timeout"]:
                return False
            
            # Get secret key from Home Assistant data
            secret_key = self.hass.data[DOMAIN].get("secret_key")
            if not secret_key:
                return False
            
            # Create expected signature
            message = f"{timestamp}:{request.path}:{request.method}"
            expected_signature = hmac.new(
                secret_key.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception as e:
            _LOGGER.warning(f"Error verifying request signature: {e}")
            return False

    async def _check_rate_limit(self, user_id: str) -> bool:
        """Check rate limiting with persistent storage."""
        try:
            # Get rate limit data from Home Assistant storage
            storage_key = f"admin_panel_helper_rate_limits_{user_id}"
            stored_data = await self.hass.storage.async_get(storage_key)
            
            now = datetime.utcnow()
            request_times = stored_data.get("requests", []) if stored_data else []
            
            # Clean old requests
            request_times = [
                datetime.fromisoformat(t) for t in request_times 
                if now - datetime.fromisoformat(t) < RATE_PERIOD
            ]
            
            # Check if limit exceeded
            if len(request_times) >= RATE_LIMIT:
                return False
            
            # Add current request
            request_times.append(now)
            
            # Store updated data
            await self.hass.storage.async_set(storage_key, {
                "requests": [t.isoformat() for t in request_times],
                "last_updated": now.isoformat()
            })
            
            return True
            
        except Exception as e:
            _LOGGER.warning(f"Error checking rate limit: {e}")
            return True  # Allow request if rate limiting fails

    async def _validate_parameters(self, params: Dict[str, str], allowed_params: List[str]) -> Dict[str, str]:
        """Validate and sanitize query parameters."""
        if not allowed_params:
            return {}
        
        validated_params = {}
        for key, value in params.items():
            if key in allowed_params:
                # Basic sanitization - remove any potentially dangerous characters
                sanitized_value = str(value).replace("'", "").replace('"', "").replace(";", "")
                validated_params[key] = sanitized_value
        
        return validated_params

    async def _prepare_secure_headers(self, request, supervisor_token: str) -> Dict[str, str]:
        """Prepare secure headers for Supervisor request."""
        headers = {
            "Authorization": f"Bearer {supervisor_token}",
            "Content-Type": "application/json",
            "User-Agent": "HomeAssistant-AdminPanelHelper/1.0"
        }
        
        # Forward only safe headers
        safe_headers = ["Accept", "Accept-Language"]
        for header in safe_headers:
            if header in request.headers:
                headers[header] = request.headers[header]
        
        return headers

    async def _validate_request_body(self, request) -> Optional[Dict[str, Any]]:
        """Validate and sanitize request body."""
        try:
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                body = await request.json()
                if not isinstance(body, dict):
                    raise ValueError("Request body must be JSON object")
                return body
            else:
                # For non-JSON requests, return None
                return None
        except Exception as e:
            _LOGGER.warning(f"Invalid request body: {e}")
            return None

    async def _get_cached_response(self, cache_key: str, ttl: int) -> Optional[Dict[str, Any]]:
        """Get cached response if available and not expired."""
        try:
            if cache_key in _response_cache:
                timestamp = _cache_timestamps.get(cache_key, 0)
                if time.time() - timestamp < ttl:
                    return _response_cache[cache_key]
                else:
                    # Remove expired cache entry
                    del _response_cache[cache_key]
                    del _cache_timestamps[cache_key]
            return None
        except Exception as e:
            _LOGGER.warning(f"Error getting cached response: {e}")
            return None

    async def _cache_response(self, cache_key: str, data: Dict[str, Any], ttl: int):
        """Cache response data."""
        try:
            _response_cache[cache_key] = data
            _cache_timestamps[cache_key] = time.time()
            
            # Clean up old cache entries
            current_time = time.time()
            expired_keys = [
                key for key, timestamp in _cache_timestamps.items()
                if current_time - timestamp > ttl
            ]
            for key in expired_keys:
                del _response_cache[key]
                del _cache_timestamps[key]
                
        except Exception as e:
            _LOGGER.warning(f"Error caching response: {e}")

    def _get_cache_key(self, request) -> str:
        """Generate cache key based on request parameters."""
        params = dict(request.query)
        return hashlib.md5(json.dumps(params, sort_keys=True).encode()).hexdigest()

    async def _log_request(self, status: str, user_id: str, endpoint: str, method: str, duration: float):
        """Log successful requests for monitoring."""
        _LOGGER.info(
            f"Request {status}: {method} {endpoint} by user {user_id} "
            f"completed in {duration:.3f}s"
        )

    async def _log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security events for monitoring and alerting."""
        _LOGGER.warning(
            f"Security event {event_type}: {json.dumps(details, default=str)}"
        )

    def _sanitize_response(self, endpoint: str, data: dict) -> dict:
        """Sanitize response data to remove sensitive information."""
        if endpoint == "addons":
            # Sanitize addons response
            safe_data = []
            for addon in data.get("data", {}).get("addons", []):
                safe_data.append({
                    "slug": addon.get("slug"),
                    "name": addon.get("name"),
                    "version": addon.get("version"),
                    "state": addon.get("state"),
                    "icon": addon.get("icon"),
                    "description": addon.get("description"),
                    "repository": addon.get("repository"),
                    "installed": addon.get("installed"),
                    "update_available": addon.get("update_available")
                })
            return {"addons": safe_data}
        
        # For future endpoints, add sanitization logic here
        # elif endpoint == "snapshots":
        #     # Sanitize snapshots response
        #     pass
        
        return data


def register_views(hass: HomeAssistant):
    """Register all API views with Home Assistant."""
    hass.http.register_view(AdminPanelHelperView(hass))
