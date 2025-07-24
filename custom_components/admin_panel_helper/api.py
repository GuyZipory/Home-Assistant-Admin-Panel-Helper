import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta

from homeassistant.components.http import HomeAssistantView
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

SUPERVISOR_URL = "http://supervisor/addons"

# In-memory rate limit tracker
_request_log = defaultdict(list)
RATE_LIMIT = 5  # Max requests per period
RATE_PERIOD = timedelta(minutes=1)  # Time window
SANITIZE_RESPONSE = True  # Strip sensitive data


class AdminPanelHelperView(HomeAssistantView):
    url = "/api/admin_panel_helper/addons"
    name = "api:admin_panel_helper_addons"
    requires_auth = True

    def __init__(self, hass):
        self.hass = hass

    async def get(self, request):
        try:
            # Validate API key
            expected_key = self.hass.data[DOMAIN].get("api_key")
            provided_key = request.headers.get("x_api_key")

            if not expected_key or expected_key != provided_key:
                _LOGGER.warning("API Key invalid or missing")
                return self.json_message("Forbidden", status_code=403)

            # Ensure user is admin
            user = request.get("hass_user")
            if not user or not user.is_admin:
                _LOGGER.warning("Non-admin user attempted access")
                return self.json_message("Admin access required", status_code=403)

            # Rate limiting
            user_id = user.id
            now = datetime.utcnow()
            _request_log[user_id] = [
                t for t in _request_log[user_id] if now - t < RATE_PERIOD
            ]
            if len(_request_log[user_id]) >= RATE_LIMIT:
                _LOGGER.warning(f"Rate limit exceeded for user: {user_id}")
                return self.json_message("Too Many Requests", status_code=429)
            _request_log[user_id].append(now)

            # Supervisor API call
            supervisor_token = os.getenv("SUPERVISOR_TOKEN")
            if not supervisor_token:
                _LOGGER.error("SUPERVISOR_TOKEN not available in environment")
                return self.json_message("Internal error", status_code=500)

            session = async_get_clientsession(self.hass)
            headers = {
                "Authorization": f"Bearer {supervisor_token}"
            }

            async with session.get(SUPERVISOR_URL, headers=headers) as resp:
                text = await resp.text()

                if resp.status != 200:
                    _LOGGER.warning(f"Supervisor call failed: {resp.status} {text}")
                    return self.json_message("Failed to fetch supervisor data", status_code=resp.status)

                data = await resp.json()

                if SANITIZE_RESPONSE:
                    safe_data = []
                    for addon in data.get("data", {}).get("addons", []):
                        safe_data.append({
                            "slug": addon.get("slug"),
                            "name": addon.get("name"),
                            "version": addon.get("version"),
                            "state": addon.get("state")
                        })
                    return self.json({"addons": safe_data})

                return self.json(data)

        except Exception as e:
            _LOGGER.exception("Error in AdminPanelHelperView")
            return self.json_message("Internal Server Error", status_code=500)
