from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.config_entries import ConfigEntry
from .const import DOMAIN, CONF_API_KEY
import uuid

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN]["api_key"] = entry.data[CONF_API_KEY]

    async def regenerate_api_key_service(call: ServiceCall):
        new_key = str(uuid.uuid4())
        hass.data[DOMAIN]["api_key"] = new_key
        data = dict(entry.data)
        data[CONF_API_KEY] = new_key
        hass.config_entries.async_update_entry(entry, data=data)
        _LOGGER.warning(f"[admin_panel_helper] API key regenerated: {new_key}")

    hass.services.async_register(DOMAIN, "regenerate_api_key", regenerate_api_key_service)

    from .api import AdminPanelHelperView
    hass.http.register_view(AdminPanelHelperView(hass))
    return True
