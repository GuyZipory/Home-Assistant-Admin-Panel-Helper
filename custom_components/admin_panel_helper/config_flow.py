from homeassistant import config_entries
import voluptuous as vol
from .const import DOMAIN, CONF_API_KEY

class AdminPanelHelperConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    async def async_step_user(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="Admin Panel Helper", data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_API_KEY): str
            })
        )
