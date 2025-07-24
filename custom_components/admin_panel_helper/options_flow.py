from homeassistant import config_entries
import uuid
from .const import DOMAIN, CONF_API_KEY

class AdminPanelHelperOptionsFlowHandler(config_entries.OptionsFlow):
    def __init__(self, config_entry):
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            new_key = str(uuid.uuid4())
            data = dict(self.config_entry.data)
            data[CONF_API_KEY] = new_key
            self.hass.config_entries.async_update_entry(self.config_entry, data=data)
            return self.async_create_entry(
                title="",
                data={}
            )

        return self.async_show_form(
            step_id="init",
            description="Press 'Submit' to regenerate a new API key.",
            data_schema=None
        )
