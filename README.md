# Home Assistant Admin Panel Helper

This custom integration exposes secure, API-key-protected access to select Home Assistant Supervisor APIs.

## Features

- Proxy to `/api/supervisor/addons`
- `x_api_key` + admin-only secured
- Key regeneration via service or UI

## Installation via HACS

1. Add this repo as a **custom repository** (type: Integration)
2. Install the integration
3. Restart Home Assistant
4. Go to **Settings → Devices & Services → Add Integration**
5. Search for **Home Assistant Admin Panel Helper**
