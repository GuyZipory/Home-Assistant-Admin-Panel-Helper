import os
import requests
import json
from fastapi import FastAPI, HTTPException, Request, Header,Query
from fastapi.middleware.cors import CORSMiddleware

SUPERVISOR_API_URL = "http://supervisor"
HASSIO_TOKEN = os.getenv("HASSIO_TOKEN")

with open("/data/options.json") as f:
    options = json.load(f)
VALID_API_KEY = options.get("api_key", "your-secret-api-key")

app = FastAPI()





# ✅ Set CORS to allow requests from Home Assistant’s frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow Home Assistant UI and external sources
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers, including Authorization
)

HEADERS = {
    "Authorization": f"Bearer {HASSIO_TOKEN}",
    "Content-Type": "application/json"
}

def validate_auth(auth_header: str = Header(None)):
    """Check if the request contains a valid authentication token."""
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization Header")

    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        if token == VALID_API_KEY:
            return True
        else:
            raise HTTPException(status_code=403, detail="Invalid API Key")

    raise HTTPException(status_code=401, detail="Invalid Authorization Header")

@app.get("/info")
def get_supervisor_info(auth: bool = Query(default=True)):
    """Get general info about the Home Assistant Supervisor"""
    response = requests.get(f"{SUPERVISOR_API_URL}/info", headers=HEADERS)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

@app.get("/addons")
def list_addons(auth: bool = Query(default=True)):
    """Get list of installed add-ons"""
    response = requests.get(f"{SUPERVISOR_API_URL}/addons", headers=HEADERS)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

# ✅ More endpoints can be added with the same authentication check

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
