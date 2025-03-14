import os
import json
import requests
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware

SUPERVISOR_API_URL = "http://supervisor"
SUPERVISOR_TOKEN = os.getenv("SUPERVISOR_TOKEN")

# Load API Key from Home Assistant options.json
with open("/data/options.json") as f:
    options = json.load(f)
VALID_API_KEY = options.get("api_key", "your-secret-api-key")

app = FastAPI()

# Enable CORS to allow Home Assistant to access the API externally
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HEADERS = {
    "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
    "Content-Type": "application/json"
}

# Authentication function
def validate_auth(request: Request):
    auth_header = request.headers.get("authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization Header")

    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        if token == VALID_API_KEY:
            return True

    raise HTTPException(status_code=403, detail="Invalid API Key")

# API Endpoint to test connection
@app.get("/api/myaddon")
async def my_api_endpoint(request: Request):
    validate_auth(request)
    return {"message": "Hello from Home Assistant Add-on!"}

# Supervisor Info Endpoint
@app.get("/api/supervisor/info")
async def get_supervisor_info(request: Request):
    validate_auth(request)
    response = requests.get(f"{SUPERVISOR_API_URL}/info", headers=HEADERS)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

# List Installed Add-ons
@app.get("/api/supervisor/addons")
async def list_addons(request: Request):
    validate_auth(request)
    response = requests.get(f"{SUPERVISOR_API_URL}/addons", headers=HEADERS)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

# Start Uvicorn server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
