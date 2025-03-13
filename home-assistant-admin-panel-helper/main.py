import os
import requests
import json
from fastapi import FastAPI, HTTPException, Header,Depends
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
    print(" validate_auth() was called")  # Debugging print

    if not auth_header:
        print("Missing Authorization Header")
        raise HTTPException(status_code=401, detail="Missing Authorization Header")

    print(f"🔍 Received Auth Header: {auth_header}")

    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        print(f"Extracted Token: {token}")

        if token == VALID_API_KEY:
            print(" Authentication Successful")
            return True

    print(" Invalid API Key")
    raise HTTPException(status_code=403, detail="Invalid API Key")

@app.get("/isApiUpNoAuth")
def isApiUp():
    return {"status": "up"}

@app.get("/isApiUpWithAuth")
def isApiUpWithAuth(auth: bool = Depends(validate_auth)):
    return {"status": "up"}

@app.get("/info")
def get_supervisor_info(auth: bool = Depends(validate_auth)):
    """Get general info about the Home Assistant Supervisor"""
    response = requests.get(f"{SUPERVISOR_API_URL}/info", headers=HEADERS)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

@app.get("/addons")
def list_addons(auth: bool = Depends(validate_auth)):
    """Get list of installed add-ons"""
    response = requests.get(f"{SUPERVISOR_API_URL}/addons", headers=HEADERS)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return response.json()

# ✅ More endpoints can be added with the same authentication check

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
