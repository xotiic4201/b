import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import secrets
import json
import jwt
import asyncio
import bcrypt
import httpx
import time
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="ANALCONTROL API",
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

class UserUpdate(BaseModel):
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

class ClientRegister(BaseModel):
    client_id: str = Field(..., example="client-001")
    name: str = Field(..., example="Office Computer")
    ip_address: str = Field(..., example="192.168.1.100")
    os_info: str = Field(default="Unknown", example="Windows 11")

class CommandRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    command: str = Field(..., example="system_info")
    parameters: Dict[str, Any] = Field(default_factory=dict)

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
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": "cyber-monitor-api"
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
            options={"verify_exp": True, "verify_iss": False}  # Changed to False for flexibility
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

# ========== DATABASE IN-MEMORY STORAGE (Fallback if no Supabase) ==========
# This will store data in memory if Supabase is not configured
class MemoryStorage:
    def __init__(self):
        self.users = {}
        self.clients = {}
        self.commands = []
        self.logs = []
        self.init_default_users()
    
    def init_default_users(self):
        # Default admin accounts
        default_admins = [
            {"id": str(uuid.uuid4()), "email": "xotiic", "password": "40671Mps19*", "is_admin": True, "is_active": True, "created_at": datetime.utcnow().isoformat(), "last_login": None},
            {"id": str(uuid.uuid4()), "email": "admin", "password": "admin123", "is_admin": True, "is_active": True, "created_at": datetime.utcnow().isoformat(), "last_login": None},
            {"id": str(uuid.uuid4()), "email": "kizer", "password": "kidraper67", "is_admin": True, "is_active": True, "created_at": datetime.utcnow().isoformat(), "last_login": None},
            {"id": str(uuid.uuid4()), "email": "nathan", "password": "femboy67", "is_admin": True, "is_active": True, "created_at": datetime.utcnow().isoformat(), "last_login": None}
        ]
        
        for user in default_admins:
            self.users[user["email"]] = user

# Initialize memory storage
memory_storage = MemoryStorage()

# ========== SUPABASE CLIENT ==========
class SupabaseClient:
    def __init__(self):
        self.url = SUPABASE_URL.rstrip('/')
        self.key = SUPABASE_KEY
        self.is_available = bool(SUPABASE_URL and SUPABASE_KEY)
        
        if self.is_available:
            self.client = httpx.AsyncClient(
                headers={
                    "apikey": self.key,
                    "Authorization": f"Bearer {self.key}",
                    "Content-Type": "application/json",
                    "Prefer": "return=representation"
                },
                timeout=30.0
            )
            logger.info("✅ Supabase client initialized")
        else:
            logger.warning("⚠️ Supabase not configured, using in-memory storage")
            self.client = None
    
    async def query(self, table: str, method: str = "GET", data: dict = None, params: dict = None):
        """Make a request to Supabase REST API"""
        if not self.is_available:
            # Fallback to memory storage
            return await self._memory_query(table, method, data, params)
        
        try:
            url = f"{self.url}/rest/v1/{table}"
            
            if method == "GET":
                response = await self.client.get(url, params=params)
            elif method == "POST":
                response = await self.client.post(url, json=data)
            elif method == "PUT":
                response = await self.client.put(url, json=data, params=params)
            elif method == "PATCH":
                response = await self.client.patch(url, json=data, params=params)
            elif method == "DELETE":
                response = await self.client.delete(url, params=params)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            
            if method == "GET" and response.status_code == 200:
                return response.json()
            elif method in ["POST", "PUT", "PATCH"] and response.status_code in [200, 201]:
                return response.json()
            elif method == "DELETE" and response.status_code == 204:
                return {"success": True}
            
            return None
            
        except Exception as e:
            logger.error(f"Supabase query error: {e}")
            # Fallback to memory storage
            return await self._memory_query(table, method, data, params)
    
    async def _memory_query(self, table: str, method: str = "GET", data: dict = None, params: dict = None):
        """Fallback to in-memory storage"""
        try:
            if table == "users":
                if method == "GET":
                    if params and "email" in params:
                        email = params["email"].replace("eq.", "")
                        user = memory_storage.users.get(email)
                        return [user] if user else []
                    else:
                        return list(memory_storage.users.values())
                elif method == "POST":
                    user_id = str(uuid.uuid4())
                    data["id"] = user_id
                    data["created_at"] = datetime.utcnow().isoformat()
                    memory_storage.users[data["email"]] = data
                    return [data]
                elif method == "PATCH":
                    if params and "email" in params:
                        email = params["email"].replace("eq.", "")
                        if email in memory_storage.users:
                            memory_storage.users[email].update(data)
                            return [memory_storage.users[email]]
                    return []
            
            elif table == "clients":
                if method == "GET":
                    return list(memory_storage.clients.values())
                elif method == "POST":
                    client_id = data.get("client_id") or str(uuid.uuid4())
                    data["id"] = str(uuid.uuid4())
                    data["created_at"] = datetime.utcnow().isoformat()
                    memory_storage.clients[client_id] = data
                    return [data]
                elif method == "PATCH":
                    if params and "client_id" in params:
                        client_id = params["client_id"].replace("eq.", "")
                        if client_id in memory_storage.clients:
                            memory_storage.clients[client_id].update(data)
                            return [memory_storage.clients[client_id]]
                    return []
            
            elif table == "commands":
                if method == "GET":
                    return memory_storage.commands[-50:] if memory_storage.commands else []
                elif method == "POST":
                    command_id = str(uuid.uuid4())
                    data["id"] = command_id
                    data["created_at"] = datetime.utcnow().isoformat()
                    memory_storage.commands.append(data)
                    return [data]
                elif method == "PATCH":
                    if params and "id" in params:
                        command_id = params["id"].replace("eq.", "")
                        for cmd in memory_storage.commands:
                            if cmd["id"] == command_id:
                                cmd.update(data)
                                return [cmd]
                    return []
            
            elif table == "logs":
                if method == "GET":
                    return memory_storage.logs[-100:] if memory_storage.logs else []
                elif method == "POST":
                    log_id = str(uuid.uuid4())
                    data["id"] = log_id
                    data["created_at"] = datetime.utcnow().isoformat()
                    memory_storage.logs.append(data)
                    return [data]
            
            return []
        except Exception as e:
            logger.error(f"Memory query error: {e}")
            return []

# Initialize Supabase client
supabase = SupabaseClient()

# ========== API ROUTES ==========
@app.post("/api/create-account", response_model=dict)
async def create_account(data: UserCreate):
    """Create a new user account"""
    try:
        # Check if passwords match
        if data.password != data.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        
        # Check if user already exists
        existing_users = await supabase.query("users", params={
            "email": f"eq.{data.email}"
        })
        
        if existing_users:
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Create user
        result = await supabase.query("users", method="POST", data={
            "email": data.email,
            "password_hash": data.password,  # Plain text for simplicity
            "is_admin": data.is_admin,
            "is_active": True,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        })
        
        logger.info(f"✅ Account created for: {data.email}")
        
        return {
            "success": True,
            "message": "Account created successfully",
            "email": data.email,
            "is_admin": data.is_admin
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create account error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/login", response_model=dict)
async def login(data: LoginRequest):
    """Login endpoint"""
    try:
        logger.info(f"Login attempt for user: {data.email}")
        
        # Get user from database
        users = await supabase.query("users", params={
            "email": f"eq.{data.email}"
        })
        
        if not users:
            logger.warning(f"User not found: {data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = users[0]
        
        # Check if user is active
        if not user.get("is_active", True):
            logger.warning(f"User account inactive: {data.email}")
            raise HTTPException(status_code=401, detail="Account is inactive")
        
        # Simple password check
        if user.get("password_hash") != data.password:
            logger.warning(f"Password verification failed for user: {data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        logger.info(f"✅ User authenticated: {user.get('email')}")
        
        # Create JWT token
        token_data = {
            "sub": user.get("email", ""),
            "email": user.get("email", ""),
            "is_admin": user.get("is_admin", False),
            "user_id": str(user.get("id", ""))
        }
        access_token = create_jwt_token(token_data)
        
        # Update last login
        try:
            await supabase.query("users", method="PATCH", data={
                "last_login": datetime.utcnow().isoformat()
            }, params={"email": f"eq.{user.get('email')}"})
        except Exception as e:
            logger.error(f"Failed to update last login: {e}")
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "email": user.get("email", ""),
                "is_admin": user.get("is_admin", False),
                "user_id": str(user.get("id", ""))
            },
            "expires_in": 86400
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/users", response_model=dict)
async def get_users(user: dict = Depends(authenticate_user)):
    """Get all users (admin only)"""
    try:
        # Check if user is admin
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Get users
        users = await supabase.query("users", params={
            "order": "created_at.desc"
        })
        
        return {
            "success": True,
            "users": users or []
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get users error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.put("/api/users/{user_id}/status", response_model=dict)
async def update_user_status(user_id: str, data: UserUpdate, user: dict = Depends(authenticate_user)):
    """Update user status (admin only)"""
    try:
        # Check if user is admin
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Update user
        update_data = {}
        if data.is_active is not None:
            update_data["is_active"] = data.is_active
        
        await supabase.query("users", method="PATCH", data=update_data, params={
            "id": f"eq.{user_id}"
        })
        
        return {
            "success": True,
            "message": "User status updated"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update user status error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.put("/api/users/{user_id}/admin", response_model=dict)
async def update_user_admin(user_id: str, data: UserUpdate, user: dict = Depends(authenticate_user)):
    """Update user admin status (admin only)"""
    try:
        # Check if user is admin
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Update user
        update_data = {}
        if data.is_admin is not None:
            update_data["is_admin"] = data.is_admin
        
        await supabase.query("users", method="PATCH", data=update_data, params={
            "id": f"eq.{user_id}"
        })
        
        return {
            "success": True,
            "message": "User admin status updated"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update user admin error: {e}")
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
        
        # Check if client exists
        existing_clients = await supabase.query("clients", params={
            "client_id": f"eq.{data.client_id}"
        })
        
        client_data = {
            "client_id": data.client_id,
            "name": data.name,
            "ip_address": data.ip_address,
            "os_info": data.os_info,
            "last_seen": datetime.utcnow().isoformat(),
            "online": True,
            "registered_at": datetime.utcnow().isoformat()
        }
        
        if existing_clients:
            # Update existing client
            await supabase.query("clients", method="PATCH", data=client_data, params={
                "client_id": f"eq.{data.client_id}"
            })
            action = "updated"
        else:
            # Create new client
            await supabase.query("clients", method="POST", data=client_data)
            action = "registered"
        
        # Add log entry
        try:
            await supabase.query("logs", method="POST", data={
                "client_id": data.client_id,
                "log_type": "info",
                "message": f"Client {action}: {data.name} ({data.client_id})",
                "created_at": datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.error(f"Log insertion error: {e}")
        
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
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=1000),
    online_only: bool = Query(False),
    search: Optional[str] = Query(None)
):
    """Get all clients from database"""
    try:
        # Get clients
        clients = await supabase.query("clients")
        
        if not clients:
            clients = []
        
        # Filter if needed
        if online_only:
            clients = [c for c in clients if c.get("online")]
        
        if search:
            search_lower = search.lower()
            clients = [c for c in clients if 
                      search_lower in c.get("client_id", "").lower() or
                      search_lower in c.get("name", "").lower() or
                      search_lower in c.get("ip_address", "").lower()]
        
        # Sort by last seen
        clients.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
        
        # Mark clients as online if they have active WebSocket connections
        for client in clients:
            client["ws_online"] = client.get("client_id") in manager.client_connections
        
        # Apply pagination
        total = len(clients)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_clients = clients[start_idx:end_idx]
        
        return {
            "success": True,
            "clients": paginated_clients,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if limit > 0 else 0
            }
        }
    except Exception as e:
        logger.error(f"Get clients error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/client/{client_id}", response_model=dict)
async def get_client(client_id: str, user: dict = Depends(authenticate_user)):
    """Get specific client details"""
    try:
        # Get client
        clients = await supabase.query("clients", params={
            "client_id": f"eq.{client_id}"
        })
        
        if not clients:
            raise HTTPException(status_code=404, detail="Client not found")
        
        client = clients[0]
        client["ws_online"] = client_id in manager.client_connections
        
        # Get recent logs for this client
        logs = await supabase.query("logs", params={
            "client_id": f"eq.{client_id}"
        })
        
        if logs:
            logs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            logs = logs[:20]
        
        return {
            "success": True,
            "client": client,
            "recent_logs": logs or [],
            "is_online": client_id in manager.client_connections
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get client error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/command", response_model=dict)
async def send_command(data: CommandRequest, user: dict = Depends(authenticate_user)):
    """Send command to client"""
    try:
        # Create command record
        result = await supabase.query("commands", method="POST", data={
            "client_id": data.client_id,
            "command": data.command,
            "parameters": json.dumps(data.parameters) if data.parameters else None,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "user_email": user.get("email", "unknown")
        })
        
        command_id = result[0].get("id") if result else str(uuid.uuid4())
        
        # Send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": str(command_id),
            "command": data.command,
            "parameters": data.parameters,
            "timestamp": datetime.utcnow().isoformat(),
            "from_user": user.get("email", "unknown")
        })
        
        if not sent:
            # Update command status if WebSocket failed
            await supabase.query("commands", method="PATCH", data={
                "status": "failed",
                "error": "Client not connected"
            }, params={"id": f"eq.{command_id}"})
        
        return {
            "success": True,
            "command_id": str(command_id),
            "sent_via_websocket": sent,
            "client_id": data.client_id,
            "message": "Command queued for execution"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send command error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/commands", response_model=dict)
async def get_commands(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=1000)
):
    """Get recent commands"""
    try:
        # Get all commands
        commands = await supabase.query("commands")
        
        if not commands:
            commands = []
        
        # Apply filters
        if client_id:
            commands = [c for c in commands if c.get("client_id") == client_id]
        
        if status:
            commands = [c for c in commands if c.get("status") == status]
        
        # Sort by date
        commands.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        # Apply pagination
        total = len(commands)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_commands = commands[start_idx:end_idx]
        
        return {
            "success": True,
            "commands": paginated_commands,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if limit > 0 else 0
            }
        }
    except Exception as e:
        logger.error(f"Get commands error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/logs", response_model=dict)
async def get_logs(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    log_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get system logs"""
    try:
        # Get all logs
        logs = await supabase.query("logs")
        
        if not logs:
            logs = []
        
        # Apply filters
        if client_id:
            logs = [l for l in logs if l.get("client_id") == client_id]
        
        if log_type:
            logs = [l for l in logs if l.get("log_type") == log_type]
        
        # Sort by date
        logs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        # Apply pagination
        total = len(logs)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_logs = logs[start_idx:end_idx]
        
        return {
            "success": True,
            "logs": paginated_logs,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if limit > 0 else 0
            }
        }
    except Exception as e:
        logger.error(f"Get logs error: {e}")
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
            "database": "in-memory" if not supabase.is_available else "supabase",
            "active_clients": len(manager.client_connections),
            "active_admins": len(manager.admin_connections),
        }
        
        return health_status
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }

@app.get("/", response_model=dict)
async def root():
    """Root endpoint with API info"""
    return {
        "message": "🚀 ANALCONTROL API",
        "version": "3.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "documentation": "/docs",
        "websocket_endpoints": {
            "admin": "/ws/admin",
            "client": "/ws/client/{client_id}"
        }
    }

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
                logger.info(f"Admin WebSocket message: {data}")
                
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
        
        # Update client status
        try:
            await supabase.query("clients", method="PATCH", data={
                "online": True,
                "last_seen": datetime.utcnow().isoformat()
            }, params={"client_id": f"eq.{client_id}"})
        except Exception as e:
            logger.error(f"Client status update error: {e}")
        
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
                    try:
                        await supabase.query("clients", method="PATCH", data={
                            "last_seen": datetime.utcnow().isoformat(),
                            "online": True
                        }, params={"client_id": f"eq.{client_id}"})
                        
                        # Send heartbeat response
                        await websocket.send_json({
                            "type": "heartbeat_response",
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    except Exception as e:
                        logger.error(f"Heartbeat update error: {e}")
                    
                elif data_type == "command_result":
                    # Update command status
                    try:
                        await supabase.query("commands", method="PATCH", data={
                            "status": "completed",
                            "result": json.dumps(data.get("result")) if data.get("result") else None,
                            "completed_at": datetime.utcnow().isoformat(),
                            "error": data.get("error", "")
                        }, params={"id": f"eq.{data.get('command_id')}"})
                    except Exception as e:
                        logger.error(f"Command result update error: {e}")
                    
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
                    
                elif data_type == "log":
                    # Store log
                    try:
                        await supabase.query("logs", method="POST", data={
                            "client_id": client_id,
                            "log_type": data.get("log_type", "info"),
                            "message": data.get("message", ""),
                            "created_at": datetime.utcnow().isoformat()
                        })
                    except Exception as e:
                        logger.error(f"Log storage error: {e}")
                    
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
        try:
            await supabase.query("clients", method="PATCH", data={
                "online": False
            }, params={"client_id": f"eq.{client_id}"})
        except Exception as e:
            logger.error(f"Client offline update error: {e}")
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Client WebSocket error: {e}")
        # Mark client as offline
        try:
            await supabase.query("clients", method="PATCH", data={
                "online": False
            }, params={"client_id": f"eq.{client_id}"})
        except Exception as e:
            logger.error(f"Client offline update error: {e}")
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

# ========== APPLICATION STARTUP ==========
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info(f"🚀 Starting ANALCONTROL API v3.0")
    logger.info(f"📡 Port: {PORT}")
    
    if supabase.is_available:
        logger.info(f"🔗 Supabase URL: {SUPABASE_URL[:30]}...")  # Log first 30 chars for security
    else:
        logger.info("💾 Using in-memory storage (no Supabase configured)")
    
    # Test database connection
    try:
        # Check if admin accounts exist
        admin_users = await supabase.query("users")
        
        if not admin_users or len(admin_users) == 0:
            logger.info("⚠️ No admin users found, default accounts available in memory")
        
        logger.info("✅ Database connection established")
        
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        logger.info("💾 Falling back to in-memory storage")
    
    logger.info(f"🔗 WebSocket endpoints:")
    logger.info(f"   • Admin: /ws/admin")
    logger.info(f"   • Client: /ws/client/{{client_id}}")
    logger.info(f"📚 Documentation: /docs")
    logger.info("✅ Application startup complete")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    if supabase.client:
        await supabase.client.aclose()

# ========== SIMPLE TEST ENDPOINTS ==========
@app.get("/api/test", response_model=dict)
async def test_endpoint():
    """Simple test endpoint"""
    return {
        "success": True,
        "message": "API is working!",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0"
    }

@app.post("/api/test-login", response_model=dict)
async def test_login(data: LoginRequest):
    """Test login endpoint that always works"""
    logger.info(f"Test login for: {data.email}")
    
    # Create a dummy user
    user_data = {
        "email": data.email,
        "is_admin": True,
        "user_id": str(uuid.uuid4())
    }
    
    # Create JWT token
    token_data = {
        "sub": data.email,
        "email": data.email,
        "is_admin": True,
        "user_id": user_data["user_id"]
    }
    access_token = create_jwt_token(token_data)
    
    return {
        "success": True,
        "token": access_token,
        "user": user_data,
        "expires_in": 86400
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True
    )
