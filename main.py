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

# ========== DATABASE (IN-MEMORY) ==========
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
    
    def create_session(self, user_id: str, session_data: dict):
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "data": session_data
        }
        return session_id
    
    def get_session(self, session_id: str):
        return self.sessions.get(session_id)
    
    def delete_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]

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
            db.clients[client_id]["last_seen"] = datetime.utcnow().isoformat()
        
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
    """Login endpoint"""
    try:
        logger.info(f"Login attempt for user: {data.email}")
        
        # Get user from database
        user = db.get_user_by_email(data.email)
        
        if not user:
            logger.warning(f"User not found: {data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if user is active
        if not user.get("is_active", True):
            logger.warning(f"User account inactive: {data.email}")
            raise HTTPException(status_code=401, detail="Account is inactive")
        
        # Check password
        if user.get("password") != data.password:
            logger.warning(f"Password verification failed for user: {data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        logger.info(f"✅ User authenticated: {user.get('email')}")
        
        # Create JWT token
        token_data = {
            "sub": user.get("email", ""),
            "email": user.get("email", ""),
            "is_admin": user.get("is_admin", False),
            "user_id": str(user.get("id", "")),
            "theme": user.get("theme", "cyberpunk")  # Include theme in token
        }
        access_token = create_jwt_token(token_data)
        
        # Update last login
        db.update_user_last_login(data.email)
        
        # Create session
        session_id = db.create_session(user["id"], {
            "user_agent": "web",
            "ip": "127.0.0.1",
            "login_time": datetime.utcnow().isoformat()
        })
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "email": user.get("email", ""),
                "is_admin": user.get("is_admin", False),
                "user_id": str(user.get("id", "")),
                "theme": user.get("theme", "cyberpunk")
            },
            "session_id": session_id,
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
        
        # Check if user already exists
        if db.get_user_by_email(data.email):
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Create user
        new_user = {
            "id": str(uuid.uuid4()),
            "email": data.email,
            "password": data.password,
            "is_admin": data.is_admin,
            "is_active": True,
            "theme": "cyberpunk",  # Default theme
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        }
        
        db.users[data.email.lower()] = new_user
        
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

@app.get("/api/users", response_model=dict)
async def get_users(user: dict = Depends(authenticate_user)):
    """Get all users (admin only)"""
    try:
        # Check if user is admin
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Get users (without passwords)
        users = []
        for user_data in db.users.values():
            users.append({
                "id": user_data["id"],
                "email": user_data["email"],
                "is_admin": user_data["is_admin"],
                "is_active": user_data["is_active"],
                "theme": user_data["theme"],
                "created_at": user_data["created_at"],
                "last_login": user_data["last_login"]
            })
        
        return {
            "success": True,
            "users": users
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
        
        # Find user by ID
        target_user = None
        for u in db.users.values():
            if u["id"] == user_id:
                target_user = u
                break
        
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Update user
        if data.is_active is not None:
            target_user["is_active"] = data.is_active
        
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
        
        # Find user by ID
        target_user = None
        for u in db.users.values():
            if u["id"] == user_id:
                target_user = u
                break
        
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Update user
        if data.is_admin is not None:
            target_user["is_admin"] = data.is_admin
        
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
        if data.client_id in db.clients:
            # Update existing client
            db.clients[data.client_id].update({
                "name": data.name,
                "ip_address": data.ip_address,
                "os_info": data.os_info,
                "last_seen": datetime.utcnow().isoformat(),
                "online": True
            })
            action = "updated"
        else:
            # Create new client
            db.clients[data.client_id] = {
                "id": str(uuid.uuid4()),
                "client_id": data.client_id,
                "name": data.name,
                "ip_address": data.ip_address,
                "os_info": data.os_info,
                "last_seen": datetime.utcnow().isoformat(),
                "online": True,
                "registered_at": datetime.utcnow().isoformat()
            }
            action = "registered"
        
        # Add log entry
        db.logs.append({
            "id": str(uuid.uuid4()),
            "client_id": data.client_id,
            "log_type": "info",
            "message": f"Client {action}: {data.name} ({data.client_id})",
            "created_at": datetime.utcnow().isoformat()
        })
        
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
        clients_list = list(db.clients.values())
        
        # Filter if needed
        if online_only:
            clients_list = [c for c in clients_list if c.get("online")]
        
        if search:
            search_lower = search.lower()
            clients_list = [c for c in clients_list if 
                          search_lower in c.get("client_id", "").lower() or
                          search_lower in c.get("name", "").lower() or
                          search_lower in c.get("ip_address", "").lower()]
        
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

@app.get("/api/client/{client_id}", response_model=dict)
async def get_client(client_id: str, user: dict = Depends(authenticate_user)):
    """Get specific client details"""
    try:
        if client_id not in db.clients:
            raise HTTPException(status_code=404, detail="Client not found")
        
        client = db.clients[client_id]
        client["ws_online"] = client_id in manager.client_connections
        
        # Get recent logs for this client
        logs = [l for l in db.logs if l.get("client_id") == client_id]
        logs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        recent_logs = logs[:20]
        
        return {
            "success": True,
            "client": client,
            "recent_logs": recent_logs,
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
        command = {
            "id": str(uuid.uuid4()),
            "client_id": data.client_id,
            "command": data.command,
            "parameters": data.parameters,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "user_email": user.get("email", "unknown")
        }
        
        db.commands.append(command)
        
        # Send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": command["id"],
            "command": data.command,
            "parameters": data.parameters,
            "timestamp": datetime.utcnow().isoformat(),
            "from_user": user.get("email", "unknown")
        })
        
        if not sent:
            # Update command status if WebSocket failed
            command["status"] = "failed"
            command["error"] = "Client not connected"
        
        return {
            "success": True,
            "command_id": command["id"],
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
    status: Optional[str] = Query(None)
):
    """Get recent commands"""
    try:
        # Get all commands
        commands = db.commands.copy()
        
        # Apply filters
        if client_id:
            commands = [c for c in commands if c.get("client_id") == client_id]
        
        if status:
            commands = [c for c in commands if c.get("status") == status]
        
        # Sort by date
        commands.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        return {
            "success": True,
            "commands": commands[:50]  # Return last 50 commands
        }
    except Exception as e:
        logger.error(f"Get commands error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/logs", response_model=dict)
async def get_logs(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    log_type: Optional[str] = Query(None)
):
    """Get system logs"""
    try:
        # Get all logs
        logs = db.logs.copy()
        
        # Apply filters
        if client_id:
            logs = [l for l in logs if l.get("client_id") == client_id]
        
        if log_type:
            logs = [l for l in logs if l.get("log_type") == log_type]
        
        # Sort by date
        logs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        return {
            "success": True,
            "logs": logs[:100]  # Return last 100 logs
        }
    except Exception as e:
        logger.error(f"Get logs error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/stats", response_model=dict)
async def get_stats(user: dict = Depends(authenticate_user)):
    """Get system statistics"""
    try:
        total_clients = len(db.clients)
        online_clients = len([c for c in db.clients.values() if c.get("online")])
        
        pending_commands = len([c for c in db.commands if c.get("status") in ["pending", "running"]])
        total_commands = len(db.commands)
        
        return {
            "success": True,
            "stats": {
                "total_clients": total_clients,
                "online_clients": online_clients,
                "pending_commands": pending_commands,
                "total_commands": total_commands,
                "active_connections": len(manager.client_connections),
                "active_admins": len(manager.admin_connections)
            }
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
            "database": "in-memory",
            "active_clients": len(manager.client_connections),
            "active_admins": len(manager.admin_connections),
            "total_users": len(db.users),
            "total_clients": len(db.clients)
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
                    
                    # Send heartbeat response
                    await websocket.send_json({
                        "type": "heartbeat_response",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif data_type == "command_result":
                    # Update command status
                    command_id = data.get("command_id")
                    for cmd in db.commands:
                        if cmd["id"] == command_id:
                            cmd["status"] = "completed"
                            cmd["result"] = data.get("result")
                            cmd["completed_at"] = datetime.utcnow().isoformat()
                            cmd["error"] = data.get("error", "")
                            break
                    
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
                    
                elif data_type == "log":
                    # Store log
                    db.logs.append({
                        "id": str(uuid.uuid4()),
                        "client_id": client_id,
                        "log_type": data.get("log_type", "info"),
                        "message": data.get("message", ""),
                        "created_at": datetime.utcnow().isoformat()
                    })
                    
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
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Client WebSocket error: {e}")
        # Mark client as offline
        if client_id in db.clients:
            db.clients[client_id]["online"] = False
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
    # Read the frontend HTML from the updated file
    # For now, we'll return a simple message and redirect to the actual frontend
    return JSONResponse({
        "message": "ANALCONTROL API is running",
        "version": "3.0",
        "endpoints": {
            "login": "/api/login",
            "docs": "/docs",
            "health": "/api/health"
        }
    })

# ========== APPLICATION STARTUP ==========
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info(f"🚀 Starting ANALCONTROL API v3.0")
    logger.info(f"📡 Port: {PORT}")
    logger.info(f"🔗 WebSocket endpoints:")
    logger.info(f"   • Admin: /ws/admin")
    logger.info(f"   • Client: /ws/client/{{client_id}}")
    logger.info(f"📚 Documentation: /docs")
    logger.info(f"👤 Default users:")
    logger.info(f"   • xotiic/40671Mps19* (Admin with create account permission)")
    logger.info(f"   • admin/admin123 (Admin)")
    logger.info(f"   • nathan/femboy67 (Admin with femboy theme)")
    logger.info(f"   • kizer/kidraper67 (Admin)")
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
