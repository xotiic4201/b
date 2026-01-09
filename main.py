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
                "online": True,
                "last_seen": datetime.utcnow().isoformat(),
                "registered_at": datetime.utcnow().isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "client_id": "client-002",
                "name": "Office PC",
                "ip_address": "192.168.1.101",
                "os_info": "Windows 11",
                "online": True,
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
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the frontend HTML"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ANALCONTROL | System Monitor</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Exo+2:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            /* ========== DEFAULT CYBERPUNK THEME ========== */
            :root {
                --primary: #8a2be2;
                --primary-dark: #5a189a;
                --primary-light: #9d4edd;
                --secondary: #0a0a0a;
                --secondary-dark: #000000;
                --secondary-light: #1a1a1a;
                --accent: #00ffff;
                --accent-dark: #00b3b3;
                --danger: #ff2a6d;
                --warning: #ffd166;
                --success: #06d6a0;
                --info: #118ab2;
                
                --background: #000000;
                --card-bg: #0d0d0d;
                --card-border: #1a1a1a;
                --text: #ffffff;
                --text-secondary: #b3b3b3;
                --text-muted: #666666;
                
                --glow-primary: 0 0 20px rgba(138, 43, 226, 0.7);
                --glow-accent: 0 0 15px rgba(0, 255, 255, 0.5);
                --glow-danger: 0 0 15px rgba(255, 42, 109, 0.5);
            }

            /* ========== FEMBOY THEME (For Nathan only) ========== */
            .theme-femboy {
                --primary: #ff69b4;
                --primary-dark: #db7093;
                --primary-light: #ffb6c1;
                --secondary: #1a0b2e;
                --secondary-dark: #0d0519;
                --secondary-light: #2d1b47;
                --accent: #ff9ff3;
                --accent-dark: #f368e0;
                --danger: #ff6b6b;
                --warning: #ffd93d;
                --success: #6bcf7f;
                --info: #54a0ff;
                
                --background: #1a0b2e;
                --card-bg: rgba(45, 27, 71, 0.9);
                --card-border: #6d3b9a;
                --text: #ffffff;
                --text-secondary: #d8bfd8;
                --text-muted: #a881af;
                
                --glow-primary: 0 0 20px rgba(255, 105, 180, 0.7);
                --glow-accent: 0 0 15px rgba(255, 159, 243, 0.5);
                --glow-danger: 0 0 15px rgba(255, 107, 107, 0.5);
            }

            /* ========== COMMON STYLES ========== */
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            html, body {
                height: 100%;
                overflow: hidden;
            }

            body {
                font-family: 'Exo 2', sans-serif;
                background: var(--background);
                color: var(--text);
                min-height: 100vh;
                overflow-y: auto;
                background-image: 
                    radial-gradient(circle at 20% 50%, rgba(var(--primary-rgb, 138, 43, 226), 0.05) 0%, transparent 50%),
                    radial-gradient(circle at 80% 20%, rgba(var(--accent-rgb, 0, 255, 255), 0.03) 0%, transparent 50%),
                    linear-gradient(180deg, rgba(0,0,0,0.95) 0%, var(--secondary-dark, rgba(10,10,10,0.95)) 100%);
                transition: all 0.5s ease;
            }

            /* Cyber grid for cyberpunk theme only */
            .cyber-grid {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-image: 
                    linear-gradient(rgba(138, 43, 226, 0.05) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(138, 43, 226, 0.05) 1px, transparent 1px);
                background-size: 50px 50px;
                z-index: -1;
                pointer-events: none;
                opacity: 0.5;
            }

            /* Hearts background for femboy theme */
            .hearts-bg {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-image: 
                    radial-gradient(circle at 10% 20%, rgba(255, 105, 180, 0.1) 0%, transparent 20%),
                    radial-gradient(circle at 90% 30%, rgba(255, 182, 193, 0.1) 0%, transparent 20%),
                    radial-gradient(circle at 50% 80%, rgba(255, 159, 243, 0.1) 0%, transparent 20%);
                z-index: -1;
                pointer-events: none;
                opacity: 0.6;
            }

            /* Scanlines for both themes */
            .scanlines {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: linear-gradient(
                    to bottom,
                    transparent 50%,
                    rgba(var(--accent-rgb, 0, 255, 255), 0.03) 51%,
                    transparent 52%
                );
                background-size: 100% 4px;
                animation: scanlines 8s linear infinite;
                z-index: -1;
                pointer-events: none;
                opacity: 0.3;
            }

            @keyframes scanlines {
                0% { transform: translateY(-100%); }
                100% { transform: translateY(100%); }
            }

            /* ========== GLOW ANIMATIONS ========== */
            @keyframes glow-pulse {
                0%, 100% { box-shadow: var(--glow-primary); }
                50% { box-shadow: 0 0 30px rgba(var(--primary-rgb, 138, 43, 226), 0.9); }
            }

            @keyframes flicker {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.8; }
            }

            @keyframes slide-in {
                from { transform: translateY(20px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }

            @keyframes float {
                0%, 100% { transform: translateY(0px); }
                50% { transform: translateY(-10px); }
            }

            @keyframes sparkle {
                0%, 100% { opacity: 0.3; transform: scale(1); }
                50% { opacity: 1; transform: scale(1.1); }
            }

            .glow-pulse {
                animation: glow-pulse 2s infinite;
            }

            .flicker {
                animation: flicker 3s infinite;
            }

            .float {
                animation: float 3s ease-in-out infinite;
            }

            .sparkle {
                animation: sparkle 2s infinite;
            }

            /* ========== CUSTOM SCROLLBAR ========== */
            ::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }

            ::-webkit-scrollbar-track {
                background: var(--secondary-light);
                border-radius: 4px;
            }

            ::-webkit-scrollbar-thumb {
                background: linear-gradient(45deg, var(--primary), var(--primary-light));
                border-radius: 4px;
            }

            ::-webkit-scrollbar-thumb:hover {
                background: linear-gradient(45deg, var(--primary-light), var(--accent));
            }

            /* ========== LAYOUT ========== */
            .container {
                max-width: 1600px;
                margin: 0 auto;
                padding: 20px;
                height: calc(100vh - 40px);
                overflow-y: auto;
            }

            .container::-webkit-scrollbar {
                width: 6px;
            }

            /* ========== HEADER ========== */
            .header {
                background: rgba(13, 13, 13, 0.95);
                backdrop-filter: blur(10px);
                border-bottom: 1px solid rgba(var(--primary-rgb, 138, 43, 226), 0.3);
                padding: 20px 30px;
                margin-bottom: 30px;
                border-radius: var(--radius-lg);
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: relative;
                overflow: hidden;
                box-shadow: 0 5px 25px rgba(0, 0, 0, 0.5);
                flex-shrink: 0;
                transition: all 0.5s ease;
            }

            .theme-femboy .header {
                background: rgba(45, 27, 71, 0.95);
                border-bottom: 1px solid rgba(255, 105, 180, 0.3);
            }

            .header::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: linear-gradient(90deg, 
                    transparent, 
                    var(--primary), 
                    var(--accent), 
                    var(--primary), 
                    transparent
                );
            }

            .logo {
                display: flex;
                align-items: center;
                gap: 15px;
            }

            .logo-icon {
                background: linear-gradient(45deg, var(--primary), var(--primary-light));
                width: 50px;
                height: 50px;
                border-radius: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 24px;
                color: white;
                box-shadow: var(--glow-primary);
                animation: glow-pulse 3s infinite;
            }

            .theme-femboy .logo-icon {
                animation: float 3s ease-in-out infinite;
            }

            .logo-text {
                font-family: 'Orbitron', monospace;
            }

            .logo-text h1 {
                background: linear-gradient(45deg, var(--primary), var(--accent));
                -webkit-background-clip: text;
                background-clip: text;
                color: transparent;
                font-size: 28px;
                font-weight: 900;
                letter-spacing: 2px;
                text-transform: uppercase;
            }

            .logo-text .tagline {
                color: var(--accent);
                font-size: 12px;
                letter-spacing: 3px;
                text-transform: uppercase;
                opacity: 0.8;
            }

            /* ========== USER PANEL ========== */
            .user-panel {
                display: flex;
                align-items: center;
                gap: 20px;
            }

            .connection-status {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 8px 16px;
                background: rgba(var(--success-rgb, 6, 214, 160), 0.1);
                border: 1px solid rgba(var(--success-rgb, 6, 214, 160), 0.3);
                border-radius: 20px;
                font-size: 14px;
                font-weight: 600;
            }

            .connection-status.connected .status-dot {
                background: var(--success);
                box-shadow: 0 0 10px var(--success);
            }

            .connection-status.disconnected .status-dot {
                background: var(--danger);
                box-shadow: 0 0 10px var(--danger);
            }

            .status-dot {
                width: 10px;
                height: 10px;
                border-radius: 50%;
                animation: flicker 2s infinite;
            }

            .user-info {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 10px 20px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: var(--radius-md);
                border: 1px solid rgba(var(--primary-rgb, 138, 43, 226), 0.2);
            }

            .theme-femboy .user-info {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 105, 180, 0.3);
            }

            .user-avatar {
                width: 40px;
                height: 40px;
                background: linear-gradient(45deg, var(--primary), var(--accent));
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: bold;
                font-size: 18px;
                color: white;
            }

            .theme-femboy .user-avatar {
                animation: sparkle 2s infinite;
            }

            .user-details {
                display: flex;
                flex-direction: column;
            }

            .user-email {
                font-weight: 600;
                font-size: 14px;
            }

            .user-role {
                font-size: 12px;
                color: var(--accent);
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            .logout-btn {
                background: linear-gradient(45deg, var(--danger), #ff2a6d);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: var(--radius-md);
                cursor: pointer;
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 8px;
                transition: all 0.3s;
                box-shadow: 0 0 15px rgba(255, 42, 109, 0.3);
            }

            .logout-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 0 20px rgba(255, 42, 109, 0.5);
            }

            /* ========== STATS CARDS ========== */
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
                flex-shrink: 0;
            }

            .stat-card {
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                border-radius: var(--radius-lg);
                padding: 25px;
                position: relative;
                overflow: hidden;
                transition: all 0.3s;
                cursor: pointer;
            }

            .stat-card:hover {
                transform: translateY(-5px);
                border-color: var(--primary);
                box-shadow: var(--glow-primary);
            }

            .theme-femboy .stat-card:hover {
                animation: float 0.5s ease-in-out;
            }

            .stat-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--primary), var(--accent));
            }

            .stat-icon {
                width: 60px;
                height: 60px;
                background: rgba(var(--primary-rgb, 138, 43, 226), 0.1);
                border-radius: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 24px;
                color: var(--primary);
                margin-bottom: 20px;
                border: 1px solid rgba(var(--primary-rgb, 138, 43, 226), 0.3);
            }

            .theme-femboy .stat-icon {
                animation: sparkle 2s infinite;
            }

            .stat-value {
                font-family: 'Orbitron', monospace;
                font-size: 42px;
                font-weight: 900;
                background: linear-gradient(45deg, var(--primary), var(--accent));
                -webkit-background-clip: text;
                background-clip: text;
                color: transparent;
                line-height: 1;
                margin: 10px 0;
            }

            .stat-label {
                color: var(--text-secondary);
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 2px;
                font-weight: 600;
            }

            /* ========== PANELS ========== */
            .panel {
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                border-radius: var(--radius-lg);
                overflow: hidden;
                display: flex;
                flex-direction: column;
                height: 600px;
                transition: all 0.5s ease;
            }

            .theme-femboy .panel {
                backdrop-filter: blur(10px);
            }

            .panel-header {
                background: rgba(13, 13, 13, 0.95);
                padding: 20px;
                border-bottom: 1px solid var(--card-border);
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-shrink: 0;
            }

            .theme-femboy .panel-header {
                background: rgba(45, 27, 71, 0.95);
            }

            .panel-header h2 {
                font-family: 'Orbitron', monospace;
                font-size: 18px;
                text-transform: uppercase;
                letter-spacing: 2px;
                color: var(--accent);
                display: flex;
                align-items: center;
                gap: 10px;
            }

            /* ========== TABS ========== */
            .tabs {
                display: flex;
                background: rgba(13, 13, 13, 0.95);
                border-bottom: 1px solid var(--card-border);
                padding: 5px;
                flex-shrink: 0;
            }

            .theme-femboy .tabs {
                background: rgba(45, 27, 71, 0.95);
            }

            .tab {
                flex: 1;
                padding: 15px;
                background: transparent;
                border: none;
                color: var(--text-secondary);
                font-family: 'Orbitron', monospace;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
                cursor: pointer;
                transition: all 0.3s;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                position: relative;
            }

            .tab:hover {
                color: var(--text);
                background: rgba(var(--primary-rgb, 138, 43, 226), 0.1);
            }

            .tab.active {
                color: var(--primary);
                background: rgba(var(--primary-rgb, 138, 43, 226), 0.2);
            }

            .tab.active::after {
                content: '';
                position: absolute;
                bottom: -1px;
                left: 0;
                right: 0;
                height: 2px;
                background: linear-gradient(90deg, var(--primary), var(--accent));
            }

            /* ========== BUTTONS ========== */
            .btn {
                padding: 12px 24px;
                border: none;
                border-radius: var(--radius-md);
                font-family: 'Exo 2', sans-serif;
                font-weight: 600;
                font-size: 14px;
                cursor: pointer;
                transition: all 0.3s;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                text-transform: uppercase;
                letter-spacing: 1px;
                position: relative;
                overflow: hidden;
            }

            .btn::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
                transition: left 0.5s;
            }

            .btn:hover::before {
                left: 100%;
            }

            .btn-primary {
                background: linear-gradient(45deg, var(--primary), var(--primary-light));
                color: white;
                box-shadow: var(--glow-primary);
            }

            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 0 25px rgba(var(--primary-rgb, 138, 43, 226), 0.7);
            }

            .theme-femboy .btn-primary:hover {
                animation: sparkle 0.5s;
            }

            /* ========== LOGIN PAGE ========== */
            .login-container {
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
                animation: fadeIn 0.5s ease;
            }

            .login-box {
                background: rgba(13, 13, 13, 0.95);
                border: 1px solid rgba(var(--primary-rgb, 138, 43, 226), 0.3);
                border-radius: var(--radius-xl);
                padding: 50px 40px;
                width: 100%;
                max-width: 420px;
                box-shadow: 0 0 60px rgba(var(--primary-rgb, 138, 43, 226), 0.2);
                position: relative;
                overflow: hidden;
                backdrop-filter: blur(10px);
            }

            .theme-femboy .login-box {
                background: rgba(45, 27, 71, 0.95);
                border: 1px solid rgba(255, 105, 180, 0.3);
                box-shadow: 0 0 60px rgba(255, 105, 180, 0.2);
            }

            .login-box::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--primary), var(--accent));
            }

            .login-title {
                text-align: center;
                margin-bottom: 40px;
            }

            .login-title h1 {
                font-family: 'Orbitron', monospace;
                font-size: 32px;
                background: linear-gradient(45deg, var(--primary), var(--accent));
                -webkit-background-clip: text;
                background-clip: text;
                color: transparent;
                margin-bottom: 10px;
            }

            .login-title .tagline {
                color: var(--accent);
                font-size: 14px;
                letter-spacing: 3px;
                text-transform: uppercase;
                opacity: 0.8;
            }

            /* ========== FORM ELEMENTS ========== */
            .form-group {
                margin-bottom: 20px;
            }

            .form-label {
                display: block;
                margin-bottom: 8px;
                color: var(--accent);
                font-weight: 600;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            .form-control {
                width: 100%;
                padding: 14px;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: var(--radius-md);
                color: var(--text);
                font-family: 'Exo 2', sans-serif;
                font-size: 14px;
                transition: all 0.3s;
            }

            .theme-femboy .form-control {
                background: rgba(255, 255, 255, 0.1);
            }

            .form-control:focus {
                outline: none;
                border-color: var(--primary);
                box-shadow: 0 0 0 3px rgba(var(--primary-rgb, 138, 43, 226), 0.1);
                background: rgba(var(--primary-rgb, 138, 43, 226), 0.05);
            }

            /* ========== NOTIFICATIONS ========== */
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                background: var(--card-bg);
                border-left: 4px solid var(--primary);
                border-radius: var(--radius-md);
                padding: 16px 20px;
                color: var(--text);
                box-shadow: 0 5px 20px rgba(0, 0, 0, 0.5);
                z-index: 10000;
                animation: slideIn 0.3s;
                max-width: 400px;
                display: flex;
                align-items: center;
                gap: 12px;
                font-weight: 500;
                backdrop-filter: blur(10px);
            }

            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }

            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }

            /* ========== UTILITY CLASSES ========== */
            .hidden { display: none !important; }
            .block { display: block; }

            .mb-2 { margin-bottom: 16px; }
            .mt-2 { margin-top: 16px; }
            .mt-4 { margin-top: 32px; }

            .text-center { text-align: center; }
            .text-danger { color: var(--danger); }
            .text-success { color: var(--success); }

            .w-full { width: 100%; }

            /* ========== LOADING ========== */
            .loading {
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid rgba(var(--primary-rgb, 138, 43, 226), 0.3);
                border-top: 3px solid var(--primary);
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            .loading-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.9);
                display: none;
                justify-content: center;
                align-items: center;
                z-index: 10001;
                backdrop-filter: blur(5px);
            }

            .loading-spinner {
                width: 80px;
                height: 80px;
                border: 4px solid rgba(var(--primary-rgb, 138, 43, 226), 0.3);
                border-top: 4px solid var(--primary);
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }

            /* ========== FEMBOY SPECIAL ELEMENTS ========== */
            .theme-femboy .heart {
                position: absolute;
                font-size: 20px;
                color: var(--primary);
                opacity: 0.5;
                animation: float 3s ease-in-out infinite;
            }

            .theme-femboy .heart:nth-child(1) { top: 10%; left: 10%; animation-delay: 0s; }
            .theme-femboy .heart:nth-child(2) { top: 20%; right: 15%; animation-delay: 0.5s; }
            .theme-femboy .heart:nth-child(3) { bottom: 15%; left: 20%; animation-delay: 1s; }
            .theme-femboy .heart:nth-child(4) { bottom: 25%; right: 25%; animation-delay: 1.5s; }

            /* ========== SPECIAL BADGE FOR NATHAN ========== */
            .special-badge {
                background: linear-gradient(45deg, var(--primary), var(--accent));
                color: white;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 11px;
                font-weight: bold;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-left: 10px;
                animation: sparkle 2s infinite;
            }
        </style>
    </head>
    <body>
        <!-- Theme-specific background elements -->
        <div class="cyber-grid"></div>
        <div class="hearts-bg"></div>
        <div class="scanlines"></div>
        
        <!-- Floating hearts for femboy theme -->
        <div class="heart hidden"><i class="fas fa-heart"></i></div>
        <div class="heart hidden"><i class="fas fa-heart"></i></div>
        <div class="heart hidden"><i class="fas fa-heart"></i></div>
        <div class="heart hidden"><i class="fas fa-heart"></i></div>

        <!-- Login Page -->
        <div id="loginPage" class="login-container">
            <div class="login-box">
                <div class="login-title">
                    <h1>ANALCONTROL</h1>
                    <div class="tagline">v3.0 | ADMINISTRATOR ACCESS</div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">USERNAME</label>
                    <input type="text" id="loginEmail" class="form-control" placeholder="Enter username" autocomplete="username" value="nathan">
                </div>
                
                <div class="form-group">
                    <label class="form-label">PASSWORD</label>
                    <input type="password" id="loginPassword" class="form-control" placeholder="••••••••" autocomplete="current-password" value="femboy67">
                </div>
                
                <button onclick="handleLogin()" class="btn btn-primary w-full" id="loginButton">
                    <i class="fas fa-lock"></i> SECURE LOGIN
                </button>
                
                <div id="loginError" class="hidden mt-2">
                    <div class="text-center text-danger">
                        <i class="fas fa-exclamation-triangle"></i> <span id="loginErrorText">Authentication failed</span>
                    </div>
                    <div class="form-hint text-center">Check your credentials and try again</div>
                </div>
                
                <div class="text-center mt-4">
                    <div class="form-hint">Default users: admin/admin123, nathan/femboy67</div>
                    <div class="form-hint mt-2">Try "nathan" for special theme!</div>
                </div>
            </div>
        </div>

        <!-- Dashboard -->
        <div id="dashboard" class="hidden">
            <div class="container">
                <!-- Header -->
                <header class="header">
                    <div class="logo">
                        <div class="logo-icon">
                            <i class="fas fa-server"></i>
                        </div>
                        <div class="logo-text">
                            <h1>ANALCONTROL v3.0</h1>
                            <div class="tagline">REAL-TIME MONITOR <span id="themeBadge" class="special-badge hidden">SPECIAL THEME</span></div>
                        </div>
                    </div>
                    
                    <div class="user-panel">
                        <div class="connection-status connected" id="connectionStatus">
                            <div class="status-dot"></div>
                            <span>CONNECTED</span>
                        </div>
                        
                        <div class="user-info">
                            <div class="user-avatar" id="userAvatar">N</div>
                            <div class="user-details">
                                <div class="user-email" id="userEmail">nathan</div>
                                <div class="user-role" id="userRole">ADMINISTRATOR</div>
                            </div>
                        </div>
                        
                        <button onclick="handleLogout()" class="logout-btn">
                            <i class="fas fa-sign-out-alt"></i> LOGOUT
                        </button>
                    </div>
                </header>

                <!-- Stats Grid -->
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-desktop"></i>
                        </div>
                        <div class="stat-value" id="totalClients">2</div>
                        <div class="stat-label">TOTAL CLIENTS</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-wifi"></i>
                        </div>
                        <div class="stat-value" id="onlineClients">0</div>
                        <div class="stat-label">ONLINE NOW</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-terminal"></i>
                        </div>
                        <div class="stat-value" id="activeCommands">0</div>
                        <div class="stat-label">ACTIVE COMMANDS</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-icon">
                            <i class="fas fa-microphone"></i>
                        </div>
                        <div class="stat-value" id="audioRecordings">0</div>
                        <div class="stat-label">AUDIO RECORDINGS</div>
                    </div>
                </div>

                <!-- Main Content -->
                <div class="main-content">
                    <!-- Left Panel -->
                    <div class="panel">
                        <div class="tabs">
                            <button class="tab active" onclick="switchTab('clients')">
                                <i class="fas fa-users"></i> CLIENTS
                            </button>
                            <button class="tab" onclick="switchTab('commands')">
                                <i class="fas fa-terminal"></i> COMMANDS
                            </button>
                            <button class="tab" onclick="switchTab('logs')">
                                <i class="fas fa-clipboard-list"></i> LOGS
                            </button>
                        </div>
                        
                        <!-- Clients Tab -->
                        <div id="clientsTab" class="tab-content">
                            <div class="panel-header">
                                <h2><i class="fas fa-users"></i> CONNECTED CLIENTS</h2>
                                <div class="panel-actions">
                                    <button onclick="refreshClients()" class="btn btn-secondary btn-sm">
                                        <i class="fas fa-sync"></i> REFRESH
                                    </button>
                                </div>
                            </div>
                            
                            <div class="panel-content">
                                <div id="clientsEmpty" class="empty-state">
                                    <i class="fas fa-users-slash"></i>
                                    <h3>No Clients Connected</h3>
                                    <p>Waiting for client connections...</p>
                                </div>
                                
                                <div class="table-container" id="clientsTableContainer">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>ID</th>
                                                <th>NAME</th>
                                                <th>STATUS</th>
                                                <th>IP ADDRESS</th>
                                                <th>LAST SEEN</th>
                                                <th>ACTIONS</th>
                                            </tr>
                                        </thead>
                                        <tbody id="clientsTable">
                                            <!-- Clients will be loaded here -->
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Commands Tab -->
                        <div id="commandsTab" class="tab-content hidden">
                            <div class="panel-header">
                                <h2><i class="fas fa-terminal"></i> COMMAND CONTROL</h2>
                            </div>
                            <div class="panel-content">
                                <div class="empty-state">
                                    <i class="fas fa-terminal"></i>
                                    <h3>Command Panel</h3>
                                    <p>Available in full version</p>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Logs Tab -->
                        <div id="logsTab" class="tab-content hidden">
                            <div class="panel-header">
                                <h2><i class="fas fa-clipboard-list"></i> SYSTEM LOGS</h2>
                            </div>
                            <div class="panel-content">
                                <div class="empty-state">
                                    <i class="fas fa-clipboard-list"></i>
                                    <h3>System Logs</h3>
                                    <p>Logs will appear here</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Right Panel -->
                    <div class="flex flex-col gap-3">
                        <!-- System Status -->
                        <div class="panel">
                            <div class="panel-header">
                                <h2><i class="fas fa-server"></i> SYSTEM STATUS</h2>
                            </div>
                            <div class="panel-content">
                                <div class="space-y-3">
                                    <div class="flex justify-between items-center">
                                        <span>Backend API</span>
                                        <span id="apiStatus" class="status-badge status-online">
                                            <i class="fas fa-circle"></i> ONLINE
                                        </span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span>WebSocket</span>
                                        <span id="wsStatus" class="status-badge status-online">
                                            <i class="fas fa-circle"></i> CONNECTED
                                        </span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span>Database</span>
                                        <span id="dbStatus" class="status-badge status-online">
                                            <i class="fas fa-circle"></i> CONNECTED
                                        </span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span>Uptime</span>
                                        <span id="uptime" class="font-mono">00:00:00</span>
                                    </div>
                                    <div class="flex justify-between items-center">
                                        <span>Active Sessions</span>
                                        <span id="activeSessions">1</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Theme Info -->
                        <div class="panel" id="themeInfoPanel">
                            <div class="panel-header">
                                <h2><i class="fas fa-palette"></i> THEME INFO</h2>
                            </div>
                            <div class="panel-content">
                                <div class="text-center">
                                    <div class="stat-value" id="themeName">FEMBOY</div>
                                    <div class="stat-label" id="themeDescription">SPECIAL THEME</div>
                                    <div class="mt-4">
                                        <p id="themeMessage">You're using the exclusive Femboy theme! ✨</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Footer -->
                <footer class="footer">
                    <div>ANALCONTROL v3.0 | SECURE MONITORING SYSTEM</div>
                    <div class="footer-links">
                        <a href="#" onclick="showAbout()">About</a>
                        <a href="#" onclick="showSettings()">Settings</a>
                        <a href="#" onclick="showHelp()">Help</a>
                    </div>
                    <div class="mt-2">
                        <small>© 2026 CP Systems. All access logged and monitored.</small>
                    </div>
                </footer>
            </div>
        </div>

        <!-- Loading Overlay -->
        <div id="loadingOverlay" class="loading-overlay">
            <div class="loading-spinner"></div>
            <div class="mt-4 text-accent" id="loadingMessage">Loading...</div>
        </div>

        <script>
            // ========== CONFIGURATION ==========
            const CONFIG = {
                BACKEND_URL: window.location.origin,
                REFRESH_INTERVAL: 10000,
                TOKEN_KEY: 'analcontrol_token',
                USER_KEY: 'analcontrol_user'
            };

            // ========== STATE ==========
            let state = {
                user: null,
                token: null,
                ws: null,
                clients: [],
                commands: [],
                logs: [],
                currentTheme: 'cyberpunk',
                dashboardStartTime: null,
                isInitialized: false
            };

            // ========== INITIALIZATION ==========
            document.addEventListener('DOMContentLoaded', async () => {
                // Check existing session
                const token = localStorage.getItem(CONFIG.TOKEN_KEY);
                const user = localStorage.getItem(CONFIG.USER_KEY);
                
                if (token && user) {
                    try {
                        state.token = token;
                        state.user = JSON.parse(user);
                        // Apply theme based on stored user
                        applyTheme(state.user.theme || 'cyberpunk');
                        await initializeDashboard();
                    } catch (error) {
                        console.error('Session restore failed:', error);
                        localStorage.removeItem(CONFIG.TOKEN_KEY);
                        localStorage.removeItem(CONFIG.USER_KEY);
                    }
                }
                
                // Setup event listeners
                setupEventListeners();
            });

            function setupEventListeners() {
                // Login form
                document.getElementById('loginEmail').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') handleLogin();
                });
                
                document.getElementById('loginPassword').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') handleLogin();
                });
                
                // Close modals on ESC
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') {
                        closeAllModals();
                    }
                });
            }

            // ========== THEME MANAGEMENT ==========
            function applyTheme(theme) {
                state.currentTheme = theme;
                
                // Remove existing theme classes
                document.body.classList.remove('theme-femboy');
                document.body.classList.remove('theme-cyberpunk');
                
                // Apply new theme
                if (theme === 'femboy') {
                    document.body.classList.add('theme-femboy');
                    
                    // Show hearts
                    document.querySelectorAll('.heart').forEach(heart => {
                        heart.classList.remove('hidden');
                    });
                    
                    // Show theme badge
                    const themeBadge = document.getElementById('themeBadge');
                    if (themeBadge) {
                        themeBadge.classList.remove('hidden');
                        themeBadge.textContent = 'FEMBOY THEME';
                    }
                    
                    // Update theme info
                    updateThemeInfo('FEMBOY', 'Exclusive Pink Theme', 'Welcome to your special femboy theme! ✨');
                    
                } else {
                    document.body.classList.add('theme-cyberpunk');
                    
                    // Hide hearts
                    document.querySelectorAll('.heart').forEach(heart => {
                        heart.classList.add('hidden');
                    });
                    
                    // Hide theme badge
                    const themeBadge = document.getElementById('themeBadge');
                    if (themeBadge) {
                        themeBadge.classList.add('hidden');
                    }
                    
                    // Update theme info
                    updateThemeInfo('CYBERPUNK', 'Default Theme', 'Standard cyberpunk interface');
                }
            }

            function updateThemeInfo(name, description, message) {
                const themeName = document.getElementById('themeName');
                const themeDesc = document.getElementById('themeDescription');
                const themeMsg = document.getElementById('themeMessage');
                
                if (themeName) themeName.textContent = name;
                if (themeDesc) themeDesc.textContent = description;
                if (themeMsg) themeMsg.textContent = message;
            }

            // ========== AUTHENTICATION ==========
            async function handleLogin() {
                const email = document.getElementById('loginEmail').value.trim();
                const password = document.getElementById('loginPassword').value;
                
                if (!email || !password) {
                    showNotification('Please enter username and password', 'error');
                    return;
                }
                
                showLoading('Authenticating...');
                
                try {
                    const response = await fetch(`${CONFIG.BACKEND_URL}/api/login`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ email, password })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok && data.success) {
                        // Store auth data
                        localStorage.setItem(CONFIG.TOKEN_KEY, data.token);
                        localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(data.user));
                        
                        state.user = data.user;
                        state.token = data.token;
                        
                        // Apply user's theme
                        applyTheme(data.user.theme || 'cyberpunk');
                        
                        // Initialize dashboard
                        await initializeDashboard();
                        
                        showNotification(`Login successful! Welcome ${data.user.email}`, 'success');
                        
                    } else {
                        throw new Error(data.detail || 'Invalid credentials');
                    }
                } catch (error) {
                    console.error('Login error:', error);
                    document.getElementById('loginError').classList.remove('hidden');
                    document.getElementById('loginErrorText').textContent = error.message;
                    showNotification('Login failed: ' + error.message, 'error');
                } finally {
                    hideLoading();
                }
            }

            function handleLogout() {
                // Close WebSocket
                if (state.ws) {
                    state.ws.close();
                }
                
                // Clear storage
                localStorage.removeItem(CONFIG.TOKEN_KEY);
                localStorage.removeItem(CONFIG.USER_KEY);
                
                // Reset state
                state = {
                    user: null,
                    token: null,
                    ws: null,
                    clients: [],
                    commands: [],
                    logs: [],
                    currentTheme: 'cyberpunk',
                    dashboardStartTime: null,
                    isInitialized: false
                };
                
                // Reset to default theme
                applyTheme('cyberpunk');
                
                // Show login page
                document.getElementById('dashboard').classList.add('hidden');
                document.getElementById('loginPage').classList.remove('hidden');
                
                showNotification('Logged out successfully', 'info');
            }

            // ========== DASHBOARD ==========
            async function initializeDashboard() {
                try {
                    showLoading('Loading dashboard...');
                    
                    // Show dashboard
                    document.getElementById('loginPage').classList.add('hidden');
                    document.getElementById('dashboard').classList.remove('hidden');
                    
                    // Set user info
                    if (state.user) {
                        document.getElementById('userEmail').textContent = state.user.email;
                        const firstLetter = state.user.email.charAt(0).toUpperCase();
                        document.getElementById('userAvatar').textContent = firstLetter;
                        document.getElementById('userRole').textContent = state.user.is_admin ? 'ADMINISTRATOR' : 'USER';
                        
                        // Special styling for Nathan
                        if (state.user.email === 'nathan') {
                            document.getElementById('userAvatar').style.background = 'linear-gradient(45deg, #ff69b4, #ff9ff3)';
                        }
                    }
                    
                    // Load initial data
                    await loadDashboardData();
                    
                    // Connect WebSocket
                    connectWebSocket();
                    
                    // Start uptime counter
                    state.dashboardStartTime = Date.now();
                    updateUptime();
                    
                    state.isInitialized = true;
                    
                    // Scroll to top
                    window.scrollTo(0, 0);
                    
                } catch (error) {
                    console.error('Dashboard initialization failed:', error);
                    showNotification('Failed to load dashboard', 'error');
                    handleLogout();
                } finally {
                    hideLoading();
                }
            }

            function updateUptime() {
                if (!state.dashboardStartTime) return;
                
                const elapsed = Date.now() - state.dashboardStartTime;
                const hours = Math.floor(elapsed / 3600000);
                const minutes = Math.floor((elapsed % 3600000) / 60000);
                const seconds = Math.floor((elapsed % 60000) / 1000);
                
                const uptimeElement = document.getElementById('uptime');
                if (uptimeElement) {
                    uptimeElement.textContent = 
                        `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                }
                
                setTimeout(updateUptime, 1000);
            }

            async function loadDashboardData() {
                try {
                    // Load clients
                    const clientsData = await apiRequest('/api/clients');
                    state.clients = clientsData.clients || [];
                    updateClientsTable();
                    
                    // Load stats
                    const statsData = await apiRequest('/api/stats');
                    updateStats(statsData.stats);
                    
                } catch (error) {
                    console.error('Failed to load dashboard data:', error);
                    // Use sample data if API fails
                    useSampleData();
                }
            }

            function useSampleData() {
                // Sample clients
                state.clients = [
                    {
                        client_id: 'client-001',
                        name: 'Main Server',
                        ip_address: '192.168.1.100',
                        online: true,
                        last_seen: new Date().toISOString(),
                        ws_online: false
                    },
                    {
                        client_id: 'client-002',
                        name: 'Office PC',
                        ip_address: '192.168.1.101',
                        online: false,
                        last_seen: new Date(Date.now() - 3600000).toISOString(),
                        ws_online: false
                    }
                ];
                
                updateClientsTable();
                updateStats({
                    total_clients: 2,
                    online_clients: 1,
                    pending_commands: 0,
                    total_commands: 0,
                    active_connections: 0,
                    active_admins: 1
                });
            }

            function updateStats(stats) {
                if (!stats) return;
                
                document.getElementById('totalClients').textContent = stats.total_clients || 0;
                document.getElementById('onlineClients').textContent = stats.online_clients || 0;
                document.getElementById('activeCommands').textContent = stats.pending_commands || 0;
                document.getElementById('activeSessions').textContent = stats.active_admins || 1;
            }

            function updateClientsTable() {
                const table = document.getElementById('clientsTable');
                const emptyState = document.getElementById('clientsEmpty');
                const container = document.getElementById('clientsTableContainer');
                
                if (!table || !emptyState) return;
                
                table.innerHTML = '';
                
                if (state.clients.length === 0) {
                    emptyState.classList.remove('hidden');
                    container.classList.add('hidden');
                    return;
                }
                
                emptyState.classList.add('hidden');
                container.classList.remove('hidden');
                
                state.clients.forEach(client => {
                    const row = document.createElement('tr');
                    const lastSeen = formatTime(client.last_seen);
                    const isOnline = client.online || client.ws_online;
                    const statusClass = isOnline ? 'status-online' : 'status-offline';
                    const statusText = isOnline ? 'ONLINE' : 'OFFLINE';
                    
                    row.innerHTML = `
                        <td><code class="text-accent">${client.client_id.substring(0, 8)}</code></td>
                        <td>${client.name}</td>
                        <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                        <td>${client.ip_address || 'N/A'}</td>
                        <td>${lastSeen}</td>
                        <td>
                            <button class="btn btn-secondary btn-sm" disabled>
                                <i class="fas fa-eye"></i> View
                            </button>
                        </td>
                    `;
                    table.appendChild(row);
                });
            }

            // ========== API FUNCTIONS ==========
            async function apiRequest(endpoint, method = 'GET', data = null) {
                const headers = {
                    'Content-Type': 'application/json'
                };
                
                if (state.token) {
                    headers['Authorization'] = `Bearer ${state.token}`;
                }
                
                const options = {
                    method,
                    headers
                };
                
                if (data) {
                    options.body = JSON.stringify(data);
                }
                
                try {
                    const response = await fetch(`${CONFIG.BACKEND_URL}${endpoint}`, options);
                    
                    if (response.status === 401) {
                        showNotification('Session expired. Please login again.', 'error');
                        handleLogout();
                        throw new Error('Unauthorized');
                    }
                    
                    if (!response.ok) {
                        const errorData = await response.json().catch(() => ({}));
                        throw new Error(errorData.detail || `HTTP ${response.status}`);
                    }
                    
                    return await response.json();
                } catch (error) {
                    console.error(`API request failed: ${endpoint}`, error);
                    throw error;
                }
            }

            // ========== WEBSOCKET ==========
            function connectWebSocket() {
                const wsUrl = CONFIG.BACKEND_URL.replace('https://', 'wss://').replace('http://', 'ws://');
                
                try {
                    state.ws = new WebSocket(`${wsUrl}/ws/admin`);
                    
                    state.ws.onopen = () => {
                        console.log('WebSocket connected');
                        updateConnectionStatus(true);
                        showNotification('Real-time connection established', 'success');
                    };
                    
                    state.ws.onmessage = (event) => {
                        try {
                            const data = JSON.parse(event.data);
                            handleWebSocketMessage(data);
                        } catch (error) {
                            console.error('WebSocket message error:', error);
                        }
                    };
                    
                    state.ws.onclose = () => {
                        console.log('WebSocket disconnected');
                        updateConnectionStatus(false);
                        
                        // Attempt to reconnect after delay
                        setTimeout(() => {
                            if (state.isInitialized) {
                                connectWebSocket();
                            }
                        }, 3000);
                    };
                    
                    state.ws.onerror = (error) => {
                        console.error('WebSocket error:', error);
                    };
                    
                } catch (error) {
                    console.error('WebSocket connection failed:', error);
                }
            }

            function updateConnectionStatus(connected) {
                const statusElement = document.getElementById('connectionStatus');
                const wsStatusElement = document.getElementById('wsStatus');
                
                if (connected) {
                    statusElement.className = 'connection-status connected';
                    statusElement.innerHTML = '<div class="status-dot"></div><span>CONNECTED</span>';
                    if (wsStatusElement) {
                        wsStatusElement.className = 'status-badge status-online';
                        wsStatusElement.innerHTML = '<i class="fas fa-circle"></i> CONNECTED';
                    }
                } else {
                    statusElement.className = 'connection-status disconnected';
                    statusElement.innerHTML = '<div class="status-dot"></div><span>DISCONNECTED</span>';
                    if (wsStatusElement) {
                        wsStatusElement.className = 'status-badge status-offline';
                        wsStatusElement.innerHTML = '<i class="fas fa-circle"></i> DISCONNECTED';
                    }
                }
            }

            function handleWebSocketMessage(data) {
                console.log('WebSocket message:', data);
                
                switch (data.type) {
                    case 'client_connected':
                        showNotification(`Client connected: ${data.client_id}`, 'info');
                        refreshClients();
                        break;
                        
                    case 'client_disconnected':
                        showNotification(`Client disconnected: ${data.client_id}`, 'warning');
                        refreshClients();
                        break;
                        
                    case 'command_result':
                        showNotification(`Command completed for ${data.client_id}`, 'info');
                        break;
                }
            }

            // ========== UI FUNCTIONS ==========
            async function refreshClients() {
                try {
                    const data = await apiRequest('/api/clients');
                    state.clients = data.clients || [];
                    updateClientsTable();
                    showNotification('Clients list refreshed', 'success');
                } catch (error) {
                    console.error('Failed to refresh clients:', error);
                }
            }

            function switchTab(tabName) {
                // Hide all tab contents
                document.querySelectorAll('.tab-content').forEach(el => {
                    el.classList.add('hidden');
                });
                
                // Show selected tab
                document.getElementById(`${tabName}Tab`).classList.remove('hidden');
                
                // Update tab buttons
                document.querySelectorAll('.tab').forEach(btn => {
                    btn.classList.remove('active');
                });
                
                // Activate clicked tab
                event.target.classList.add('active');
            }

            function formatTime(dateString) {
                if (!dateString) return 'Never';
                const date = new Date(dateString);
                const now = new Date();
                const diffMs = now - date;
                const diffMins = Math.floor(diffMs / 60000);
                
                if (diffMins < 1) return 'Just now';
                if (diffMins < 60) return `${diffMins}m ago`;
                if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
                return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            }

            // ========== UI HELPERS ==========
            function showLoading(message = 'Loading...') {
                document.getElementById('loadingMessage').textContent = message;
                document.getElementById('loadingOverlay').style.display = 'flex';
            }

            function hideLoading() {
                document.getElementById('loadingOverlay').style.display = 'none';
            }

            function showNotification(message, type = 'info', duration = 3000) {
                const notification = document.createElement('div');
                notification.className = `notification`;
                
                let icon = 'fa-info-circle';
                if (type === 'success') icon = 'fa-check-circle';
                if (type === 'error') icon = 'fa-times-circle';
                if (type === 'warning') icon = 'fa-exclamation-triangle';
                
                notification.innerHTML = `
                    <i class="fas ${icon}" style="color: var(--${type}); font-size: 1.2rem;"></i>
                    <div style="flex: 1;">${message}</div>
                `;
                
                document.body.appendChild(notification);
                
                setTimeout(() => {
                    notification.style.animation = 'slideOut 0.3s';
                    setTimeout(() => {
                        if (notification.parentNode) {
                            document.body.removeChild(notification);
                        }
                    }, 300);
                }, duration);
            }

            function closeAllModals() {
                // Not needed for this version
            }

            // ========== GLOBAL EXPORTS ==========
            window.handleLogin = handleLogin;
            window.handleLogout = handleLogout;
            window.switchTab = switchTab;
            window.refreshClients = refreshClients;
            window.showAbout = () => showNotification('ANALCONTROL v3.0 - Secure Monitoring System', 'info');
            window.showSettings = () => showNotification('Settings panel coming soon', 'info');
            window.showHelp = () => showNotification('Press F1 for help documentation', 'info');
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

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
