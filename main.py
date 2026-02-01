# backend_unified.py - Complete ANALCONTROL v4.0 with J.A.R.V.I.S. AI (FREE Local AI - NO API KEYS)
import os
import sys
import logging
import json
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, StreamingResponse
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timedelta
import secrets
import jwt
import asyncio
import uuid
import time
import base64
import hashlib
import mimetypes
import io
import aiohttp
import random
import traceback
import html
import re
from supabase import create_client, Client

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
    title="ANALCONTROL API with J.A.R.V.I.S.",
    version="4.0",
    description="Advanced Client Monitoring System with FREE Local AI Assistant",
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
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
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

# ========== LOCAL AI MODELS (NO API KEYS NEEDED) ==========
class LocalAI:
    """Local AI that runs entirely on your server - NO API KEYS NEEDED"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
        self.model_loaded = False
        self.similarity_threshold = 0.3
        
    def _load_patterns(self):
        """Load extensive pattern matching for ANALCONTROL"""
        return {
            # Greetings
            "hello": "Good evening, sir. J.A.R.V.I.S. systems are online. How may I assist with ANALCONTROL operations today?",
            "hi": "Good evening. J.A.R.V.I.S. at your service. How can I help with the monitoring system?",
            "hey": "Greetings. How may I assist you with ANALCONTROL today?",
            "greetings": "Good day, sir. J.A.R.V.I.S. is ready to assist.",
            
            # Help and capabilities
            "help": """I can help you with ANALCONTROL v4.0:

📊 **Website Navigation:**
   • Switch between all 7 tabs
   • Refresh any section
   • Search and filter data

🖥️ **Client Operations:**
   • Monitor client status
   • Execute commands remotely
   • Capture screenshots
   • Record screens
   • Live stream displays

💻 **System Management:**
   • View system logs
   • Check performance metrics
   • Manage recordings
   • Handle Python scripts

💬 **Communication:**
   • Chat with users
   • Message clients
   • Global messaging

⚡ **Quick Actions:**
   • "Show clients" - View connected systems
   • "Take screenshot" - Capture screen
   • "Open Python" - Access Python tab
   • "Refresh all" - Update all data

What would you like to do?""",
            
            "what can you do": """I have complete control over ANALCONTROL v4.0:

🔧 **Full Website Control:**
   • Navigate all tabs and panels
   • Click any button or control
   • Fill forms and submit them
   • Refresh data dynamically

🎯 **Client Management:**
   • View all connected clients
   • Execute commands on any client
   • Capture screenshots/recordings
   • Get system information
   • Start/stop live streams

📁 **File Operations:**
   • Execute Python scripts
   • Manage screenshot gallery
   • Handle recording library
   • View and export logs

💬 **Communication:**
   • Global chat interface
   • Private messaging
   • Client communication
   • User notifications

📊 **Monitoring:**
   • Real-time status updates
   • Connection graphs
   • System statistics
   • Performance metrics

Try commands like:
• "Show me connected clients"
• "Take screenshot of client-001"
• "Open command panel"
• "Check system status"
• "Message all users" """,
            
            "what is analcontrol": """ANALCONTROL v4.0 is an advanced client monitoring and control system.

🎯 **Core Purpose:**
   • Real-time remote system monitoring
   • Centralized client management
   • Automated system administration
   • Comprehensive logging and analytics

🛠️ **Key Features:**
   • **Client Dashboard**: Live status monitoring
   • **Command Center**: Remote command execution
   • **Python Engine**: Script execution on clients
   • **Screen Capture**: Screenshots & recordings
   • **Live Streaming**: Real-time screen viewing
   • **Chat System**: User/client communication
   • **Log Management**: System activity tracking
   • **User Roles**: Role-based access control

🚀 **Use Cases:**
   • IT administration and monitoring
   • Remote system management
   • Security surveillance
   • Automated maintenance
   • User activity monitoring
   • System diagnostics

⚡ **Real-time Capabilities:**
   • WebSocket connections
   • Live status updates
   • Instant command results
   • Real-time chat
   • Live screen streaming

I'm J.A.R.V.I.S., your AI assistant for this powerful platform.""",
            
            # Navigation patterns
            "show client": "Opening Clients tab to display connected systems. [Action: switch to clients]",
            "open client": "Switching to Clients tab. [Action: switch to clients]",
            "view client": "Displaying client dashboard. [Action: switch to clients]",
            "connected client": "Showing connected clients. [Action: switch to clients]",
            "online client": "Displaying online systems. [Action: switch to clients]",
            
            "show command": "Opening Commands tab for remote execution. [Action: switch to commands]",
            "open command": "Accessing command control panel. [Action: switch to commands]",
            "execute command": "Loading command interface. [Action: switch to commands]",
            "send command": "Preparing command execution. [Action: switch to commands]",
            
            "show python": "Opening Python tab for script execution. [Action: switch to python]",
            "open python": "Accessing Python script editor. [Action: switch to python]",
            "run python": "Loading Python execution panel. [Action: switch to python]",
            "python script": "Opening script management. [Action: switch to python]",
            
            "show screenshot": "Opening Screenshots tab. [Action: switch to screenshots]",
            "open screenshot": "Accessing screenshot gallery. [Action: switch to screenshots]",
            "view screenshot": "Loading screenshot library. [Action: switch to screenshots]",
            "capture screenshot": "Opening capture controls. [Action: switch to screenshots]",
            
            "show recording": "Opening Recordings tab. [Action: switch to recordings]",
            "open recording": "Accessing recording library. [Action: switch to recordings]",
            "view recording": "Loading video recordings. [Action: switch to recordings]",
            "record screen": "Opening recording controls. [Action: switch to recordings]",
            
            "show log": "Opening Logs tab. [Action: switch to logs]",
            "open log": "Accessing system logs. [Action: switch to logs]",
            "view log": "Displaying activity logs. [Action: switch to logs]",
            "check log": "Loading log history. [Action: switch to logs]",
            
            "show chat": "Opening Chat tab. [Action: switch to chat]",
            "open chat": "Accessing chat interface. [Action: switch to chat]",
            "message": "Loading messaging system. [Action: switch to chat]",
            "talk to": "Opening communication panel. [Action: switch to chat]",
            
            # Action patterns
            "take screenshot": "Capturing screenshot from connected clients. [Action: execute screenshot]",
            "capture screenshot": "Initiating screenshot capture. [Action: execute screenshot]",
            "grab screen": "Taking screen capture. [Action: execute screenshot]",
            "screenshot all": "Capturing all client screens. [Action: execute screenshot all]",
            
            "start recording": "Beginning screen recording. [Action: execute record_screen]",
            "record screen": "Initiating screen recording. [Action: execute record_screen]",
            "start video": "Starting video capture. [Action: execute record_screen]",
            "record all": "Recording all client screens. [Action: execute record_screen all]",
            
            "live stream": "Starting live screen streaming. [Action: execute live_screen]",
            "stream screen": "Initiating live stream. [Action: execute live_screen]",
            "watch live": "Opening live view. [Action: execute live_screen]",
            "live view": "Starting live streaming. [Action: execute live_screen]",
            
            "refresh": "Refreshing all system data. [Action: refresh all]",
            "update": "Updating dashboard information. [Action: refresh all]",
            "reload": "Reloading system data. [Action: refresh all]",
            "sync": "Synchronizing all panels. [Action: refresh all]",
            
            "system info": "Getting system information from clients. [Action: execute system_info]",
            "get info": "Retrieving client system details. [Action: execute system_info]",
            "check system": "Checking client systems. [Action: execute system_info]",
            "client info": "Getting client information. [Action: execute system_info]",
            
            # Status queries
            "status": "Checking system status and metrics. [Action: check status]",
            "system status": "Analyzing ANALCONTROL system health. [Action: check status]",
            "health": "Checking system health status. [Action: check status]",
            "how many client": "Counting connected clients. [Action: refresh clients]",
            "online count": "Checking online client count. [Action: refresh clients]",
            
            # Troubleshooting
            "not working": "I understand you're experiencing issues, sir. Let me help troubleshoot. What specifically isn't working? You can describe the problem and I'll guide you through solutions.",
            "error": "I apologize for the error. Could you provide more details about what happened? This will help me assist you better with the issue.",
            "broken": "Let me help you resolve this. What component seems to be malfunctioning? I can guide you through recovery steps.",
            "fix": "I'll help you fix the issue. Please describe what needs repair or what error you're encountering.",
            
            # Information
            "version": "ANALCONTROL Version 4.0 with J.A.R.V.I.S. AI Integration. Latest build with full website control capabilities.",
            "who made": "ANALCONTROL was developed for comprehensive system monitoring and administration. I'm J.A.R.V.I.S., your integrated AI assistant.",
            "developer": "This platform is designed for advanced client monitoring, remote management, and system administration.",
            "about": """ANALCONTROL v4.0 - Advanced Monitoring System

• **Purpose**: Comprehensive remote system management
• **Features**: Real-time monitoring, command execution, media capture
• **AI Integration**: J.A.R.V.I.S. assistant with full website control
• **Architecture**: Modern web-based, real-time updates
• **Security**: Role-based access, encrypted communications
• **Scalability**: Supports unlimited client connections

I'm here to help you leverage all these capabilities effectively.""",
            
            # Gratitude
            "thank": "You're welcome, sir. Always happy to assist with ANALCONTROL operations.",
            "thanks": "My pleasure. Let me know if you need further assistance.",
            "appreciate": "Thank you, sir. I'm here to ensure system efficiency.",
            
            # Farewell
            "bye": "Goodbye, sir. J.A.R.V.I.S. systems will remain online for your next command.",
            "goodbye": "Farewell. The monitoring systems continue running.",
            "exit": "Exiting chat interface. Type anything to reactivate J.A.R.V.I.S.",
            "close": "Closing chat window. I remain active in the background.",
            
            # Confirmation
            "yes": "Affirmative. Proceeding as requested.",
            "no": "Understood. Operation cancelled.",
            "ok": "Acknowledged. Continuing with current operations.",
            "okay": "Confirmed. Standing by for next instruction.",
            
            # Default fallback
            "default": "I understand you're asking about ANALCONTROL. I can help with website navigation, client management, command execution, system monitoring, and communication features. Could you be more specific about what you'd like to do?"
        }
    
    def get_response(self, message: str, context: Dict = None) -> str:
        """Get AI response using local pattern matching with similarity"""
        message_lower = message.lower().strip()
        
        # Direct pattern matching first
        for pattern, response in self.patterns.items():
            if pattern in message_lower:
                return response
        
        # Try partial matching with similarity
        best_match = None
        best_score = 0
        
        for pattern, response in self.patterns.items():
            # Simple word overlap scoring
            pattern_words = set(pattern.split())
            message_words = set(message_lower.split())
            common_words = pattern_words.intersection(message_words)
            
            if common_words:
                score = len(common_words) / max(len(pattern_words), len(message_words))
                if score > best_score:
                    best_score = score
                    best_match = response
        
        if best_score > 0.2:  # Threshold for partial matches
            return best_match
        
        # Contextual response based on keywords
        keywords = {
            'tab': "Which tab would you like to open? I can navigate to: Clients, Commands, Python, Screenshots, Recordings, Logs, or Chat.",
            'client': "I can help with client management. Would you like to view clients, execute commands, capture screenshots, or get system info?",
            'command': "I can execute commands on clients. What would you like to run? Screenshot, system info, recording, or custom command?",
            'python': "The Python tab allows script execution on clients. Would you like to write code, use templates, or view execution history?",
            'screenshot': "I can capture screenshots from clients. Specify a client or say 'all' for all connected systems.",
            'recording': "I can record client screens. Set duration in seconds or say 'live' for streaming.",
            'log': "The Logs tab shows system activity. Would you like to view, filter, or export logs?",
            'chat': "I can open the chat interface. Would you like global chat or to message a specific user/client?",
            'refresh': "Refreshing system data. Specify what to refresh: all, clients, screenshots, recordings, logs, or commands.",
            'status': "Checking system status. I can show connection count, online clients, active streams, and system health.",
            'help': "I can help with all ANALCONTROL features. Be specific about what you need assistance with.",
            'how': "I'll guide you through the process. What would you like to learn how to do?",
            'what': "I'll explain that feature. What specifically would you like to know about?",
            'why': "Let me explain the purpose and benefits of that feature.",
            'where': "I'll show you where to find that in the interface.",
            'when': "I can tell you when that feature is available or how to schedule it.",
        }
        
        for keyword, response in keywords.items():
            if keyword in message_lower:
                return response
        
        # Enhanced default response with suggestions
        suggestions = [
            "Show me connected clients",
            "Take a screenshot",
            "Open Python tab", 
            "Start recording",
            "Check system status",
            "Open chat interface"
        ]
        
        random_suggestion = random.choice(suggestions)
        
        return f"""I understand you're asking about "{message}". 

I can help you with ANALCONTROL v4.0 operations:

• **Navigation**: Switch between all 7 tabs
• **Client Control**: Monitor, command, and capture from clients  
• **System Management**: View logs, check status, manage data
• **Communication**: Chat with users and clients
• **Automation**: Schedule tasks and auto-capture

Try saying something like:
• "{random_suggestion}"
• "What can you do?"
• "Help me with [specific task]"

Or be more specific about what you'd like to accomplish."""

# Initialize local AI
local_ai = LocalAI()

# ========== JARVIS PERSONALITY ENGINE ==========
class JarvisPersonalityEngine:
    """Adds personality and context to J.A.R.V.I.S. responses"""
    
    def __init__(self):
        self.conversation_history = []
        self.user_preferences = {}
        
    def enhance_response(self, response: str) -> str:
        """Add personality touches to response"""
        # Add occasional personality flair
        if random.random() < 0.1:  # 10% chance
            prefixes = [
                "Certainly, sir. ",
                "Right away. ",
                "Of course. ",
                "Immediately, sir. ",
                "At once. "
            ]
            response = random.choice(prefixes) + response
        
        return response
    
    def add_to_history(self, role: str, content: str):
        """Add message to conversation history"""
        self.conversation_history.append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Keep only last 50 messages
        if len(self.conversation_history) > 50:
            self.conversation_history = self.conversation_history[-50:]

# Initialize personality engine
personality_engine = JarvisPersonalityEngine()

# ========== JARVIS ACTION EXECUTOR ==========
class JarvisActionExecutor:
    @staticmethod
    def parse_action_from_query(query: str, response: str, user_context: Dict = None) -> Optional[Dict]:
        """Parse actions from query and response"""
        query_lower = query.lower()
        
        # Extract action from response if marked
        if '[Action:' in response:
            action_match = re.search(r'\[Action:\s*(.*?)\]', response)
            if action_match:
                action_text = action_match.group(1).lower()
                
                # Map action text to action types
                action_map = {
                    'switch to clients': {'type': 'navigate', 'tab': 'clients'},
                    'switch to commands': {'type': 'navigate', 'tab': 'commands'},
                    'switch to python': {'type': 'navigate', 'tab': 'python'},
                    'switch to screenshots': {'type': 'navigate', 'tab': 'screenshots'},
                    'switch to recordings': {'type': 'navigate', 'tab': 'recordings'},
                    'switch to logs': {'type': 'navigate', 'tab': 'logs'},
                    'switch to chat': {'type': 'navigate', 'tab': 'chat'},
                    'execute screenshot': {'type': 'command', 'command': 'screenshot'},
                    'execute record_screen': {'type': 'command', 'command': 'record_screen'},
                    'execute live_screen': {'type': 'command', 'command': 'live_screen'},
                    'execute system_info': {'type': 'command', 'command': 'system_info'},
                    'refresh all': {'type': 'refresh', 'target': 'all'},
                    'refresh clients': {'type': 'refresh', 'target': 'clients'},
                    'check status': {'type': 'status', 'target': 'system'},
                }
                
                if action_text in action_map:
                    return action_map[action_text]
        
        # Fallback: determine action from query
        if any(word in query_lower for word in ['show', 'open', 'switch', 'view', 'display']):
            if 'client' in query_lower:
                return {'type': 'navigate', 'tab': 'clients'}
            elif 'command' in query_lower:
                return {'type': 'navigate', 'tab': 'commands'}
            elif 'python' in query_lower:
                return {'type': 'navigate', 'tab': 'python'}
            elif 'screenshot' in query_lower:
                return {'type': 'navigate', 'tab': 'screenshots'}
            elif any(word in query_lower for word in ['record', 'video']):
                return {'type': 'navigate', 'tab': 'recordings'}
            elif 'log' in query_lower:
                return {'type': 'navigate', 'tab': 'logs'}
            elif 'chat' in query_lower:
                return {'type': 'navigate', 'tab': 'chat'}
        
        elif any(word in query_lower for word in ['take', 'capture', 'grab']):
            if 'screenshot' in query_lower:
                return {'type': 'command', 'command': 'screenshot'}
        
        elif any(word in query_lower for word in ['record', 'start video']):
            if 'screen' in query_lower or 'record' in query_lower:
                return {'type': 'command', 'command': 'record_screen'}
        
        elif 'live' in query_lower or 'stream' in query_lower:
            return {'type': 'command', 'command': 'live_screen'}
        
        elif any(word in query_lower for word in ['refresh', 'update', 'reload']):
            return {'type': 'refresh', 'target': 'all'}
        
        elif 'status' in query_lower or 'health' in query_lower:
            return {'type': 'status', 'target': 'system'}
        
        return None

# ========== JARVIS WEBSITE CONTROLLER ==========
class JarvisWebsiteController:
    def __init__(self, token: str = None, user: Dict = None):
        self.token = token
        self.user = user
    
    async def execute_action(self, action: Dict) -> Dict:
        """Execute website action"""
        if not action:
            return {"success": False, "error": "No action specified"}
        
        action_type = action.get("type")
        
        actions = {
            'navigate': "Navigating to tab",
            'command': "Executing command",
            'refresh': "Refreshing data",
            'status': "Checking status"
        }
        
        description = actions.get(action_type, "Performing action")
        
        return {
            "success": True,
            "action": action,
            "description": description,
            "message": f"Action '{action_type}' queued for execution",
            "timestamp": datetime.utcnow().isoformat()
        }

# ========== STRUCTURED LOGGER ==========
class StructuredLogger:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def log_api_call(self, endpoint: str, user: str, status: str, details: dict = None):
        """Log API calls with structured data"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "endpoint": endpoint,
            "user": user,
            "status": status,
            "details": details or {}
        }
        self.logger.info(json.dumps(log_data))
    
    def log_command(self, command_id: str, client_id: str, command: str, user: str, status: str):
        """Log command execution"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "command",
            "command_id": command_id,
            "client_id": client_id,
            "command": command,
            "user": user,
            "status": status
        }
        self.logger.info(json.dumps(log_data))

# Initialize structured logger
structured_logger = StructuredLogger()

# ========== DATA MODELS ==========
class LoginRequest(BaseModel):
    email: str = Field(..., example="admin")
    password: str = Field(..., example="admin123")

class UserCreate(BaseModel):
    email: str = Field(..., example="newadmin")
    password: str = Field(..., example="password123")
    confirm_password: str = Field(..., example="password123")
    is_admin: bool = Field(default=True)
    theme: str = Field(default="red_black")

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
    client_id: str = Field(..., min_length=1, max_length=100)
    command: str = Field(..., min_length=1, max_length=100)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('command')
    def validate_command(cls, v):
        allowed_commands = ['screenshot', 'system_info', 'custom', 'restart', 
                           'shutdown', 'record_screen', 'live_screen']
        if v not in allowed_commands and not v.startswith('custom_'):
            raise ValueError(f'Command must be one of: {", ".join(allowed_commands)}')
        return v

class PythonExecutionRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    filename: str = Field(..., example="script.py")
    content: str = Field(..., description="Python code content")
    parameters: Optional[List[str]] = Field(default_factory=list)
    timeout: int = Field(default=30, description="Execution timeout in seconds")
    allow_imports: bool = Field(default=True, description="Allow importing modules")
    restricted_mode: bool = Field(default=True, description="Enable restricted execution mode")

class ScreenshotRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    image_data: str = Field(..., description="Base64 encoded image")
    filename: str = Field(..., example="screenshot.png")

class RecordingRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    video_data: str = Field(..., description="Base64 encoded video")
    filename: str = Field(..., example="recording.mp4")
    duration: int = Field(default=30)
    fps: int = Field(default=30)

class SystemInfoRequest(BaseModel):
    client_id: str = Field(..., example="client-001")
    info: Dict[str, Any] = Field(default_factory=dict)

class ChatMessage(BaseModel):
    message: str = Field(..., description="Message content")
    recipient: Optional[str] = Field(None, description="Recipient user ID (null for all)")

class JarvisChatRequest(BaseModel):
    message: str
    context: Optional[Dict] = None

class JarvisChatResponse(BaseModel):
    success: bool
    response: str
    action: Optional[Dict] = None
    model: str
    timestamp: str

# ========== AI PROCESSING FUNCTION ==========
async def process_with_local_ai(message: str, context: Dict = None) -> Dict:
    """Process message using local AI"""
    context = context or {}
    
    # Get response from local AI
    ai_response = local_ai.get_response(message, context)
    
    # Enhance with JARVIS personality
    enhanced_response = personality_engine.enhance_response(ai_response)
    
    # Add to history
    personality_engine.add_to_history("user", message)
    personality_engine.add_to_history("assistant", enhanced_response)
    
    # Determine if action needed
    action = JarvisActionExecutor.parse_action_from_query(message, enhanced_response, context)
    
    return {
        "success": True,
        "response": enhanced_response,
        "action": action,
        "model": "local_ai",
        "timestamp": datetime.utcnow().isoformat()
    }

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
    """Hash password using SHA256"""
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
        
        # Verify password
        hashed_input = hash_password(password)
        
        # Check stored hash or plain text (for compatibility)
        stored_password = user_data.get("password_hash") or user_data.get("password")
        
        if stored_password and (stored_password == hashed_input or stored_password == password):
            
            # Update last login
            supabase.table("users")\
                .update({"last_login": datetime.utcnow().isoformat()})\
                .eq("id", user_data["id"])\
                .execute()
            
            return {
                "id": user_data["id"],
                "email": user_data["email"],
                "is_admin": user_data.get("is_admin", False),
                "theme": user_data.get("theme", "red_black"),
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
            "password_hash": hash_password(user_data["password"]),
            "is_admin": user_data.get("is_admin", False),
            "theme": user_data.get("theme", "red_black"),
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
                "theme": response.data[0].get("theme", "red_black")
            }
    
    except Exception as e:
        logger.error(f"Create Supabase user error: {e}")
    
    return None

# ========== IN-MEMORY DATABASE ==========
class Database:
    def __init__(self):
        self.users = {}
        self.clients = {}
        self.commands = []
        self.logs = []
        self.sessions = {}
        self.chat_messages = []
        self.user_tags = {}
        self.screenshots = []
        self.recordings = []
        self.client_heartbeats = {}
        self.system_info = []
        self.init_default_data()
        self.init_user_tags()
    
    def init_default_data(self):
        # Default users with red/black theme
        default_users = [
            {
                "id": str(uuid.uuid4()),
                "email": "xotiic",
                "password": "40671Mps19*",
                "is_admin": True,
                "is_active": True,
                "theme": "red_black",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            },
            {
                "id": str(uuid.uuid4()),
                "email": "admin",
                "password": "admin123",
                "is_admin": True,
                "is_active": True,
                "theme": "red_black",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            },
            {
                "id": str(uuid.uuid4()),
                "email": "kizer",
                "password": "kidraper67",
                "is_admin": True,
                "is_active": True,
                "theme": "red_black",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            },
            {
                "id": str(uuid.uuid4()),
                "email": "nathan",
                "password": "femboy67",
                "is_admin": True,
                "is_active": True,
                "theme": "red_black",
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            }
        ]
        
        for user in default_users:
            self.users[user["email"].lower()] = user
        
        # Default client
        self.clients["default"] = {
            "id": str(uuid.uuid4()),
            "client_id": "default",
            "name": "Default Client",
            "ip_address": "127.0.0.1",
            "os_info": "Windows 11",
            "hardware_info": {},
            "online": False,
            "ws_online": False,
            "last_seen": datetime.utcnow().isoformat(),
            "registered_at": datetime.utcnow().isoformat()
        }
    
    def init_user_tags(self):
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
            "color": "#ff55ff",
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
    
    def add_screenshot(self, screenshot_data: dict):
        screenshot_id = str(uuid.uuid4())
        screenshot_data["id"] = screenshot_id
        screenshot_data["created_at"] = datetime.utcnow().isoformat()
        self.screenshots.append(screenshot_data)
        return screenshot_data
    
    def add_recording(self, recording_data: dict):
        recording_id = str(uuid.uuid4())
        recording_data["id"] = recording_id
        recording_data["created_at"] = datetime.utcnow().isoformat()
        self.recordings.append(recording_data)
        return recording_data
    
    def update_client_heartbeat(self, client_id: str):
        """Update client heartbeat timestamp"""
        self.client_heartbeats[client_id] = datetime.utcnow().timestamp()
    
    def is_client_alive(self, client_id: str, timeout: int = 60) -> bool:
        """Check if client is alive based on heartbeat"""
        last_heartbeat = self.client_heartbeats.get(client_id)
        if not last_heartbeat:
            return False
        return (datetime.utcnow().timestamp() - last_heartbeat) < timeout

# Initialize database
db = Database()

# ========== MEDIA HELPER FUNCTIONS ==========
def get_media_type(filename: str) -> str:
    """Get proper media type from filename"""
    ext = filename.lower().split('.')[-1]
    media_types = {
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'mp4': 'video/mp4',
        'webm': 'video/webm',
        'avi': 'video/x-msvideo',
        'mov': 'video/quicktime'
    }
    return media_types.get(ext, 'application/octet-stream')

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.client_connections: Dict[str, WebSocket] = {}
        self.admin_connections: List[WebSocket] = []
        self.chat_connections: Dict[str, WebSocket] = {}
        self.connection_times: Dict[str, float] = {}
        self.pending_messages: Dict[str, List[dict]] = {}
        self.active_recordings: Dict[str, bool] = {}
        self.active_streams: Dict[str, bool] = {}
        self.auto_screenshots: Dict[str, bool] = {}
        self.auto_recordings: Dict[str, bool] = {}

    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections.append(websocket)
        logger.info(f"👑 Admin connected. Total admins: {len(self.admin_connections)}")

    async def connect_client(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.client_connections[client_id] = websocket
        self.connection_times[client_id] = time.time()
        logger.info(f"🖥️  Client connected: {client_id}. Total clients: {len(self.client_connections)}")
        
        # Update client status
        if client_id in db.clients:
            db.clients[client_id]["online"] = True
            db.clients[client_id]["ws_online"] = True
            db.clients[client_id]["last_seen"] = datetime.utcnow().isoformat()
        
        # Store in Supabase
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
        
        # Send pending messages if any
        if client_id in self.pending_messages:
            for msg in self.pending_messages[client_id]:
                await self.send_to_client(client_id, msg)
            del self.pending_messages[client_id]
        
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
        
        # Notify others
        await self.broadcast_chat({
            "type": "user_online",
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat()
        }, exclude_user=user_id)
        
        # Send initial data
        await self.send_chat_history(user_id)
        await self.send_user_list(user_id)
    
    async def send_chat_history(self, user_id: str):
        """Send chat history to user"""
        if user_id in self.chat_connections:
            try:
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
                            "color": tag["color"] if tag else "#ff2a2a",
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
            # Stop any active features
            self.stop_streaming(client_id)
            self.stop_auto_screenshots(client_id)
            self.stop_auto_recordings(client_id)
            
            del self.client_connections[client_id]
            if client_id in self.connection_times:
                del self.connection_times[client_id]
            
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
            
            # Notify others
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
                # Store message for later delivery
                if client_id not in self.pending_messages:
                    self.pending_messages[client_id] = []
                self.pending_messages[client_id].append(message)
                return False
        
        # Client not connected, store message
        if client_id not in self.pending_messages:
            self.pending_messages[client_id] = []
        self.pending_messages[client_id].append(message)
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
    
    def start_recording(self, client_id: str):
        """Mark client as recording"""
        self.active_recordings[client_id] = True
    
    def stop_recording(self, client_id: str):
        """Stop recording on client"""
        self.active_recordings.pop(client_id, None)
    
    def is_recording(self, client_id: str) -> bool:
        """Check if client is recording"""
        return self.active_recordings.get(client_id, False)
    
    def start_streaming(self, client_id: str):
        """Mark client as streaming"""
        self.active_streams[client_id] = True
    
    def stop_streaming(self, client_id: str):
        """Stop streaming on client"""
        self.active_streams.pop(client_id, None)
    
    def is_streaming(self, client_id: str) -> bool:
        """Check if client is streaming"""
        return self.active_streams.get(client_id, False)
    
    def start_auto_screenshots(self, client_id: str):
        """Mark client as auto-screenshotting"""
        self.auto_screenshots[client_id] = True
    
    def stop_auto_screenshots(self, client_id: str):
        """Stop auto screenshots on client"""
        self.auto_screenshots.pop(client_id, None)
    
    def is_auto_screenshots(self, client_id: str) -> bool:
        """Check if client is auto-screenshotting"""
        return self.auto_screenshots.get(client_id, False)
    
    def start_auto_recordings(self, client_id: str):
        """Mark client as auto-recording"""
        self.auto_recordings[client_id] = True
    
    def stop_auto_recordings(self, client_id: str):
        """Stop auto recordings on client"""
        self.auto_recordings.pop(client_id, None)
    
    def is_auto_recordings(self, client_id: str) -> bool:
        """Check if client is auto-recording"""
        return self.auto_recordings.get(client_id, False)

manager = ConnectionManager()

# ========== CORE API ROUTES ==========
@app.get("/")
async def root():
    return {
        "message": "ANALCONTROL v4.0 API with J.A.R.V.I.S. AI", 
        "status": "online",
        "ai": "FREE Local AI - NO API KEYS REQUIRED",
        "version": "4.0"
    }

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "api": "online",
            "ai": "online (local)",
            "database": "online" if supabase else "offline"
        },
        "ai_info": {
            "provider": "local_patterns",
            "patterns_loaded": len(local_ai.patterns),
            "free": True,
            "requires_api_key": False
        }
    }

@app.post("/api/login")
async def login(request: LoginRequest):
    """Simple login for demo - in production, use proper auth"""
    try:
        logger.info(f"Login attempt for user: {request.email}")
        
        user_data = None
        
        # Try Supabase first
        if supabase:
            user_data = await verify_supabase_user(request.email, request.password)
        
        # Fallback to in-memory database
        if not user_data:
            user = db.get_user_by_email(request.email)
            
            if not user:
                logger.warning(f"User not found: {request.email}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            if not user.get("is_active", True):
                logger.warning(f"User account inactive: {request.email}")
                raise HTTPException(status_code=401, detail="Account is inactive")
            
            if user.get("password") != request.password:
                logger.warning(f"Password verification failed for user: {request.email}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            user_data = {
                "id": user["id"],
                "email": user["email"],
                "is_admin": user.get("is_admin", False),
                "theme": user.get("theme", "red_black"),
                "is_active": user.get("is_active", True)
            }
            
            db.update_user_last_login(request.email)
        
        logger.info(f"✅ User authenticated: {user_data.get('email')}")
        
        # Create JWT token
        token_data = {
            "sub": user_data["email"],
            "email": user_data["email"],
            "is_admin": user_data["is_admin"],
            "user_id": user_data["id"],
            "theme": user_data.get("theme", "red_black")
        }
        
        access_token = create_jwt_token(token_data)
        
        return {
            "success": True,
            "token": access_token,
            "user": {
                "email": user_data["email"],
                "is_admin": user_data["is_admin"],
                "user_id": user_data["id"],
                "theme": user_data.get("theme", "red_black")
            },
            "expires_in": 86400
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========== JARVIS AI ENDPOINTS ==========
@app.post("/api/jarvis/chat", response_model=JarvisChatResponse)
async def jarvis_chat(request: JarvisChatRequest, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Chat with J.A.R.V.I.S. using FREE local AI - NO API KEYS NEEDED"""
    try:
        # Verify token
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        
        user_email = payload.get("email", "user")
        
        logger.info(f"JARVIS chat from {user_email}: {request.message[:50]}...")
        
        # Build context
        user_context = {
            "user_id": payload.get("user_id"),
            "email": user_email,
            "is_admin": payload.get("is_admin", False),
            "current_tab": request.context.get("current_tab", "dashboard") if request.context else "dashboard"
        }
        
        # Process with local AI (FREE - NO API KEYS)
        result = await process_with_local_ai(request.message, user_context)
        
        # Log interaction
        structured_logger.log_api_call(
            "/api/jarvis/chat",
            user_email,
            "success",
            {"message_length": len(request.message), "has_action": result.get("action") is not None}
        )
        
        return JarvisChatResponse(**result)
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"JARVIS error: {e}")
        raise HTTPException(status_code=500, detail=f"AI processing error: {str(e)}")

@app.post("/api/jarvis/execute-action")
async def jarvis_execute_action(action: Dict, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Execute JARVIS action"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        
        user_email = payload.get("email")
        
        controller = JarvisWebsiteController(token=token, user=payload)
        result = await controller.execute_action(action)
        
        logger.info(f"JARVIS action by {user_email}: {action.get('type')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Action error: {e}")
        return {"success": False, "error": str(e)}

@app.get("/api/jarvis/system-status")
async def jarvis_system_status(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get JARVIS system status"""
    try:
        payload = verify_jwt_token(credentials.credentials)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return {
            "success": True,
            "status": {
                "jarvis": "online",
                "ai_model": "local_ai (FREE)",
                "personality_engine": "active",
                "website_knowledge": "complete",
                "conversation_history": len(personality_engine.conversation_history),
                "local_ai_patterns": len(local_ai.patterns),
                "requires_api_key": False,
                "cost": "$0.00"
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/jarvis/reset-conversation")
async def jarvis_reset_conversation(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Reset conversation history"""
    try:
        payload = verify_jwt_token(credentials.credentials)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        personality_engine.conversation_history = []
        
        return {
            "success": True,
            "message": "Conversation history reset"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/jarvis/get-suggestions")
async def jarvis_get_suggestions(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get contextual suggestions"""
    try:
        payload = verify_jwt_token(credentials.credentials)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        suggestions = [
            {"text": "Show connected clients", "action": {"type": "navigate", "tab": "clients"}},
            {"text": "Take a screenshot", "action": {"type": "command", "command": "screenshot"}},
            {"text": "Open Python tab", "action": {"type": "navigate", "tab": "python"}},
            {"text": "Check system status", "action": {"type": "status", "target": "system"}},
            {"text": "Refresh dashboard", "action": {"type": "refresh", "target": "all"}},
            {"text": "Open chat", "action": {"type": "navigate", "tab": "chat"}}
        ]
        
        return {
            "success": True,
            "suggestions": suggestions
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/jarvis/ai-config")
async def get_ai_config():
    """Get AI configuration - Shows FREE local AI details"""
    return {
        "success": True,
        "config": {
            "ai_provider": "local_patterns",
            "free": True,
            "patterns_loaded": len(local_ai.patterns),
            "requires_api_key": False,
            "offline_capable": True,
            "cost_per_request": "$0.00",
            "features": [
                "Website navigation",
                "Command execution",
                "System monitoring",
                "Chat control",
                "Data management"
            ]
        }
    }

# ========== CLIENT MANAGEMENT ENDPOINTS ==========
@app.post("/api/create-account", response_model=dict)
async def create_account(data: UserCreate, user: dict = Depends(authenticate_user)):
    """Create a new user account"""
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
                "theme": user_data.get("theme", "red_black"),
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
        
        # Check for duplicate by name
        existing_client = None
        for client_id, client in db.clients.items():
            if client.get("name") == data.name:
                existing_client = client
                break
        
        if existing_client:
            logger.info(f"⚠️  Client with name '{data.name}' already exists. Updating instead.")
            data.client_id = existing_client.get("client_id", data.client_id)
            action = "updated"
        else:
            action = "registered"
        
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
        
        # Add streaming status
        for client in clients_list:
            client_id = client.get("client_id")
            client["is_streaming"] = manager.is_streaming(client_id)
            client["is_auto_screenshots"] = manager.is_auto_screenshots(client_id)
            client["is_auto_recordings"] = manager.is_auto_recordings(client_id)
        
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
        structured_logger.log_api_call("/api/command", user.get("email"), "started", {
            "client_id": data.client_id,
            "command": data.command
        })
        
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
        
        # Send via WebSocket
        sent = await manager.send_to_client(data.client_id, {
            "type": "command",
            "command_id": command_id,
            "command": data.command,
            "parameters": data.parameters,
            "timestamp": datetime.utcnow().isoformat(),
            "from_user": user.get("email", "unknown")
        })
        
        if sent:
            structured_logger.log_command(command_id, data.client_id, data.command, user.get("email"), "sent")
        else:
            structured_logger.log_command(command_id, data.client_id, data.command, user.get("email"), "queued")
        
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

@app.get("/api/commands", response_model=dict)
async def get_commands(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000)
):
    """Get recent commands"""
    try:
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
            "client_id": data.client_id,
            "filename": data.filename,
            "image_data": data.image_data,
            "size": len(image_data),
            "created_at": datetime.utcnow().isoformat()
        }
        
        db.add_screenshot(screenshot_data)
        
        # Notify admins
        await manager.notify_admins({
            "type": "screenshot_received",
            "client_id": data.client_id,
            "filename": data.filename,
            "size": len(image_data),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {
            "success": True,
            "message": "Screenshot uploaded",
            "filename": data.filename,
            "size": len(image_data)
        }
        
    except Exception as e:
        logger.error(f"Upload screenshot error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/screenshots", response_model=dict)
async def get_screenshots(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000)
):
    """Get all screenshots"""
    try:
        screenshots_list = db.screenshots.copy()
        
        # Apply filters
        if client_id:
            screenshots_list = [s for s in screenshots_list if s.get("client_id") == client_id]
        
        # Sort by date
        screenshots_list.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        screenshots_list = screenshots_list[:limit]
        
        return {
            "success": True,
            "screenshots": screenshots_list
        }
    except Exception as e:
        logger.error(f"Get screenshots error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/recordings", response_model=dict)
async def get_recordings(
    user: dict = Depends(authenticate_user),
    client_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000)
):
    """Get all screen recordings"""
    try:
        recordings_list = db.recordings.copy()
        
        # Apply filters
        if client_id:
            recordings_list = [r for r in recordings_list if r.get("client_id") == client_id]
        
        # Sort by date
        recordings_list.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        recordings_list = recordings_list[:limit]
        
        return {
            "success": True,
            "recordings": recordings_list
        }
    except Exception as e:
        logger.error(f"Get recordings error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/stats", response_model=dict)
async def get_stats(user: dict = Depends(authenticate_user)):
    """Get system statistics"""
    try:
        stats = {
            "total_clients": len(db.clients),
            "online_clients": len([c for c in db.clients.values() if c.get("online")]),
            "ws_online_clients": len(manager.client_connections),
            "pending_commands": len([c for c in db.commands if c.get("status") in ["pending", "running"]]),
            "total_commands": len(db.commands),
            "today_logs": len([l for l in db.logs if l.get("created_at", "").startswith(datetime.utcnow().date().isoformat())]),
            "total_screenshots": len(db.screenshots),
            "total_recordings": len(db.recordings),
            "total_users": len(db.users),
            "active_admins": len(manager.admin_connections),
            "chat_users": len(manager.chat_connections),
            "active_recordings": len(manager.active_recordings),
            "active_streams": len(manager.active_streams),
            "auto_screenshots": len(manager.auto_screenshots),
            "auto_recordings": len(manager.auto_recordings)
        }
        
        return {
            "success": True,
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/client/heartbeat", response_model=dict)
async def client_heartbeat(data: dict):
    """Receive heartbeat from client"""
    try:
        client_id = data.get("client_id")
        if not client_id:
            return {"success": False, "error": "Client ID required"}
        
        # Update heartbeat timestamp
        db.update_client_heartbeat(client_id)
        
        # Update client last_seen
        if client_id in db.clients:
            db.clients[client_id]["last_seen"] = datetime.utcnow().isoformat()
            db.clients[client_id]["online"] = True
        
        # Check if client has pending messages
        if client_id in manager.pending_messages and manager.pending_messages[client_id]:
            return {
                "success": True,
                "has_pending_messages": True,
                "message_count": len(manager.pending_messages[client_id])
            }
        
        return {"success": True, "has_pending_messages": False}
        
    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        return {"success": False, "error": str(e)}

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
            "server_time": datetime.utcnow().isoformat(),
            "client_id": client_id
        })
        
        while True:
            try:
                data = await websocket.receive_json()
                message_type = data.get("type")
                
                if message_type == "heartbeat":
                    db.update_client_heartbeat(client_id)
                    await websocket.send_json({
                        "type": "heartbeat_response",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
                elif message_type == "command_result":
                    command_id = data.get("command_id")
                    for cmd in db.commands:
                        if cmd["id"] == command_id:
                            cmd["status"] = "completed"
                            cmd["result"] = data.get("result")
                            cmd["completed_at"] = datetime.utcnow().isoformat()
                            break
                    
                    await manager.notify_admins({
                        "type": "command_result",
                        "client_id": client_id,
                        "command_id": command_id,
                        "result": data.get("result"),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
                elif message_type == "screenshot_result":
                    image_data = data.get("image_data")
                    filename = data.get("filename", f"screenshot_{client_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png")
                    
                    if image_data:
                        screenshot_data = {
                            "client_id": client_id,
                            "filename": filename,
                            "image_data": image_data,
                            "size": len(base64.b64decode(image_data)),
                            "created_at": datetime.utcnow().isoformat()
                        }
                        
                        db.add_screenshot(screenshot_data)
                        
                        await manager.notify_admins({
                            "type": "screenshot_received",
                            "client_id": client_id,
                            "filename": filename,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error processing message from {client_id}: {e}")
                continue
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Client WebSocket error: {e}")
    finally:
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
def print_startup_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ░J░A░R░V░I░S░  ANALCONTROL v4.0  -  UNIFIED BACKEND     ║
║                                                              ║
║        Just A Rather Very Intelligent System                 ║
║                                                              ║
║        🆓 100% FREE LOCAL AI • NO API KEYS REQUIRED         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

🤖 J.A.R.V.I.S. initializing with FREE local AI...
    """
    print(banner)
    
    print("\n📋 Configuration:")
    print(f"   • AI Provider: Local Pattern Matching (FREE)")
    print(f"   • Patterns Loaded: {len(local_ai.patterns)}")
    print(f"   • Personality Engine: ✅ Active")
    print(f"   • Website Knowledge: ✅ Complete")
    print(f"   • API Key Required: ❌ NO - 100% Free")
    print(f"   • Internet Required: ❌ NO - Works offline")
    print(f"   • Cost Per Request: $0.00")
    
    print("\n🏗️  Capabilities:")
    print("   1. Complete website navigation (7 tabs)")
    print("   2. Command execution on clients")
    print("   3. Screenshot and recording control")
    print("   4. System monitoring and status")
    print("   5. Chat and communication")
    print("   6. Python script execution")
    print("   7. Data management and refresh")
    
    print("\n🌐 API Endpoints:")
    print("   • POST   /api/jarvis/chat              - Chat with JARVIS (FREE AI)")
    print("   • GET    /api/jarvis/ai-config         - Show AI configuration")
    print("   • POST   /api/jarvis/execute-action    - Execute website actions")
    print("   • GET    /api/jarvis/system-status     - Get system status")
    print("   • POST   /api/login                    - User authentication")
    print("   • GET    /api/clients                  - Get all clients")
    print("   • POST   /api/command                  - Send commands")
    
    print("\n🚀 Try these commands:")
    print("   • 'Show me connected clients'")
    print("   • 'Take a screenshot'")
    print("   • 'Open Python tab'")
    print("   • 'Check system status'")
    print("   • 'What can you do?'")
    
    print("\n✅ System ready! No API keys needed - 100% FREE AI!")
    print("   Total AI Patterns: " + str(len(local_ai.patterns)))
    print("   Memory Usage: Minimal")
    print("   Cost: $0.00\n")

@app.on_event("startup")
async def startup_event():
    print_startup_banner()

# ========== MAIN ==========
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info"
    )
