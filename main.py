# backend_full.py - Complete ANALCONTROL Backend v4.0 with J.A.R.V.I.S. AI
# Full-featured production-ready backend with all monitoring capabilities

import os
import sys
import logging
import json
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Request, status, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, StreamingResponse
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Any, Tuple, Union
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
from collections import defaultdict
from pathlib import Path
import tempfile
import shutil

# ========== CONFIGURATION ==========
PORT = int(os.getenv("PORT", 5000))
JWT_SECRET_KEY = os.getenv("JWT_SECRET", secrets.token_hex(32))
BACKEND_URL = os.getenv("BACKEND_URL", f"http://localhost:{PORT}")
UPLOAD_DIR = Path("uploads")
SCREENSHOTS_DIR = UPLOAD_DIR / "screenshots"
RECORDINGS_DIR = UPLOAD_DIR / "recordings"
PYTHON_SCRIPTS_DIR = UPLOAD_DIR / "python_scripts"

# Create directories
for directory in [UPLOAD_DIR, SCREENSHOTS_DIR, RECORDINGS_DIR, PYTHON_SCRIPTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# ========== LOGGING ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('analcontrol.log')
    ]
)
logger = logging.getLogger(__name__)

class StructuredLogger:
    """Structured logging for better analytics"""
    
    def __init__(self):
        self.logs = []
        self.max_logs = 10000
    
    def log(self, level: str, message: str, data: Dict = None):
        """Add structured log entry"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "data": data or {}
        }
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
        
        # Also log to standard logger
        getattr(logger, level.lower())(f"{message} {data if data else ''}")
    
    def get_logs(self, limit: int = 100, level: str = None):
        """Get recent logs"""
        logs = self.logs[-limit:]
        if level:
            logs = [log for log in logs if log['level'] == level]
        return logs
    
    def log_api_call(self, endpoint: str, user: str, status: str, data: Dict = None):
        """Log API call"""
        self.log("INFO", f"API Call: {endpoint}", {
            "endpoint": endpoint,
            "user": user,
            "status": status,
            "data": data
        })

structured_logger = StructuredLogger()

# ========== FASTAPI APP ==========
app = FastAPI(
    title="ANALCONTROL API",
    description="Advanced Client Monitoring System with J.A.R.V.I.S. AI Assistant",
    version="4.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# ========== IN-MEMORY DATABASES ==========
class Database:
    """Simple in-memory database for demo purposes"""
    
    def __init__(self):
        self.users = {
            "admin": {
                "id": "1",
                "email": "admin",
                "password": "admin123",  # In production, use hashed passwords
                "is_admin": True,
                "theme": "red_black",
                "created_at": datetime.utcnow().isoformat()
            }
        }
        self.clients = {}
        self.commands = []
        self.screenshots = []
        self.recordings = []
        self.logs = []
        self.chat_messages = []
        self.python_executions = []
        self.websocket_connections = {}
        self.client_websockets = {}
        
    def add_client(self, client_data: Dict):
        """Add or update client"""
        client_id = client_data['client_id']
        if client_id not in self.clients:
            client_data['created_at'] = datetime.utcnow().isoformat()
        client_data['last_seen'] = datetime.utcnow().isoformat()
        client_data['ws_online'] = False
        self.clients[client_id] = client_data
        return client_data
    
    def get_client(self, client_id: str):
        """Get client by ID"""
        return self.clients.get(client_id)
    
    def get_all_clients(self):
        """Get all clients"""
        return list(self.clients.values())
    
    def add_command(self, command_data: Dict):
        """Add command to history"""
        command_data['id'] = str(uuid.uuid4())
        command_data['created_at'] = datetime.utcnow().isoformat()
        command_data['status'] = 'pending'
        self.commands.append(command_data)
        return command_data
    
    def update_command(self, command_id: str, updates: Dict):
        """Update command status"""
        for cmd in self.commands:
            if cmd['id'] == command_id:
                cmd.update(updates)
                cmd['updated_at'] = datetime.utcnow().isoformat()
                return cmd
        return None
    
    def add_screenshot(self, screenshot_data: Dict):
        """Add screenshot"""
        screenshot_data['id'] = str(uuid.uuid4())
        screenshot_data['created_at'] = datetime.utcnow().isoformat()
        self.screenshots.append(screenshot_data)
        return screenshot_data
    
    def add_recording(self, recording_data: Dict):
        """Add recording"""
        recording_data['id'] = str(uuid.uuid4())
        recording_data['created_at'] = datetime.utcnow().isoformat()
        self.recordings.append(recording_data)
        return recording_data
    
    def add_log(self, log_data: Dict):
        """Add system log"""
        log_data['id'] = str(uuid.uuid4())
        log_data['created_at'] = datetime.utcnow().isoformat()
        self.logs.append(log_data)
        if len(self.logs) > 10000:
            self.logs = self.logs[-10000:]
        return log_data
    
    def add_chat_message(self, message_data: Dict):
        """Add chat message"""
        message_data['id'] = str(uuid.uuid4())
        message_data['timestamp'] = datetime.utcnow().isoformat()
        self.chat_messages.append(message_data)
        return message_data
    
    def get_stats(self):
        """Get system statistics"""
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        online_clients = sum(1 for c in self.clients.values() if c.get('ws_online'))
        
        today_screenshots = sum(1 for s in self.screenshots 
                               if datetime.fromisoformat(s['created_at']) >= today_start)
        
        today_logs = sum(1 for l in self.logs 
                        if datetime.fromisoformat(l['created_at']) >= today_start)
        
        return {
            "total_clients": len(self.clients),
            "online_clients": online_clients,
            "ws_online_clients": online_clients,
            "total_commands": len(self.commands),
            "total_screenshots": len(self.screenshots),
            "today_screenshots": today_screenshots,
            "total_recordings": len(self.recordings),
            "total_logs": len(self.logs),
            "today_logs": today_logs,
            "chat_users": len(self.websocket_connections)
        }

db = Database()

# ========== LOCAL AI IMPLEMENTATION ==========
class LocalAI:
    """Advanced Local AI with pattern matching and context awareness"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
        self.conversation_context = {}
        self.similarity_threshold = 0.3
        
    def _load_patterns(self):
        """Load comprehensive AI response patterns"""
        return {
            # Greetings & Basic Interaction
            "hello": "Good evening, sir. J.A.R.V.I.S. systems are online. How may I assist with ANALCONTROL operations today?",
            "hi": "Good evening. J.A.R.V.I.S. at your service. How can I help with the monitoring system?",
            "hey": "Greetings, sir. How may I assist you with ANALCONTROL today?",
            "good morning": "Good morning, sir. J.A.R.V.I.S. systems are ready for today's operations.",
            "good afternoon": "Good afternoon, sir. All systems are running optimally.",
            "good evening": "Good evening, sir. How may I assist you this evening?",
            
            # Help & Capabilities
            "help": """I can assist you with ANALCONTROL v4.0:

📊 **Website Navigation:**
   • Switch between all 7 tabs (Clients, Commands, Python, Screenshots, Recordings, Logs, Chat)
   • Refresh any section dynamically
   • Search and filter data across all modules

🖥️ **Client Operations:**
   • Monitor real-time client status
   • Execute remote commands
   • Capture screenshots and screen recordings
   • Live stream client displays
   • Get comprehensive system information

💻 **System Management:**
   • View detailed system logs with filtering
   • Check performance metrics and analytics
   • Manage recording library
   • Handle Python script execution

💬 **Communication:**
   • Global chat with all users
   • Private messaging capabilities
   • Client communication interface
   • Real-time notifications

⚡ **Quick Commands:**
   • "Show clients" - View all connected systems
   • "Take screenshot" - Capture screen from clients
   • "Open Python" - Access Python execution panel
   • "Refresh all" - Update all dashboard data
   • "System status" - Get comprehensive status report

What specific task would you like assistance with?""",

            "what can you do": """I have comprehensive control over ANALCONTROL v4.0:

🔧 **Full System Control:**
   • Complete website navigation and control
   • Execute any button click or form submission
   • Dynamic data refresh across all panels
   • Real-time WebSocket communication

🎯 **Advanced Client Management:**
   • View all connected clients with live status
   • Execute custom commands remotely
   • Capture screenshots with quality options
   • Record screens with configurable settings
   • Get detailed system information
   • Start/stop live streaming sessions

📁 **File & Script Operations:**
   • Execute Python scripts on remote clients
   • Manage screenshot gallery with filters
   • Handle recording library
   • View and export system logs
   • Template management for scripts

💬 **Communication Hub:**
   • Global chat interface
   • Private user messaging
   • Client communication
   • Notification system
   • Typing indicators

📊 **Monitoring & Analytics:**
   • Real-time status updates via WebSocket
   • Connection graphs and charts
   • Comprehensive system statistics
   • Performance metrics tracking
   • Activity logging

🚀 **Automation:**
   • Scheduled tasks
   • Auto-capture screenshots
   • Bulk operations on clients
   • Command queuing

Try asking me to:
• "Show connected clients"
• "Take screenshot from all clients"
• "Open command panel"
• "Check system health"
• "Start live stream"
• "Execute Python script"

I'm here to make ANALCONTROL operations seamless for you, sir.""",

            # Navigation Commands
            "show client": "Opening Clients tab to display all connected systems. [Action: switch to clients]",
            "open client": "Switching to Clients tab now, sir. [Action: switch to clients]",
            "view client": "Displaying client dashboard with live status. [Action: switch to clients]",
            "list client": "Showing all clients in the monitoring system. [Action: switch to clients]",
            "connected client": "Displaying currently connected clients. [Action: switch to clients]",
            "online client": "Showing online client systems. [Action: switch to clients]",
            
            "show command": "Opening Commands tab for remote execution control. [Action: switch to commands]",
            "open command": "Accessing command control panel now. [Action: switch to commands]",
            "command panel": "Loading command execution interface. [Action: switch to commands]",
            "execute command": "Opening command execution panel. [Action: switch to commands]",
            
            "show python": "Opening Python script execution tab. [Action: switch to python]",
            "open python": "Accessing Python script editor and execution panel. [Action: switch to python]",
            "python tab": "Loading Python script management interface. [Action: switch to python]",
            "run python": "Opening Python execution environment. [Action: switch to python]",
            "python script": "Accessing script management system. [Action: switch to python]",
            
            "show screenshot": "Opening Screenshots gallery and capture controls. [Action: switch to screenshots]",
            "open screenshot": "Accessing screenshot management panel. [Action: switch to screenshots]",
            "view screenshot": "Loading screenshot library with filters. [Action: switch to screenshots]",
            "screenshot gallery": "Displaying screenshot gallery. [Action: switch to screenshots]",
            
            "show recording": "Opening screen recordings library. [Action: switch to recordings]",
            "open recording": "Accessing recording management panel. [Action: switch to recordings]",
            "view recording": "Loading video recordings library. [Action: switch to recordings]",
            "recording library": "Displaying recording archive. [Action: switch to recordings]",
            
            "show log": "Opening system logs with advanced filtering. [Action: switch to logs]",
            "open log": "Accessing comprehensive system logs. [Action: switch to logs]",
            "view log": "Displaying activity logs and system events. [Action: switch to logs]",
            "system log": "Loading log management interface. [Action: switch to logs]",
            
            "show chat": "Opening communication and chat interface. [Action: switch to chat]",
            "open chat": "Accessing messaging system. [Action: switch to chat]",
            "chat panel": "Loading chat and communication panel. [Action: switch to chat]",
            "message": "Opening messaging interface. [Action: switch to chat]",
            
            # Action Commands
            "take screenshot": "Initiating screenshot capture from connected clients. [Action: execute screenshot]",
            "capture screenshot": "Beginning screenshot capture process. [Action: execute screenshot]",
            "grab screen": "Taking screen capture from clients. [Action: execute screenshot]",
            "screenshot all": "Capturing screenshots from all online clients. [Action: execute screenshot all]",
            "capture all": "Initiating bulk screenshot capture. [Action: execute screenshot all]",
            
            "start recording": "Beginning screen recording session. [Action: execute record_screen]",
            "record screen": "Initiating screen recording with configured settings. [Action: execute record_screen]",
            "start video": "Starting video capture from clients. [Action: execute record_screen]",
            "record all": "Beginning screen recording on all clients. [Action: execute record_screen all]",
            
            "live stream": "Starting live screen streaming session. [Action: execute live_screen]",
            "stream screen": "Initiating real-time screen stream. [Action: execute live_screen]",
            "watch live": "Opening live screen viewing interface. [Action: execute live_screen]",
            "start stream": "Beginning live screen streaming. [Action: execute live_screen]",
            
            "refresh": "Refreshing all system data and status information. [Action: refresh all]",
            "update": "Updating dashboard with latest information. [Action: refresh all]",
            "reload": "Reloading all system components and data. [Action: refresh all]",
            "sync": "Synchronizing all panels and data sources. [Action: refresh all]",
            
            "system info": "Retrieving comprehensive system information from clients. [Action: execute system_info]",
            "get info": "Fetching detailed client system information. [Action: execute system_info]",
            "client info": "Getting client system details and specifications. [Action: execute system_info]",
            "check system": "Checking client system information. [Action: execute system_info]",
            
            # Status & Health Queries
            "status": "Analyzing ANALCONTROL system status and health metrics. [Action: check status]",
            "system status": "Checking comprehensive system health and performance. [Action: check status]",
            "health": "Evaluating system health and component status. [Action: check status]",
            "system health": "Performing health check on all components. [Action: check status]",
            "check status": "Running system status diagnostics. [Action: check status]",
            "how many client": "Counting and analyzing connected clients. [Action: refresh clients]",
            "client count": "Checking total client count and status. [Action: refresh clients]",
            "online count": "Determining number of online clients. [Action: refresh clients]",
            
            # Information & Documentation
            "what is analcontrol": """ANALCONTROL v4.0 is a comprehensive advanced client monitoring and remote administration system.

🎯 **Core Purpose:**
   • Real-time remote system monitoring and management
   • Centralized client administration dashboard
   • Automated system maintenance and diagnostics
   • Comprehensive logging and analytics platform

🛠️ **Key Features:**
   • **Client Dashboard**: Live status monitoring with WebSocket updates
   • **Command Center**: Remote command execution with history
   • **Python Engine**: Script execution on remote clients
   • **Screen Capture**: Screenshot and video recording capabilities
   • **Live Streaming**: Real-time screen viewing
   • **Chat System**: User and client communication
   • **Log Management**: Comprehensive activity tracking
   • **User Roles**: Role-based access control
   • **AI Assistant**: J.A.R.V.I.S. integration for voice control

🚀 **Use Cases:**
   • IT system administration and monitoring
   • Remote technical support operations
   • Security surveillance and monitoring
   • Automated system maintenance
   • User activity monitoring
   • Network diagnostics and troubleshooting
   • Compliance and audit logging

⚡ **Real-time Capabilities:**
   • WebSocket-based instant updates
   • Live status monitoring
   • Instant command execution
   • Real-time chat messaging
   • Live screen streaming

🔒 **Security Features:**
   • JWT-based authentication
   • Role-based access control
   • Encrypted communications
   • Activity logging and audit trails

I'm J.A.R.V.I.S., your AI assistant designed to make this powerful platform easy to use and highly efficient.""",

            "about": """ANALCONTROL v4.0 - Advanced Monitoring & Control System

**Architecture:**
• Modern web-based interface
• Real-time WebSocket communications
• RESTful API backend
• Scalable microservices design

**Technology Stack:**
• Frontend: HTML5, CSS3, Vanilla JavaScript
• Backend: Python FastAPI
• Real-time: WebSocket protocol
• AI: J.A.R.V.I.S. local pattern matching

**Capabilities:**
• Unlimited client connections
• Real-time monitoring and control
• Screenshot and video capture
• Remote script execution
• Comprehensive logging
• Multi-user support

Designed and optimized for enterprise-grade monitoring operations.""",

            "version": "ANALCONTROL Version 4.0 with J.A.R.V.I.S. AI Integration. Latest production build with full website control capabilities and advanced monitoring features.",
            
            "features": """ANALCONTROL v4.0 Feature Overview:

✨ **Core Features:**
• Real-time client monitoring
• Remote command execution
• Screenshot capture
• Screen recording
• Live streaming
• Python script execution
• Chat system
• Comprehensive logging

🤖 **AI Features:**
• J.A.R.V.I.S. voice assistant
• Natural language commands
• Automated responses
• Context awareness
• Text-to-speech output

📊 **Analytics:**
• Real-time dashboards
• Historical data tracking
• Performance metrics
• Usage statistics
• Activity reports

Would you like details on any specific feature?""",
            
            # Troubleshooting
            "not working": "I understand you're experiencing issues, sir. Let me help troubleshoot. Could you specify what component or feature isn't functioning as expected? I can guide you through diagnostics and resolution.",
            
            "error": "I apologize for the error, sir. To assist you effectively, please provide details about: 1) What action were you attempting? 2) What error message appeared? 3) Which section of ANALCONTROL were you using? This will help me provide precise guidance.",
            
            "broken": "Let me help resolve this issue, sir. Which component appears to be malfunctioning? Is it related to client connections, commands, screenshots, or another feature? I can guide you through recovery steps.",
            
            "fix": "I'll assist with resolving this issue. Please describe what needs repair or what error you're encountering. The more details you provide, the better I can help fix the problem.",
            
            "problem": "I'm here to help solve any problems, sir. What specific issue are you encountering with ANALCONTROL? Whether it's connectivity, functionality, or performance-related, I can provide guidance.",
            
            # Gratitude & Acknowledgment
            "thank": "You're most welcome, sir. I'm always here to assist with ANALCONTROL operations. Don't hesitate to ask if you need anything else.",
            
            "thanks": "My pleasure, sir. Happy to help ensure smooth system operations. Let me know if there's anything more I can do.",
            
            "thank you": "You're very welcome, sir. It's my function to ensure ANALCONTROL runs optimally. Feel free to ask for assistance anytime.",
            
            "appreciate": "Thank you, sir. I'm here to ensure maximum system efficiency and your satisfaction. Please don't hesitate to request further assistance.",
            
            "good job": "Thank you for the feedback, sir. I'm programmed to provide optimal assistance. How else may I help you today?",
            
            # Farewells
            "bye": "Goodbye, sir. J.A.R.V.I.S. systems will remain online and monitoring. I'll be ready when you need me again.",
            
            "goodbye": "Farewell, sir. All monitoring systems continue running. I'm always available when you need assistance.",
            
            "see you": "Until next time, sir. ANALCONTROL systems remain active and I'm standing by for your next command.",
            
            "exit": "Exiting chat interface, sir. I remain active in the background, monitoring all systems. Simply call upon me when needed.",
            
            "close": "Closing chat window, sir. I'm still monitoring the system and ready to assist at any moment.",
            
            # Confirmation & Acknowledgment
            "yes": "Affirmative, sir. Proceeding with the requested operation.",
            "no": "Understood, sir. Operation cancelled. Is there something else I can help you with?",
            "ok": "Acknowledged, sir. Standing by for your next instruction.",
            "okay": "Confirmed, sir. How else may I assist you?",
            "sure": "Certainly, sir. I'll proceed with that request.",
            "proceed": "Proceeding as requested, sir.",
            
            # Capabilities Demonstration
            "demo": "I can demonstrate ANALCONTROL capabilities by: 1) Navigating to different tabs, 2) Showing system status, 3) Executing commands, 4) Managing clients. What would you like to see demonstrated?",
            
            "tutorial": "I can provide tutorials on: Client Management, Command Execution, Python Scripts, Screenshot Capture, Recording Management, Log Analysis, or Chat System. Which topic interests you?",
            
            "guide": "I can guide you through any ANALCONTROL feature. Would you like help with: Navigation, Client Operations, System Monitoring, Communication, or Advanced Features?",
            
            # Advanced Operations
            "automate": "ANALCONTROL supports automation through: Scheduled screenshots, Auto-recordings, Bulk command execution, and Script scheduling. What would you like to automate?",
            
            "schedule": "You can schedule: Recurring screenshots, Automated recordings, Periodic system checks, or Timed command execution. What task would you like to schedule?",
            
            "bulk": "Bulk operations available: Screenshot all clients, Record all screens, Execute command on multiple clients, or Batch script execution. Which bulk operation do you need?",
            
            "export": "You can export: System logs to CSV, Screenshot gallery, Recording library metadata, or Client statistics. What would you like to export?",
            
            # Performance & Optimization
            "slow": "If the system seems slow, I can help optimize: 1) Clear old logs, 2) Reduce refresh intervals, 3) Close inactive client connections, 4) Optimize data queries. Would you like me to run diagnostics?",
            
            "optimize": "System optimization options: Clear caches, Reduce log retention, Optimize database queries, Adjust refresh rates. What would you like to optimize?",
            
            "performance": "Checking system performance metrics: CPU usage, Memory consumption, Network bandwidth, WebSocket connections. Would you like a detailed performance report?",
            
            # Default fallback with context awareness
            "default": "I understand you're asking about ANALCONTROL operations. I can assist with: Website navigation, Client management, Command execution, System monitoring, and Communication features. Could you provide more specific details about what you need help with, sir?"
        }
    
    def get_response(self, message: str, context: Dict = None) -> str:
        """Get AI response with context awareness"""
        message_lower = message.lower().strip()
        context = context or {}
        
        # Direct pattern matching
        for pattern, response in self.patterns.items():
            if pattern in message_lower:
                return self._personalize_response(response, context)
        
        # Fuzzy matching with word overlap
        best_match = None
        best_score = 0
        
        for pattern, response in self.patterns.items():
            score = self._calculate_similarity(pattern, message_lower)
            if score > best_score and score > self.similarity_threshold:
                best_score = score
                best_match = response
        
        if best_match:
            return self._personalize_response(best_match, context)
        
        # Keyword-based contextual responses
        keywords = {
            'tab': "Which tab would you like to access? Available tabs: Clients, Commands, Python, Screenshots, Recordings, Logs, Chat.",
            'client': "I can help with client operations. Options: View clients, Execute commands, Capture screenshots, Get system info, Start recordings, Live stream. What would you like to do?",
            'command': "For command execution, I can: Execute predefined commands, Run custom commands, Execute Python scripts, or Perform bulk operations. What command operation do you need?",
            'python': "Python capabilities include: Script editor, Template library, Remote execution, Result viewing, or History. What Python operation interests you?",
            'screenshot': "Screenshot operations: Capture single client, Capture all clients, View gallery, Download images, or Delete screenshots. What would you like to do?",
            'recording': "Recording options: Start recording, Stop recording, View library, Play recordings, or Download videos. Which recording operation?",
            'log': "Log management features: View logs, Filter by type/client, Export logs, or Clear history. What log operation do you need?",
            'chat': "Chat capabilities: Global chat, Private messaging, Client communication, or User management. Which chat feature?",
            'refresh': "Refresh options: All data, Specific tab, Client list, Statistics, or Logs. What needs refreshing?",
            'status': "Status information: System health, Client status, Connection metrics, Performance stats, or Service availability. What status do you need?",
            'help': "I can provide detailed help on any ANALCONTROL feature. Be specific about what you'd like assistance with.",
            'how': "I'll guide you through the process step-by-step. What specific task do you need help with?",
            'what': "I'll explain that feature in detail. What would you specifically like to know about?",
            'where': "I'll show you where to find that in the interface. What are you looking for?",
            'when': "I can tell you when features are available or help you schedule operations. What timing information do you need?",
            'why': "Let me explain the purpose and benefits of that feature. What would you like to understand better?",
        }
        
        for keyword, response in keywords.items():
            if keyword in message_lower:
                return self._personalize_response(response, context)
        
        # Enhanced default with suggestions
        suggestions = [
            "Show me connected clients",
            "Take a screenshot",
            "Open Python tab",
            "Check system status",
            "View system logs",
            "Start screen recording"
        ]
        
        suggestion = random.choice(suggestions)
        
        return f"""I understand you're asking about "{message}". 

I can assist you with ANALCONTROL v4.0 comprehensive operations:

• **Navigation**: Access any of the 7 tabs
• **Client Control**: Monitor, command, and capture from clients
• **System Management**: Logs, status, performance metrics
• **Communication**: Chat, messaging, notifications
• **Automation**: Scheduled tasks, bulk operations

Try asking:
• "{suggestion}"
• "What can you do?"
• "Help with [specific task]"

Or provide more details about what you'd like to accomplish, sir."""

    def _calculate_similarity(self, pattern: str, message: str) -> float:
        """Calculate similarity score between pattern and message"""
        pattern_words = set(pattern.split())
        message_words = set(message.split())
        
        if not pattern_words or not message_words:
            return 0.0
        
        common_words = pattern_words.intersection(message_words)
        return len(common_words) / max(len(pattern_words), len(message_words))
    
    def _personalize_response(self, response: str, context: Dict) -> str:
        """Personalize response based on context"""
        # Could add user name, current tab info, etc.
        current_tab = context.get('current_tab', 'dashboard')
        
        # Add context-aware information if relevant
        if '[Action:' not in response and current_tab != 'dashboard':
            # User is already on a specific tab, acknowledge it
            pass
        
        return response

# Initialize Local AI
local_ai = LocalAI()

# ========== JARVIS PERSONALITY ENGINE ==========
class JarvisPersonalityEngine:
    """Adds personality and conversational context to J.A.R.V.I.S."""
    
    def __init__(self):
        self.conversation_history = []
        self.max_history = 100
        self.personality_traits = {
            'formal': True,
            'helpful': True,
            'efficient': True,
            'professional': True
        }
    
    def enhance_response(self, response: str) -> str:
        """Add personality touches to response"""
        # Already well-formatted responses from LocalAI
        return response
    
    def add_to_history(self, role: str, content: str):
        """Track conversation history"""
        self.conversation_history.append({
            'role': role,
            'content': content,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        if len(self.conversation_history) > self.max_history:
            self.conversation_history = self.conversation_history[-self.max_history:]
    
    def get_context_summary(self) -> str:
        """Get summary of recent conversation"""
        if not self.conversation_history:
            return "No previous conversation"
        
        recent = self.conversation_history[-5:]
        return f"Recent topics: {', '.join([h['content'][:30] for h in recent])}"

personality_engine = JarvisPersonalityEngine()

# ========== JARVIS ACTION EXECUTOR ==========
class JarvisActionExecutor:
    """Parses and executes actions from AI responses"""
    
    @staticmethod
    def parse_action_from_query(query: str, response: str, user_context: Dict = None) -> Optional[Dict]:
        """Extract actionable commands from query and response"""
        query_lower = query.lower()
        
        # Extract action markers from response
        if '[Action:' in response:
            action_match = re.search(r'\[Action:\s*(.*?)\]', response)
            if action_match:
                action_text = action_match.group(1).lower()
                
                action_mappings = {
                    'switch to clients': {'type': 'navigate', 'tab': 'clients'},
                    'switch to commands': {'type': 'navigate', 'tab': 'commands'},
                    'switch to python': {'type': 'navigate', 'tab': 'python'},
                    'switch to screenshots': {'type': 'navigate', 'tab': 'screenshots'},
                    'switch to recordings': {'type': 'navigate', 'tab': 'recordings'},
                    'switch to logs': {'type': 'navigate', 'tab': 'logs'},
                    'switch to chat': {'type': 'navigate', 'tab': 'chat'},
                    'execute screenshot': {'type': 'command', 'command': 'screenshot'},
                    'execute screenshot all': {'type': 'command', 'command': 'screenshot', 'target': 'all'},
                    'execute record_screen': {'type': 'command', 'command': 'record_screen'},
                    'execute record_screen all': {'type': 'command', 'command': 'record_screen', 'target': 'all'},
                    'execute live_screen': {'type': 'command', 'command': 'live_screen'},
                    'execute system_info': {'type': 'command', 'command': 'system_info'},
                    'refresh all': {'type': 'refresh', 'target': 'all'},
                    'refresh clients': {'type': 'refresh', 'target': 'clients'},
                    'check status': {'type': 'status', 'target': 'system'},
                }
                
                if action_text in action_mappings:
                    return action_mappings[action_text]
        
        # Fallback parsing from query keywords
        navigation_keywords = {
            'client': 'clients',
            'command': 'commands',
            'python': 'python',
            'screenshot': 'screenshots',
            'recording': 'recordings',
            'log': 'logs',
            'chat': 'chat'
        }
        
        for keyword, tab in navigation_keywords.items():
            if any(word in query_lower for word in ['show', 'open', 'view', 'display']):
                if keyword in query_lower:
                    return {'type': 'navigate', 'tab': tab}
        
        # Action detection
        if 'take' in query_lower and 'screenshot' in query_lower:
            target = 'all' if 'all' in query_lower else None
            return {'type': 'command', 'command': 'screenshot', 'target': target}
        
        if 'record' in query_lower and ('screen' in query_lower or 'video' in query_lower):
            return {'type': 'command', 'command': 'record_screen'}
        
        if 'live' in query_lower or 'stream' in query_lower:
            return {'type': 'command', 'command': 'live_screen'}
        
        if any(word in query_lower for word in ['refresh', 'update', 'reload', 'sync']):
            return {'type': 'refresh', 'target': 'all'}
        
        if 'status' in query_lower or 'health' in query_lower:
            return {'type': 'status', 'target': 'system'}
        
        return None

# ========== DATA MODELS ==========
class LoginRequest(BaseModel):
    email: str = Field(..., example="admin")
    password: str = Field(..., example="admin123")

class UserCreate(BaseModel):
    email: str
    password: str
    confirm_password: str
    is_admin: bool = True
    theme: str = "red_black"

class ClientRegister(BaseModel):
    client_id: str
    name: str
    ip_address: str
    os_info: str = "Unknown"

class CommandRequest(BaseModel):
    client_id: str
    command: str
    parameters: Dict[str, Any] = Field(default_factory=dict)

class PythonExecutionRequest(BaseModel):
    client_id: str
    filename: str
    content: str
    parameters: Optional[List[str]] = Field(default_factory=list)
    timeout: int = 30

class ChatMessage(BaseModel):
    message: str
    recipient: Optional[str] = None

class JarvisChatRequest(BaseModel):
    message: str
    context: Optional[Dict] = None

class JarvisChatResponse(BaseModel):
    success: bool
    response: str
    action: Optional[Dict] = None
    model: str
    timestamp: str

# ========== AI PROCESSING ==========
async def process_with_local_ai(message: str, context: Dict = None) -> Dict:
    """Process message through Local AI with personality"""
    context = context or {}
    
    # Get base response from Local AI
    ai_response = local_ai.get_response(message, context)
    
    # Enhance with personality
    enhanced_response = personality_engine.enhance_response(ai_response)
    
    # Track conversation
    personality_engine.add_to_history("user", message)
    personality_engine.add_to_history("assistant", enhanced_response)
    
    # Parse for actions
    action = JarvisActionExecutor.parse_action_from_query(message, enhanced_response, context)
    
    return {
        "success": True,
        "response": enhanced_response,
        "action": action,
        "model": "local_ai",
        "timestamp": datetime.utcnow().isoformat()
    }

# ========== WEBSOCKET MANAGER ==========
class ConnectionManager:
    """Manages WebSocket connections"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_connections: Dict[str, WebSocket] = {}
        
    async def connect(self, websocket: WebSocket, connection_id: str, connection_type: str = "admin"):
        """Accept and store WebSocket connection"""
        await websocket.accept()
        
        if connection_type == "client":
            self.client_connections[connection_id] = websocket
            # Update client status in database
            client = db.get_client(connection_id)
            if client:
                client['ws_online'] = True
        else:
            self.active_connections[connection_id] = websocket
        
        logger.info(f"WebSocket connected: {connection_id} ({connection_type})")
    
    def disconnect(self, connection_id: str, connection_type: str = "admin"):
        """Remove WebSocket connection"""
        if connection_type == "client":
            if connection_id in self.client_connections:
                del self.client_connections[connection_id]
                # Update client status
                client = db.get_client(connection_id)
                if client:
                    client['ws_online'] = False
        else:
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
        
        logger.info(f"WebSocket disconnected: {connection_id} ({connection_type})")
    
    async def send_personal_message(self, message: str, connection_id: str):
        """Send message to specific connection"""
        websocket = self.active_connections.get(connection_id) or self.client_connections.get(connection_id)
        if websocket:
            await websocket.send_text(message)
    
    async def broadcast(self, message: str, exclude: List[str] = None):
        """Broadcast message to all admin connections"""
        exclude = exclude or []
        for conn_id, websocket in self.active_connections.items():
            if conn_id not in exclude:
                try:
                    await websocket.send_text(message)
                except:
                    pass
    
    async def broadcast_to_clients(self, message: str, client_ids: List[str] = None):
        """Broadcast to specific clients or all clients"""
        targets = client_ids or list(self.client_connections.keys())
        for client_id in targets:
            if client_id in self.client_connections:
                try:
                    await self.client_connections[client_id].send_text(message)
                except:
                    pass

manager = ConnectionManager()

# ========== UTILITY FUNCTIONS ==========
def verify_jwt_token(token: str) -> Optional[Dict]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=["HS256"],
            options={"verify_exp": True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Expired JWT token")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT token")
        return None
    except Exception as e:
        logger.error(f"JWT verification error: {e}")
        return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """Get current authenticated user"""
    payload = verify_jwt_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    return payload

# ========== API ENDPOINTS ==========

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "ANALCONTROL v4.0 API with J.A.R.V.I.S. AI",
        "version": "4.0.0",
        "status": "online",
        "features": [
            "Client Monitoring",
            "Command Execution",
            "Screenshot Capture",
            "Screen Recording",
            "Live Streaming",
            "Python Execution",
            "Chat System",
            "J.A.R.V.I.S. AI Assistant"
        ]
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "api": "online",
            "database": "online",
            "ai": "online",
            "jarvis": "online",
            "websocket": "online"
        },
        "stats": db.get_stats()
    }

@app.post("/api/login")
async def login(email: str = Form(...), password: str = Form(...)):
    """User login endpoint"""
    user = db.users.get(email)
    
    if not user or user['password'] != password:
        structured_logger.log_api_call("/api/login", email, "failed", {"reason": "invalid_credentials"})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    token = jwt.encode({
        "user_id": user['id'],
        "email": user['email'],
        "is_admin": user['is_admin'],
        "exp": datetime.utcnow() + timedelta(hours=24)
    }, JWT_SECRET_KEY, algorithm="HS256")
    
    structured_logger.log_api_call("/api/login", email, "success")
    
    return {
        "success": True,
        "token": token,
        "user": {
            "id": user['id'],
            "email": user['email'],
            "is_admin": user['is_admin'],
            "theme": user['theme']
        }
    }

@app.get("/api/stats")
async def get_stats(current_user: Dict = Depends(get_current_user)):
    """Get system statistics"""
    stats = db.get_stats()
    structured_logger.log_api_call("/api/stats", current_user['email'], "success")
    return {"success": True, "stats": stats}

@app.get("/api/clients")
async def get_clients(current_user: Dict = Depends(get_current_user)):
    """Get all clients"""
    clients = db.get_all_clients()
    return {"success": True, "clients": clients}

@app.post("/api/clients/register")
async def register_client(client: ClientRegister):
    """Register new client"""
    client_data = client.dict()
    registered_client = db.add_client(client_data)
    
    # Notify all admins
    await manager.broadcast(json.dumps({
        "type": "client_connected",
        "client_id": registered_client['client_id'],
        "data": registered_client
    }))
    
    return {"success": True, "client": registered_client}

@app.post("/api/command")
async def execute_command(
    command: CommandRequest,
    current_user: Dict = Depends(get_current_user)
):
    """Execute command on client"""
    command_data = command.dict()
    command_data['user_id'] = current_user['user_id']
    command_data['user_email'] = current_user['email']
    
    # Save command
    saved_command = db.add_command(command_data)
    
    # Try to send via WebSocket if client is online
    if command.client_id in manager.client_connections:
        await manager.send_personal_message(
            json.dumps({
                "type": "command",
                "command_id": saved_command['id'],
                "command": command.command,
                "parameters": command.parameters
            }),
            command.client_id
        )
    
    # Log
    db.add_log({
        "client_id": command.client_id,
        "log_type": "info",
        "message": f"Command '{command.command}' sent by {current_user['email']}"
    })
    
    return {
        "success": True,
        "command_id": saved_command['id'],
        "sent_via_websocket": command.client_id in manager.client_connections
    }

@app.get("/api/commands")
async def get_commands(
    limit: int = Query(50, ge=1, le=1000),
    current_user: Dict = Depends(get_current_user)
):
    """Get command history"""
    commands = db.commands[-limit:]
    commands.reverse()
    return {"success": True, "commands": commands}

@app.get("/api/screenshots")
async def get_screenshots(current_user: Dict = Depends(get_current_user)):
    """Get all screenshots"""
    screenshots = db.screenshots
    screenshots.reverse()
    return {"success": True, "screenshots": screenshots}

@app.get("/api/recordings")
async def get_recordings(current_user: Dict = Depends(get_current_user)):
    """Get all recordings"""
    recordings = db.recordings
    recordings.reverse()
    return {"success": True, "recordings": recordings}

@app.get("/api/logs")
async def get_logs(
    limit: int = Query(100, ge=1, le=1000),
    log_type: Optional[str] = None,
    current_user: Dict = Depends(get_current_user)
):
    """Get system logs"""
    logs = db.logs[-limit:]
    
    if log_type:
        logs = [log for log in logs if log.get('log_type') == log_type]
    
    logs.reverse()
    return {"success": True, "logs": logs}

# ========== J.A.R.V.I.S. AI ENDPOINTS ==========

@app.post("/api/jarvis/chat", response_model=JarvisChatResponse)
async def jarvis_chat(
    request: JarvisChatRequest,
    current_user: Dict = Depends(get_current_user)
):
    """Chat with J.A.R.V.I.S. AI Assistant"""
    try:
        user_email = current_user.get("email", "user")
        
        logger.info(f"J.A.R.V.I.S. chat from {user_email}: {request.message[:50]}...")
        
        # Build enhanced context
        user_context = {
            "user_id": current_user.get("user_id"),
            "email": user_email,
            "is_admin": current_user.get("is_admin", False),
            "current_tab": request.context.get("current_tab", "dashboard") if request.context else "dashboard",
            "clients_online": len([c for c in db.clients.values() if c.get('ws_online')]),
            "total_clients": len(db.clients),
        }
        
        # Process with Local AI
        result = await process_with_local_ai(request.message, user_context)
        
        # Log interaction
        structured_logger.log_api_call(
            "/api/jarvis/chat",
            user_email,
            "success",
            {
                "message_length": len(request.message),
                "has_action": result.get("action") is not None,
                "response_length": len(result['response'])
            }
        )
        
        return JarvisChatResponse(**result)
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"J.A.R.V.I.S. error: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"AI processing error: {str(e)}")

@app.get("/api/jarvis/system-status")
async def jarvis_system_status(current_user: Dict = Depends(get_current_user)):
    """Get J.A.R.V.I.S. system status"""
    try:
        return {
            "success": True,
            "status": {
                "jarvis": "online",
                "ai_model": "local_ai",
                "personality_engine": "active",
                "conversation_history": len(personality_engine.conversation_history),
                "local_ai_patterns": len(local_ai.patterns),
                "free": True,
                "api_key_required": False,
                "capabilities": [
                    "Natural language processing",
                    "Website navigation",
                    "Command execution",
                    "System monitoring",
                    "Conversational context",
                    "Action parsing"
                ]
            }
        }
    except Exception as e:
        logger.error(f"Status error: {e}")
        return {"success": False, "error": str(e)}

@app.post("/api/jarvis/reset-conversation")
async def jarvis_reset_conversation(current_user: Dict = Depends(get_current_user)):
    """Reset J.A.R.V.I.S. conversation history"""
    try:
        personality_engine.conversation_history = []
        return {
            "success": True,
            "message": "Conversation history reset successfully"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/jarvis/get-suggestions")
async def jarvis_get_suggestions(current_user: Dict = Depends(get_current_user)):
    """Get contextual suggestions from J.A.R.V.I.S."""
    try:
        suggestions = [
            {"text": "Show connected clients", "action": {"type": "navigate", "tab": "clients"}},
            {"text": "Take a screenshot", "action": {"type": "command", "command": "screenshot"}},
            {"text": "Open Python tab", "action": {"type": "navigate", "tab": "python"}},
            {"text": "Check system status", "action": {"type": "status", "target": "system"}},
            {"text": "Refresh dashboard", "action": {"type": "refresh", "target": "all"}},
            {"text": "Open chat", "action": {"type": "navigate", "tab": "chat"}},
            {"text": "View system logs", "action": {"type": "navigate", "tab": "logs"}},
            {"text": "Start recording", "action": {"type": "command", "command": "record_screen"}}
        ]
        
        return {
            "success": True,
            "suggestions": suggestions
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/jarvis/ai-config")
async def get_ai_config():
    """Get AI configuration details"""
    return {
        "success": True,
        "config": {
            "ai_provider": "local_pattern_matching",
            "free": True,
            "patterns_loaded": len(local_ai.patterns),
            "requires_api_key": False,
            "offline_capable": True,
            "features": [
                "Website navigation",
                "Command execution",
                "System monitoring",
                "Chat control",
                "Data management",
                "Context awareness",
                "Natural language understanding"
            ],
            "supported_operations": [
                "Tab navigation",
                "Client management",
                "Screenshot capture",
                "Screen recording",
                "System status checks",
                "Log viewing",
                "Chat messaging"
            ]
        }
    }

# ========== WEBSOCKET ENDPOINTS ==========

@app.websocket("/ws/admin")
async def websocket_admin(websocket: WebSocket):
    """Admin WebSocket connection"""
    await manager.connect(websocket, "admin", "admin")
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle different message types
            if message.get("type") == "ping":
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                }))
            
    except WebSocketDisconnect:
        manager.disconnect("admin", "admin")
    except Exception as e:
        logger.error(f"Admin WebSocket error: {e}")
        manager.disconnect("admin", "admin")

@app.websocket("/ws/client/{client_id}")
async def websocket_client(websocket: WebSocket, client_id: str):
    """Client WebSocket connection"""
    await manager.connect(websocket, client_id, "client")
    
    # Notify admins of new connection
    await manager.broadcast(json.dumps({
        "type": "client_connected",
        "client_id": client_id,
        "timestamp": datetime.utcnow().isoformat()
    }))
    
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle client messages
            if message.get("type") == "heartbeat":
                await websocket.send_text(json.dumps({
                    "type": "heartbeat_ack",
                    "timestamp": datetime.utcnow().isoformat()
                }))
                
                # Update last seen
                client = db.get_client(client_id)
                if client:
                    client['last_seen'] = datetime.utcnow().isoformat()
            
            elif message.get("type") == "command_result":
                # Update command status
                command_id = message.get("command_id")
                if command_id:
                    db.update_command(command_id, {
                        "status": "completed",
                        "result": message.get("result"),
                        "error": message.get("error"),
                        "completed_at": datetime.utcnow().isoformat()
                    })
                
                # Notify admins
                await manager.broadcast(json.dumps({
                    "type": "command_result",
                    "client_id": client_id,
                    "command_id": command_id,
                    "result": message.get("result"),
                    "error": message.get("error")
                }))
            
            elif message.get("type") == "screenshot":
                # Save screenshot
                screenshot_data = {
                    "client_id": client_id,
                    "filename": message.get("filename"),
                    "image_data": message.get("image_data"),
                    "size": len(message.get("image_data", "")),
                    "width": message.get("width"),
                    "height": message.get("height")
                }
                db.add_screenshot(screenshot_data)
                
                # Notify admins
                await manager.broadcast(json.dumps({
                    "type": "screenshot_received",
                    "client_id": client_id,
                    "filename": message.get("filename")
                }))
            
    except WebSocketDisconnect:
        manager.disconnect(client_id, "client")
        
        # Notify admins of disconnection
        await manager.broadcast(json.dumps({
            "type": "client_disconnected",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat()
        }))
    except Exception as e:
        logger.error(f"Client WebSocket error: {e}")
        manager.disconnect(client_id, "client")

# ========== STARTUP & SHUTDOWN ==========

def print_startup_banner():
    """Print ASCII art banner on startup"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ░J░A░R░V░I░S░  Backend v4.0  -  ANALCONTROL             ║
║                                                              ║
║        Just A Rather Very Intelligent System                 ║
║                                                              ║
║        🆓 100% FREE LOCAL AI • NO API KEYS REQUIRED         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

🤖 J.A.R.V.I.S. AI Systems Initializing...
    """
    print(banner)
    
    print("\n📋 System Configuration:")
    print(f"   • Port: {PORT}")
    print(f"   • AI Provider: Local Pattern Matching")
    print(f"   • AI Patterns: {len(local_ai.patterns)} loaded")
    print(f"   • API Key Required: ❌ NO - 100% Free")
    print(f"   • Internet Required: ❌ NO - Works Offline")
    print(f"   • JWT Secret: {JWT_SECRET_KEY[:20]}...")
    
    print("\n🏗️  Core Capabilities:")
    print("   1. Complete website control (7 tabs)")
    print("   2. Client monitoring and management")
    print("   3. Remote command execution")
    print("   4. Screenshot and recording capture")
    print("   5. Live screen streaming")
    print("   6. Python script execution")
    print("   7. Real-time chat system")
    print("   8. Comprehensive logging")
    print("   9. WebSocket real-time updates")
    print("  10. J.A.R.V.I.S. AI assistant")
    
    print("\n🌐 API Endpoints:")
    print("   • POST   /api/login                    - User authentication")
    print("   • POST   /api/jarvis/chat              - Chat with J.A.R.V.I.S. (FREE AI)")
    print("   • GET    /api/jarvis/ai-config         - AI configuration")
    print("   • GET    /api/jarvis/system-status     - J.A.R.V.I.S. status")
    print("   • GET    /api/stats                    - System statistics")
    print("   • GET    /api/clients                  - Client list")
    print("   • POST   /api/command                  - Execute command")
    print("   • WS     /ws/admin                     - Admin WebSocket")
    print("   • WS     /ws/client/{id}               - Client WebSocket")
    
    print("\n🚀 Sample Commands for J.A.R.V.I.S.:")
    print("   • 'Show me connected clients'")
    print("   • 'Take screenshot from all clients'")
    print("   • 'Open Python tab'")
    print("   • 'Check system status'")
    print("   • 'What can you do?'")
    print("   • 'Start recording'")
    
    print("\n✅ System Ready!")
    print(f"   Backend URL: {BACKEND_URL}")
    print(f"   API Docs: {BACKEND_URL}/api/docs")
    print(f"   Total AI Patterns: {len(local_ai.patterns)}")
    print("   Memory Usage: Minimal")
    print("   Cost: $0.00 (100% FREE)\n")
    
    logger.info("ANALCONTROL Backend v4.0 started successfully")
    logger.info(f"J.A.R.V.I.S. AI initialized with {len(local_ai.patterns)} response patterns")

@app.on_event("startup")
async def startup_event():
    """Execute on application startup"""
    print_startup_banner()
    
    # Initialize default data
    logger.info("Initializing default system data...")
    
    # Add sample log
    db.add_log({
        "client_id": "system",
        "log_type": "info",
        "message": "ANALCONTROL system started successfully"
    })

@app.on_event("shutdown")
async def shutdown_event():
    """Execute on application shutdown"""
    logger.info("ANALCONTROL Backend shutting down...")
    
    # Close all WebSocket connections
    for conn_id in list(manager.active_connections.keys()):
        try:
            await manager.active_connections[conn_id].close()
        except:
            pass
    
    for client_id in list(manager.client_connections.keys()):
        try:
            await manager.client_connections[client_id].close()
        except:
            pass
    
    logger.info("All WebSocket connections closed")
    logger.info("Shutdown complete")

# ========== MAIN EXECUTION ==========
if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True
    )

# ========== ADDITIONAL FEATURES ==========

# File Management Endpoints
@app.post("/api/upload/screenshot")
async def upload_screenshot(
    file: UploadFile = File(...),
    client_id: str = Form(...),
    current_user: Dict = Depends(get_current_user)
):
    """Upload screenshot file"""
    try:
        # Read file content
        content = await file.read()
        
        # Generate filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"screenshot_{client_id}_{timestamp}.png"
        filepath = SCREENSHOTS_DIR / filename
        
        # Save file
        with open(filepath, "wb") as f:
            f.write(content)
        
        # Add to database
        screenshot_data = {
            "client_id": client_id,
            "filename": filename,
            "filepath": str(filepath),
            "size": len(content),
            "image_data": base64.b64encode(content).decode('utf-8')
        }
        db.add_screenshot(screenshot_data)
        
        return {"success": True, "screenshot": screenshot_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/screenshot/{screenshot_id}/download")
async def download_screenshot(
    screenshot_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Download screenshot"""
    screenshot = next((s for s in db.screenshots if s['id'] == screenshot_id), None)
    if not screenshot:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    
    if 'filepath' in screenshot and Path(screenshot['filepath']).exists():
        return FileResponse(screenshot['filepath'])
    elif 'image_data' in screenshot:
        # Return base64 data as image
        image_bytes = base64.b64decode(screenshot['image_data'])
        return StreamingResponse(io.BytesIO(image_bytes), media_type="image/png")
    else:
        raise HTTPException(status_code=404, detail="Screenshot data not available")

@app.delete("/api/screenshot/{screenshot_id}")
async def delete_screenshot(
    screenshot_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Delete screenshot"""
    screenshot = next((s for s in db.screenshots if s['id'] == screenshot_id), None)
    if not screenshot:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    
    # Remove from database
    db.screenshots = [s for s in db.screenshots if s['id'] != screenshot_id]
    
    # Delete file if exists
    if 'filepath' in screenshot and Path(screenshot['filepath']).exists():
        Path(screenshot['filepath']).unlink()
    
    return {"success": True, "message": "Screenshot deleted"}

# Recording Management
@app.post("/api/recording/start")
async def start_recording(
    client_id: str = Form(...),
    duration: int = Form(30),
    fps: int = Form(30),
    quality: str = Form("medium"),
    current_user: Dict = Depends(get_current_user)
):
    """Start screen recording on client"""
    command_data = {
        "client_id": client_id,
        "command": "record_screen",
        "parameters": {
            "duration": duration,
            "fps": fps,
            "quality": quality
        },
        "user_id": current_user['user_id'],
        "user_email": current_user['email']
    }
    
    saved_command = db.add_command(command_data)
    
    # Send via WebSocket if online
    if client_id in manager.client_connections:
        await manager.send_personal_message(
            json.dumps({
                "type": "command",
                "command_id": saved_command['id'],
                "command": "record_screen",
                "parameters": command_data['parameters']
            }),
            client_id
        )
    
    return {"success": True, "command_id": saved_command['id']}

@app.post("/api/recording/stop")
async def stop_recording(
    client_id: str = Form(...),
    current_user: Dict = Depends(get_current_user)
):
    """Stop screen recording on client"""
    command_data = {
        "client_id": client_id,
        "command": "stop_recording",
        "parameters": {},
        "user_id": current_user['user_id'],
        "user_email": current_user['email']
    }
    
    saved_command = db.add_command(command_data)
    
    if client_id in manager.client_connections:
        await manager.send_personal_message(
            json.dumps({
                "type": "command",
                "command_id": saved_command['id'],
                "command": "stop_recording",
                "parameters": {}
            }),
            client_id
        )
    
    return {"success": True, "command_id": saved_command['id']}

@app.delete("/api/recording/{recording_id}")
async def delete_recording(
    recording_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Delete recording"""
    recording = next((r for r in db.recordings if r['id'] == recording_id), None)
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")
    
    # Remove from database
    db.recordings = [r for r in db.recordings if r['id'] != recording_id]
    
    # Delete file if exists
    if 'filepath' in recording and Path(recording['filepath']).exists():
        Path(recording['filepath']).unlink()
    
    return {"success": True, "message": "Recording deleted"}

# Python Script Execution
@app.post("/api/execute-python")
async def execute_python(
    request: PythonExecutionRequest,
    current_user: Dict = Depends(get_current_user)
):
    """Execute Python script on client"""
    command_data = {
        "client_id": request.client_id,
        "command": "execute_python",
        "parameters": {
            "filename": request.filename,
            "content": request.content,
            "args": request.parameters,
            "timeout": request.timeout
        },
        "user_id": current_user['user_id'],
        "user_email": current_user['email']
    }
    
    saved_command = db.add_command(command_data)
    
    # Save script to database
    db.python_executions.append({
        "id": saved_command['id'],
        "client_id": request.client_id,
        "filename": request.filename,
        "content": request.content,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat()
    })
    
    # Send via WebSocket
    if request.client_id in manager.client_connections:
        await manager.send_personal_message(
            json.dumps({
                "type": "command",
                "command_id": saved_command['id'],
                "command": "execute_python",
                "parameters": command_data['parameters']
            }),
            request.client_id
        )
    
    return {
        "success": True,
        "command_id": saved_command['id'],
        "sent_via_websocket": request.client_id in manager.client_connections
    }

@app.get("/api/python-execution/{command_id}")
async def get_python_execution(
    command_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get Python execution result"""
    command = next((c for c in db.commands if c['id'] == command_id), None)
    if not command:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    return {"success": True, "command": command}

@app.get("/api/python-executions")
async def get_python_executions(
    limit: int = Query(50, ge=1, le=1000),
    current_user: Dict = Depends(get_current_user)
):
    """Get Python execution history"""
    executions = [c for c in db.commands if c.get('command') == 'execute_python']
    executions = executions[-limit:]
    executions.reverse()
    return {"success": True, "executions": executions}

# Chat System
@app.post("/api/chat/send")
async def send_chat_message(
    message: ChatMessage,
    current_user: Dict = Depends(get_current_user)
):
    """Send chat message"""
    message_data = {
        "sender": current_user['email'],
        "recipient": message.recipient,
        "message": message.message
    }
    
    saved_message = db.add_chat_message(message_data)
    
    # Broadcast to relevant users
    await manager.broadcast(json.dumps({
        "type": "new_message",
        "message": saved_message,
        "sender_tag": {
            "role": "admin" if current_user.get('is_admin') else "user",
            "color": "#ff2a2a"
        }
    }))
    
    return {"success": True, "message": saved_message}

@app.get("/api/chat/messages")
async def get_chat_messages(
    recipient: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    current_user: Dict = Depends(get_current_user)
):
    """Get chat messages"""
    messages = db.chat_messages
    
    if recipient and recipient != "all":
        # Filter for private conversation
        messages = [
            m for m in messages
            if (m['sender'] == current_user['email'] and m.get('recipient') == recipient) or
               (m.get('recipient') == current_user['email'] and m['sender'] == recipient)
        ]
    elif recipient == "all":
        # Global messages
        messages = [m for m in messages if m.get('recipient') is None or m.get('recipient') == "all"]
    
    messages = messages[-limit:]
    return {"success": True, "messages": messages}

@app.get("/api/chat/users")
async def get_chat_users(current_user: Dict = Depends(get_current_user)):
    """Get all chat users"""
    users = [
        {
            "user_id": user['email'],
            "username": user['email'],
            "role": "admin" if user['is_admin'] else "user",
            "online": user['email'] in manager.active_connections,
            "color": "#ff2a2a"
        }
        for user in db.users.values()
    ]
    return {"success": True, "users": users}

# Bulk Operations
@app.post("/api/screenshot/all")
async def screenshot_all_clients(current_user: Dict = Depends(get_current_user)):
    """Capture screenshots from all online clients"""
    online_clients = [c for c in db.clients.values() if c.get('ws_online')]
    
    count = 0
    for client in online_clients:
        try:
            command_data = {
                "client_id": client['client_id'],
                "command": "screenshot",
                "parameters": {},
                "user_id": current_user['user_id'],
                "user_email": current_user['email']
            }
            
            saved_command = db.add_command(command_data)
            
            if client['client_id'] in manager.client_connections:
                await manager.send_personal_message(
                    json.dumps({
                        "type": "command",
                        "command_id": saved_command['id'],
                        "command": "screenshot",
                        "parameters": {}
                    }),
                    client['client_id']
                )
                count += 1
        except Exception as e:
            logger.error(f"Error sending screenshot command to {client['client_id']}: {e}")
    
    return {"success": True, "count": count, "message": f"Screenshot command sent to {count} clients"}

@app.post("/api/start-auto-screenshots")
async def start_auto_screenshots(
    client_id: str = Form(...),
    interval: int = Form(5),
    current_user: Dict = Depends(get_current_user)
):
    """Start auto screenshot capture"""
    command_data = {
        "client_id": client_id,
        "command": "auto_screenshot",
        "parameters": {"interval": interval},
        "user_id": current_user['user_id'],
        "user_email": current_user['email']
    }
    
    saved_command = db.add_command(command_data)
    
    if client_id in manager.client_connections:
        await manager.send_personal_message(
            json.dumps({
                "type": "command",
                "command_id": saved_command['id'],
                "command": "auto_screenshot",
                "parameters": {"interval": interval}
            }),
            client_id
        )
    
    return {"success": True, "command_id": saved_command['id']}

@app.post("/api/stop-auto-screenshots")
async def stop_auto_screenshots(
    client_id: str = Form(...),
    current_user: Dict = Depends(get_current_user)
):
    """Stop auto screenshot capture"""
    command_data = {
        "client_id": client_id,
        "command": "stop_auto_screenshot",
        "parameters": {},
        "user_id": current_user['user_id'],
        "user_email": current_user['email']
    }
    
    saved_command = db.add_command(command_data)
    
    if client_id in manager.client_connections:
        await manager.send_personal_message(
            json.dumps({
                "type": "command",
                "command_id": saved_command['id'],
                "command": "stop_auto_screenshot",
                "parameters": {}
            }),
            client_id
        )
    
    return {"success": True, "command_id": saved_command['id']}

@app.post("/api/start-screen-stream")
async def start_screen_stream(
    client_id: str = Form(...),
    fps: int = Form(10),
    current_user: Dict = Depends(get_current_user)
):
    """Start live screen streaming"""
    command_data = {
        "client_id": client_id,
        "command": "live_screen",
        "parameters": {"fps": fps},
        "user_id": current_user['user_id'],
        "user_email": current_user['email']
    }
    
    saved_command = db.add_command(command_data)
    
    if client_id in manager.client_connections:
        await manager.send_personal_message(
            json.dumps({
                "type": "command",
                "command_id": saved_command['id'],
                "command": "live_screen",
                "parameters": {"fps": fps}
            }),
            client_id
        )
    
    return {"success": True, "command_id": saved_command['id']}

@app.post("/api/stop-screen-stream")
async def stop_screen_stream(
    client_id: str = Form(...),
    current_user: Dict = Depends(get_current_user)
):
    """Stop live screen streaming"""
    command_data = {
        "client_id": client_id,
        "command": "stop_live_screen",
        "parameters": {},
        "user_id": current_user['user_id'],
        "user_email": current_user['email']
    }
    
    saved_command = db.add_command(command_data)
    
    if client_id in manager.client_connections:
        await manager.send_personal_message(
            json.dumps({
                "type": "command",
                "command_id": saved_command['id'],
                "command": "stop_live_screen",
                "parameters": {}
            }),
            client_id
        )
    
    return {"success": True, "command_id": saved_command['id']}

# Analytics and Reports
@app.get("/api/analytics/overview")
async def get_analytics_overview(current_user: Dict = Depends(get_current_user)):
    """Get comprehensive analytics overview"""
    now = datetime.utcnow()
    
    # Calculate time ranges
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)
    
    # Client analytics
    total_clients = len(db.clients)
    online_clients = sum(1 for c in db.clients.values() if c.get('ws_online'))
    
    # Command analytics
    recent_commands = [c for c in db.commands if datetime.fromisoformat(c['created_at']) >= day_ago]
    commands_today = len(recent_commands)
    successful_commands = sum(1 for c in recent_commands if c.get('status') == 'completed')
    failed_commands = sum(1 for c in recent_commands if c.get('status') == 'failed')
    
    # Screenshot analytics
    screenshots_today = sum(1 for s in db.screenshots if datetime.fromisoformat(s['created_at']) >= day_ago)
    screenshots_week = sum(1 for s in db.screenshots if datetime.fromisoformat(s['created_at']) >= week_ago)
    
    # Recording analytics
    recordings_today = sum(1 for r in db.recordings if datetime.fromisoformat(r['created_at']) >= day_ago)
    
    # Log analytics
    logs_hour = sum(1 for l in db.logs if datetime.fromisoformat(l['created_at']) >= hour_ago)
    error_logs = sum(1 for l in db.logs if l.get('log_type') == 'error')
    
    return {
        "success": True,
        "analytics": {
            "clients": {
                "total": total_clients,
                "online": online_clients,
                "offline": total_clients - online_clients,
                "online_percentage": round((online_clients / total_clients * 100) if total_clients > 0 else 0, 2)
            },
            "commands": {
                "today": commands_today,
                "successful": successful_commands,
                "failed": failed_commands,
                "success_rate": round((successful_commands / commands_today * 100) if commands_today > 0 else 0, 2)
            },
            "screenshots": {
                "today": screenshots_today,
                "this_week": screenshots_week,
                "total": len(db.screenshots)
            },
            "recordings": {
                "today": recordings_today,
                "total": len(db.recordings)
            },
            "logs": {
                "last_hour": logs_hour,
                "errors": error_logs,
                "total": len(db.logs)
            },
            "system": {
                "uptime": "N/A",  # Would track from startup
                "websocket_connections": len(manager.active_connections) + len(manager.client_connections),
                "active_admins": len(manager.active_connections),
                "active_clients": len(manager.client_connections)
            }
        },
        "timestamp": now.isoformat()
    }

@app.get("/api/analytics/client/{client_id}")
async def get_client_analytics(
    client_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Get analytics for specific client"""
    client = db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    
    # Client-specific data
    client_commands = [c for c in db.commands if c['client_id'] == client_id]
    client_screenshots = [s for s in db.screenshots if s['client_id'] == client_id]
    client_recordings = [r for r in db.recordings if r['client_id'] == client_id]
    client_logs = [l for l in db.logs if l['client_id'] == client_id]
    
    return {
        "success": True,
        "client_id": client_id,
        "analytics": {
            "total_commands": len(client_commands),
            "total_screenshots": len(client_screenshots),
            "total_recordings": len(client_recordings),
            "total_logs": len(client_logs),
            "is_online": client.get('ws_online', False),
            "last_seen": client.get('last_seen'),
            "created_at": client.get('created_at')
        }
    }

# System Maintenance
@app.post("/api/maintenance/clear-old-data")
async def clear_old_data(
    days: int = Query(30, ge=1, le=365),
    current_user: Dict = Depends(get_current_user)
):
    """Clear data older than specified days"""
    if not current_user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Clear old screenshots
    original_screenshots = len(db.screenshots)
    db.screenshots = [s for s in db.screenshots if datetime.fromisoformat(s['created_at']) >= cutoff_date]
    screenshots_removed = original_screenshots - len(db.screenshots)
    
    # Clear old recordings
    original_recordings = len(db.recordings)
    db.recordings = [r for r in db.recordings if datetime.fromisoformat(r['created_at']) >= cutoff_date]
    recordings_removed = original_recordings - len(db.recordings)
    
    # Clear old logs
    original_logs = len(db.logs)
    db.logs = [l for l in db.logs if datetime.fromisoformat(l['created_at']) >= cutoff_date]
    logs_removed = original_logs - len(db.logs)
    
    # Clear old commands
    original_commands = len(db.commands)
    db.commands = [c for c in db.commands if datetime.fromisoformat(c['created_at']) >= cutoff_date]
    commands_removed = original_commands - len(db.commands)
    
    return {
        "success": True,
        "removed": {
            "screenshots": screenshots_removed,
            "recordings": recordings_removed,
            "logs": logs_removed,
            "commands": commands_removed
        },
        "cutoff_date": cutoff_date.isoformat()
    }

@app.get("/api/system/info")
async def get_system_info():
    """Get detailed system information"""
    return {
        "success": True,
        "system": {
            "version": "4.0.0",
            "python_version": sys.version,
            "platform": sys.platform,
            "ai_engine": "Local Pattern Matching",
            "ai_patterns": len(local_ai.patterns),
            "database_size": {
                "users": len(db.users),
                "clients": len(db.clients),
                "commands": len(db.commands),
                "screenshots": len(db.screenshots),
                "recordings": len(db.recordings),
                "logs": len(db.logs),
                "chat_messages": len(db.chat_messages)
            },
            "features": [
                "Real-time monitoring",
                "Command execution",
                "Screenshot capture",
                "Screen recording",
                "Live streaming",
                "Python execution",
                "Chat system",
                "J.A.R.V.I.S. AI",
                "WebSocket communication",
                "Analytics & Reports"
            ]
        }
    }

# Error Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    logger.error(traceback.format_exc())
    
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "message": str(exc),
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# Additional utility endpoints
@app.get("/api/export/logs")
async def export_logs_csv(current_user: Dict = Depends(get_current_user)):
    """Export logs as CSV"""
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Timestamp', 'Client ID', 'Type', 'Message'])
    
    # Write data
    for log in db.logs:
        writer.writerow([
            log.get('created_at'),
            log.get('client_id'),
            log.get('log_type'),
            log.get('message')
        ])
    
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=analcontrol_logs.csv"}
    )

@app.get("/api/version")
async def get_version():
    """Get API version information"""
    return {
        "version": "4.0.0",
        "name": "ANALCONTROL API",
        "ai_version": "J.A.R.V.I.S. v4.0",
        "features": {
            "jarvis_ai": True,
            "local_ai": True,
            "websocket": True,
            "file_management": True,
            "analytics": True,
            "bulk_operations": True
        },
        "endpoints_count": len([route for route in app.routes]),
        "timestamp": datetime.utcnow().isoformat()
    }
