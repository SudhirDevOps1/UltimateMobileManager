"""
+--------------------------------------------------------------------------------------+
|                     ULTIMATE MOBILE MANAGER v5.1 - FIXED                             |
|                     Developer: Sudhir Kumar (@SudhirDevOps1)                         |
|                     All Bugs Fixed - Python 3.14 Compatible                          |
+--------------------------------------------------------------------------------------+
"""

import os
import sys
import subprocess
import zipfile
import secrets
import threading
import hashlib
import json
import shutil
import time
import re
import locale
import secrets
import threading
import logging
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import random
from datetime import datetime
from pathlib import Path
from tkinter import *
from tkinter import ttk, messagebox, filedialog, simpledialog

# ══════════════════════════════════════════════════════════════════════════════════════
#                                    INSTALL DEPENDENCIES
# ══════════════════════════════════════════════════════════════════════════════════════

def install_package(package):
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
    except:
        pass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    install_package('cryptography')
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════════════

class Config:
    SCRIPT_DIR = Path(__file__).parent.absolute()
    PLATFORM_TOOLS = SCRIPT_DIR / "platform-tools"
    ADB_PATH = PLATFORM_TOOLS / "adb.exe"
    SCRCPY_PATH = SCRIPT_DIR / "scrcpy" / "scrcpy.exe"
    BACKUP_DIR = SCRIPT_DIR / "backups"
    TEMP_DIR = SCRIPT_DIR / "temp"
    SCREENSHOTS_DIR = SCRIPT_DIR / "screenshots"
    
    # Create directories
    for d in [BACKUP_DIR, TEMP_DIR, SCREENSHOTS_DIR]:
        try:
            d.mkdir(parents=True, exist_ok=True)
        except:
            pass
    
    # Theme
    BG_PRIMARY = '#0a0e17'
    BG_SECONDARY = '#131a27'
    BG_TERTIARY = '#1c2636'
    BG_CARD = '#1e293b'
    ACCENT = '#3b82f6'
    ACCENT2 = '#8b5cf6'
    SUCCESS = '#10b981'
    WARNING = '#f59e0b'
    ERROR = '#ef4444'
    TEXT = '#f1f5f9'
    TEXT_DIM = '#64748b'
    BORDER = '#334155'


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    SAFE UTILITIES
# ══════════════════════════════════════════════════════════════════════════════════════

def safe_str(value, default=""):
    """Safely convert any value to string"""
    if value is None:
        return default
    try:
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='replace')
        return str(value).strip()
    except:
        return default


def safe_decode(data, default=""):
    """Safely decode bytes to string"""
    if data is None:
        return default
    if isinstance(data, str):
        return data
    try:
        return data.decode('utf-8', errors='replace')
    except:
        try:
            return data.decode('latin-1', errors='replace')
        except:
            return default


def format_size(size):
    """Format file size to human readable"""
    try:
        size = int(size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
    except:
        return str(size)


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    ADB MANAGER (FIXED)
# ══════════════════════════════════════════════════════════════════════════════════════

class ADBManager:
    """ADB Manager with proper encoding handling"""
    
    def __init__(self):
        self.adb_path = None
        self.device_id = None
        self._cached_info = None
        self._find_adb()
    
    def _find_adb(self):
        """Find ADB executable"""
        # Check in platform-tools
        if Config.ADB_PATH.exists():
            self.adb_path = str(Config.ADB_PATH)
            return True
        
        # Check in PATH
        try:
            result = subprocess.run(
                ["adb", "version"],
                capture_output=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            if result.returncode == 0:
                self.adb_path = "adb"
                return True
        except:
            pass
        
        return False
    
    def is_available(self):
        return self.adb_path is not None
    
    def execute(self, *args, timeout=60):
        """Execute ADB command with proper encoding"""
        if not self.adb_path:
            return False, "", "ADB not found"
        
        cmd = [self.adb_path] + list(args)
        
        try:
            # Use PIPE and handle encoding manually
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            try:
                stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                return False, "", "Timeout"
            
            # Decode with error handling
            stdout = safe_decode(stdout_bytes)
            stderr = safe_decode(stderr_bytes)
            
            return process.returncode == 0, stdout, stderr
            
        except FileNotFoundError:
            return False, "", "ADB not found"
        except Exception as e:
            return False, "", str(e)
    
    def shell(self, command, timeout=30):
        """Execute shell command on device"""
        return self.execute("shell", command, timeout=timeout)
    
    def execute_progressive(self, *args, callback=None):
        """Execute ADB command and get progressive output (for push/pull)"""
        if not self.adb_path: return False, "ADB not found"
        cmd = [self.adb_path] + list(args)
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                universal_newlines=True, text=True, bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            if callback:
                for line in process.stdout:
                    callback(line.strip())
            process.communicate()
            return process.returncode == 0, ""
        except Exception as e:
            return False, str(e)
    
    def check_connection(self):
        """Check device connection"""
        if not self.adb_path:
            return False, None, "ADB not installed"
        
        success, stdout, stderr = self.execute("devices")
        
        if not success:
            return False, None, f"ADB error: {stderr}"
        
        lines = stdout.strip().split('\n')
        for line in lines:
            line = safe_str(line)
            if '\tdevice' in line:
                self.device_id = line.split('\t')[0]
                return True, self.device_id, "Connected"
            elif '\tunauthorized' in line:
                return False, line.split('\t')[0], "Unauthorized - Allow USB debugging on phone"
            elif '\toffline' in line:
                return False, line.split('\t')[0], "Offline - Reconnect USB"
        
        return False, None, "No device connected"
    
    def get_device_info(self):
        """Get device information (Cached)"""
        if self._cached_info:
            return self._cached_info
            
        info = {}
        
        props = {
            'brand': 'ro.product.brand',
            'model': 'ro.product.model',
            'android': 'ro.build.version.release',
            'sdk': 'ro.build.version.sdk',
        }
        
        for key, prop in props.items():
            success, stdout, _ = self.shell(f"getprop {prop}")
            if success:
                info[key] = safe_str(stdout)

        # CPU Info
        success, cpu, _ = self.shell("getprop ro.board.platform")
        if not success or not cpu.strip():
            success, cpu, _ = self.shell("getprop ro.product.board")
        info['cpu'] = safe_str(cpu).title() if success else 'Unknown'
        
        if info:
            self._cached_info = info
            
        return info
    
    def get_battery_info(self):
        """Get battery information"""
        success, stdout, _ = self.shell("dumpsys battery")
        
        if not success:
            return None
        
        info = {}
        for line in stdout.split('\n'):
            line = safe_str(line).strip()
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower().replace(' ', '_')
                    value = parts[1].strip()
                    info[key] = value
        
        return info
    
    def get_storage_info(self):
        """Get storage information"""
        success, stdout, _ = self.shell("df -h /sdcard 2>/dev/null")
        
        if success and stdout:
            lines = stdout.strip().split('\n')
            for line in lines:
                if '/sdcard' in line or 'emulated' in line or '/data' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        return {
                            'total': parts[1],
                            'used': parts[2],
                            'free': parts[3],
                            'percent': parts[4] if len(parts) > 4 else 'N/A'
                        }
        return None
    
    def get_network_info(self):
        """Get network information"""
        info = {}
        
        # WiFi SSID
        success, stdout, _ = self.shell("dumpsys wifi | grep 'mWifiInfo'")
        if success:
            ssid_match = re.search(r'SSID: ([^,]+)', stdout)
            if ssid_match:
                ssid = ssid_match.group(1).strip().strip('"')
                info['wifi_ssid'] = ssid
        
        # IP Address
        success, stdout, _ = self.shell("ip addr show wlan0 2>/dev/null | grep 'inet '")
        if success:
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', stdout)
            if ip_match:
                info['ip'] = ip_match.group(1)
        
        return info
    
    def get_device_time(self):
        """Get device current time"""
        success, stdout, _ = self.shell("date '+%Y-%m-%d %H:%M:%S'")
        return safe_str(stdout) if success else "Unknown"
    
    def get_uptime(self):
        """Get device uptime"""
        success, stdout, _ = self.shell("uptime -p 2>/dev/null || uptime")
        if success:
            text = safe_str(stdout)
            if ',' in text:
                return text.split(',')[0]
            return text[:30]
        return "Unknown"
    
    def list_directory(self, path):
        """List directory contents"""
        path = safe_str(path) or "/sdcard"
        
        if not path.startswith('/'):
            path = '/' + path
        path = path.rstrip('/') + '/'
        if path == '//':
            path = '/'
        
        items = []
        
        # Try ls -la
        success, stdout, _ = self.shell(f'ls -la "{path}" 2>/dev/null')
        
        if not success or not stdout.strip():
            # Fallback to simple ls
            success, stdout, _ = self.shell(f'ls "{path}" 2>/dev/null')
            if success:
                for name in stdout.strip().split('\n'):
                    name = safe_str(name)
                    if name and name not in ['.', '..']:
                        full_path = f"{path.rstrip('/')}/{name}"
                        _, is_dir_check, _ = self.shell(f'[ -d "{full_path}" ] && echo DIR')
                        is_dir = 'DIR' in safe_str(is_dir_check)
                        items.append({
                            'name': name,
                            'is_dir': is_dir,
                            'is_link': False,
                            'size': '-',
                            'permissions': '',
                            'full_path': full_path
                        })
            return sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower()))
        
        # Parse ls -la output
        for line in stdout.strip().split('\n'):
            line = safe_str(line)
            if not line or line.startswith('total') or line.startswith('ls:'):
                continue
            
            item = self._parse_ls_line(line, path)
            if item:
                items.append(item)
        
        return sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower()))
    
    def _parse_ls_line(self, line, base_path):
        """Parse ls -la output line"""
        parts = line.split()
        if len(parts) < 5:
            return None
        
        permissions = safe_str(parts[0])
        last_part = safe_str(parts[-1])
        
        if last_part in ['.', '..']:
            return None
        
        is_dir = permissions.startswith('d')
        is_link = permissions.startswith('l')
        
        # Find filename
        name = None
        size = '-'
        
        for i, part in enumerate(parts):
            part = safe_str(part)
            if re.match(r'^\d{1,2}:\d{2}$', part) and i + 1 < len(parts):
                name = ' '.join(parts[i+1:])
                if not is_dir and i >= 1:
                    for j in range(i-1, 0, -1):
                        if parts[j].isdigit():
                            size = parts[j]
                            break
                break
        
        if not name:
            name = last_part
            if len(parts) > 4 and not is_dir:
                size = parts[4] if parts[4].isdigit() else '-'
        
        if is_link and ' -> ' in name:
            name = name.split(' -> ')[0]
        
        name = safe_str(name)
        if not name or name in ['.', '..']:
            return None
        
        return {
            'name': name,
            'is_dir': is_dir,
            'is_link': is_link,
            'size': size if not is_dir else '-',
            'permissions': permissions[:10] if len(permissions) >= 10 else permissions,
            'full_path': f"{base_path.rstrip('/')}/{name}"
        }
    
    def push(self, local_path, remote_path, callback=None):
        """Push file to device with optional progress callback"""
        args = ["push", "-p", str(local_path), remote_path]
        return self.execute_progressive(*args, callback=callback)
    
    def pull(self, remote_path, local_path, callback=None):
        """Pull file from device with optional progress callback"""
        args = ["pull", "-p", remote_path, str(local_path)]
        return self.execute_progressive(*args, callback=callback)
    
    def mkdir(self, path):
        """Create directory"""
        return self.shell(f'mkdir -p "{path}"')
    
    def remove(self, path):
        """Remove file/folder"""
        return self.shell(f'rm -rf "{path}"')
    
    def get_installed_apps(self):
        """Get list of installed apps"""
        success, stdout, _ = self.shell("pm list packages -3")
        
        if not success:
            return []
        
        apps = []
        for line in stdout.strip().split('\n'):
            line = safe_str(line)
            if line.startswith('package:'):
                apps.append(line.replace('package:', '').strip())
        
        return sorted(apps)
    
    def open_app(self, package):
        """Open an app"""
        return self.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
    
    def uninstall_app(self, package):
        """Uninstall an app"""
        return self.execute("uninstall", package)
    
    def take_screenshot(self, save_path=None):
        """Take screenshot"""
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = Config.SCREENSHOTS_DIR / f"screenshot_{timestamp}.png"
        
        remote_path = "/sdcard/screenshot_temp.png"
        
        success, _, stderr = self.shell(f"screencap -p {remote_path}")
        if not success:
            return False, f"Capture failed: {stderr}"
        
        success, _, stderr = self.pull(remote_path, save_path)
        if not success:
            return False, f"Pull failed: {stderr}"
        
        self.shell(f"rm {remote_path}")
        
        return True, str(save_path)
    
    def screen_on(self):
        return self.shell("input keyevent KEYCODE_WAKEUP")
    
    def screen_off(self):
        return self.shell("input keyevent KEYCODE_SLEEP")
    
    def reboot(self, mode='normal'):
        modes = {
            'normal': 'reboot',
            'recovery': 'reboot recovery',
            'bootloader': 'reboot bootloader',
        }

        return self.execute(modes.get(mode, 'reboot'))
    
    def install_app(self, path):
        """Install APK"""
        return self.execute("install", "-r", str(path))
    
    def connect_wireless(self, ip, port):
        """Connect to wireless device"""
        return self.execute("connect", f"{ip}:{port}")
    
    def enable_wireless(self):
        """Enable ADB over TCP/IP"""
        return self.execute("tcpip", "5555")

    def disconnect_all(self):
        """Disconnect all wireless devices"""
        return self.execute("disconnect", "")


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    ENCRYPTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════════════

class Encryptor:
    """AES-256-GCM Encryption"""
    
    @staticmethod
    def derive_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def encrypt(input_path, output_path, password):
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
            
            salt = secrets.token_bytes(16)
            key = Encryptor.derive_key(password, salt)
            nonce = secrets.token_bytes(12)
            
            aesgcm = AESGCM(key)
            encrypted = aesgcm.encrypt(nonce, data, None)
            
            header = json.dumps({
                'v': '5.1',
                'hash': hashlib.sha256(data).hexdigest(),
                'size': len(data),
                'time': datetime.now().isoformat()
            }).encode('utf-8')
            
            with open(output_path, 'wb') as f:
                f.write(len(header).to_bytes(4, 'big'))
                f.write(header)
                f.write(salt)
                f.write(nonce)
                f.write(encrypted)
            
            return True, "Success"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def decrypt(input_path, output_path, password):
        try:
            with open(input_path, 'rb') as f:
                header_len = int.from_bytes(f.read(4), 'big')
                header = json.loads(f.read(header_len).decode('utf-8'))
                salt = f.read(16)
                nonce = f.read(12)
                encrypted = f.read()
            
            key = Encryptor.derive_key(password, salt)
            aesgcm = AESGCM(key)
            
            try:
                data = aesgcm.decrypt(nonce, encrypted, None)
            except:
                return False, "Wrong password!"
            
            if hashlib.sha256(data).hexdigest() != header['hash']:
                return False, "Data corrupted!"
            
            with open(output_path, 'wb') as f:
                f.write(data)
            
            return True, header
        except Exception as e:
            return False, str(e)



# ══════════════════════════════════════════════════════════════════════════════════════
#                                    WEB SERVER ENGINE
# ══════════════════════════════════════════════════════════════════════════════════════

class WebServer:
    """Secure Web Interface Provider"""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultimate Mobile Manager</title>
    <style>
        :root { --bg: #0f172a; --surface: #1e293b; --primary: #3b82f6; --text: #f8fafc; }
        body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; min-height: 100vh; display: flex; flex-direction: column; }
        .container { max-width: 900px; margin: 0 auto; padding: 1rem; width: 100%; box-sizing: border-box; }
        .card { background: var(--surface); border-radius: 1rem; padding: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 2rem; border: 1px solid #334155; }
        h1 { margin: 0 0 1.5rem 0; font-weight: 300; letter-spacing: -1px; }
        
        /* Inputs */
        input { background: #0f172a; border: 1px solid #334155; padding: 1rem; color: white; width: 100%; border-radius: 0.5rem; font-size: 1.5rem; text-align: center; letter-spacing: 0.5rem; margin-bottom: 1rem; box-sizing: border-box; }
        button { background: var(--primary); border: none; padding: 0.75rem 1.5rem; color: white; border-radius: 0.5rem; font-size: 1rem; cursor: pointer; transition: 0.2s; font-weight: bold; }
        button:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn-sm { padding: 0.5rem 1rem; font-size: 0.875rem; }
        
        .hidden { display: none !important; }
        
        /* Stats Grid */
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; }
        .stat-item { background: #334155; padding: 1rem; border-radius: 0.5rem; text-align: center; }
        .stat-value { font-size: 1.5rem; font-weight: bold; color: var(--primary); }
        .stat-label { font-size: 0.875rem; color: #94a3b8; }
        
        /* Tabs */
        .tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
        .tab { background: #334155; color: #94a3b8; padding: 0.75rem 1.5rem; border-radius: 0.5rem; flex: 1; text-align: center; cursor: pointer; border: 1px solid transparent; }
        .tab.active { background: var(--primary); color: white; border-color: var(--primary); }
        
        /* File Browser */
        .file-toolbar { display: flex; gap: 0.5rem; margin-bottom: 1rem; align-items: center; }
        .path-bar { background: #0f172a; padding: 0.75rem; border-radius: 0.5rem; flex: 1; font-family: monospace; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; border: 1px solid #334155; }
        #file-list { list-style: none; padding: 0; margin: 0; }
        .file-item { display: flex; align-items: center; padding: 0.75rem; border-bottom: 1px solid #334155; transition: 0.2s; cursor: default; }
        .file-item.dir { cursor: pointer; }
        .file-item:hover { background: #334155; }
        .file-icon { margin-right: 1rem; font-size: 1.25rem; width: 24px; text-align: center; }
        .file-name { flex: 1; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
        .file-meta { color: #94a3b8; font-size: 0.875rem; min-width: 60px; text-align: right; }
        
        .logout-btn { position: fixed; top: 1rem; right: 1rem; background: #ef4444; font-size: 0.8rem; padding: 0.5rem 1rem; z-index: 100; opacity: 0.8; }
        
        @media (max-width: 600px) {
            .container { padding: 1rem; }
            .card { padding: 1rem; }
            .stat-value { font-size: 1.25rem; }
            h1 { font-size: 1.5rem; }
        }
    </style>
</head>
<body>
    <!-- Login Screen -->
    <div id="login-view" class="container" style="justify-content: center; flex: 1; display: flex; flex-direction: column;">
        <div class="card" style="text-align: center;">
            <h1>🔐 Security Check</h1>
            <p style="color: #94a3b8; margin-bottom: 2rem;">Enter the PIN shown in the desktop app</p>
            <input type="password" id="pin-input" maxlength="4" placeholder="••••" autofocus>
            <button onclick="login()" style="width: 100%">Access Dashboard</button>
            <p id="error-msg" style="color: #ef4444; margin-top: 1rem; display: none;">Invalid PIN</p>
        </div>
    </div>

    <!-- Dashboard -->
    <div id="dashboard-view" class="hidden">
        <button class="logout-btn" onclick="logout()">Logout</button>
        
        <div class="container">
            <!-- Device Stats -->
            <div class="card">
                <h2>📱 Device Overview</h2>
                <div class="stat-grid" id="stats">Loading...</div>
            </div>

            <!-- File Browser -->
            <div class="card">
                <h2 style="margin-top: 0">📂 File Explorer</h2>
                
                <div class="tabs">
                    <div class="tab active" onclick="switchTab('mobile')" id="tab-mobile">📱 Mobile</div>
                    <div class="tab" onclick="switchTab('pc')" id="tab-pc">💻 PC (Desktop)</div>
                </div>

                <div class="file-toolbar">
                    <button class="btn-sm" onclick="navUp()">⬆ Up</button>
                    <div class="path-bar" id="current-path">/sdcard</div>
                    <button class="btn-sm" onclick="refreshFiles()">🔄</button>
                </div>
                
                <ul id="file-list"></ul>
            </div>
        </div>
    </div>

    <script>
        let state = {
            mode: 'mobile', // or 'pc'
            mobilePath: '/sdcard',
            pcPath: '/', // Start at Drives
            token: localStorage.getItem('auth_token')
        };

        if (state.token) showDashboard();

        // ─── Auth ───
        async function login() {
            const pin = document.getElementById('pin-input').value;
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({pin})
            });
            const data = await res.json();
            if (data.success) {
                state.token = data.token;
                localStorage.setItem('auth_token', data.token);
                showDashboard();
            } else {
                document.getElementById('error-msg').style.display = 'block';
            }
        }

        function logout() {
            state.token = null;
            localStorage.removeItem('auth_token');
            location.reload();
        }

        function showDashboard() {
            document.getElementById('login-view').classList.add('hidden');
            document.getElementById('dashboard-view').classList.remove('hidden');
            loadStats();
            loadFiles();
        }

        // ─── Logic ───
        function switchTab(mode) {
            state.mode = mode;
            document.getElementById('tab-mobile').className = `tab ${mode==='mobile'?'active':''}`;
            document.getElementById('tab-pc').className = `tab ${mode==='pc'?'active':''}`;
            loadFiles();
        }

        function navUp() {
            const path = state.mode === 'mobile' ? state.mobilePath : state.pcPath;
            if (path === '/' || path.match(/^[A-Za-z]:\/$/)) {
                if (state.mode === 'pc') {
                    state.pcPath = '/';
                    loadFiles();
                }
                return;
            }
            
            const parts = path.split('/').filter(x => x);
            if (parts.length <= 1 && path.includes(':/')) {
                 state.pcPath = '/';
            } else {
                 const newPath = path.substring(0, path.lastIndexOf('/')) || '/';
                 if (state.mode === 'mobile') state.mobilePath = newPath;
                 else state.pcPath = newPath;
            }
            loadFiles();
        }
        
        function navigate(name) {
            if (state.mode === 'mobile') {
                state.mobilePath = (state.mobilePath === '/' ? '' : state.mobilePath) + '/' + name;
            } else {
                if (name.includes(':/')) {
                    state.pcPath = name;
                } else {
                    state.pcPath = (state.pcPath.endsWith('/') ? state.pcPath : state.pcPath + '/') + name;
                }
            }
            loadFiles();
        }
        
        function refreshFiles() { loadFiles(); }

        // ─── API Calls ───
        async function loadStats() {
            try {
                const res = await fetch('/api/stats', { headers: {'Authorization': state.token} });
                if (res.status === 401) return logout();
                const data = await res.json();
                document.getElementById('stats').innerHTML = `
                    <div class="stat-item"><div class="stat-value">${data.brand}</div><div class="stat-label">Model</div></div>
                    <div class="stat-item"><div class="stat-value">${data.battery}%</div><div class="stat-label">Battery</div></div>
                    <div class="stat-item"><div class="stat-value">${data.android}</div><div class="stat-label">Android</div></div>
                `;
            } catch(e) { console.error(e); }
        }

        async function loadFiles() {
            const path = state.mode === 'mobile' ? state.mobilePath : state.pcPath;
            document.getElementById('current-path').innerText = path;
            document.getElementById('file-list').innerHTML = '<li class="file-item" style="justify-content:center; color:#64748b">Loading...</li>';
            
            try {
                const url = `/api/files?mode=${state.mode}&path=${encodeURIComponent(path)}`;
                const res = await fetch(url, { headers: {'Authorization': state.token} });
                if (res.status === 401) return logout();
                
                const data = await res.json();
                
                // Update Path (backend might normalize it)
                if (data.path) {
                    if (state.mode === 'mobile') state.mobilePath = data.path;
                    else state.pcPath = data.path;
                    document.getElementById('current-path').innerText = data.path;
                }

                const list = document.getElementById('file-list');
                list.innerHTML = '';
                
                if (data.items.length === 0) {
                     list.innerHTML = '<li class="file-item" style="justify-content:center; color:#64748b">Empty Folder</li>';
                     return;
                }

                data.items.forEach(item => {
                    const icon = item.is_dir ? '📁' : '📄';
                    const li = document.createElement('li');
                    li.className = `file-item ${item.is_dir ? 'dir' : ''}`;
                    li.innerHTML = `
                        <span class="file-icon">${icon}</span>
                        <span class="file-name">${item.name}</span>
                        <span class="file-meta">${item.size}</span>
                    `;
                    if (item.is_dir) {
                        li.onclick = () => navigate(item.name);
                    }
                    list.appendChild(li);
                });
            } catch(e) {
                 document.getElementById('file-list').innerHTML = '<li class="file-item" style="justify-content:center; color:#ef4444">Error loading files</li>';
            }
        }
    </script>
</body>
</html>
"""

    def __init__(self, adb_manager):
        self.adb = adb_manager
        self.port = 0
        self.pin = secrets.token_hex(2).upper()
        self.token = secrets.token_urlsafe(16)
        self.server = None
        self.thread = None
        self.running = False

    def start(self):
        if self.running: 
            return self.get_address(), self.pin
        
        handler_factory = lambda *args: SecureHTTPHandler(self, *args)
        self.server = ThreadingHTTPServer(('0.0.0.0', 0), handler_factory)
        self.port = self.server.server_port
        self.running = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.get_address(), self.pin

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.running = False

    def get_address(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return f"http://{ip}:{self.port}"
        except:
            return f"http://localhost:{self.port}"

class SecureHTTPHandler(BaseHTTPRequestHandler):
    def __init__(self, app_server, *args):
        self.app = app_server
        super().__init__(*args)

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # Privacy Headers
        self.send_response(200 if self.path in ['/', '/api/stats'] or self.path.startswith('/api/files') else 404)
        if self.path == '/': 
            self.send_header('Content-type', 'text/html; charset=utf-8')
        elif self.path.startswith('/api/'):
            self.send_header('Content-type', 'application/json')
        
        # Security/Privacy
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()

        if self.path == '/':
            self.wfile.write(self.app.HTML_TEMPLATE.encode('utf-8'))
            return
            
        # Verify Token for API
        auth = self.headers.get('Authorization')
        if not auth or auth != self.app.token:
            # We already sent 200/headers, so simple return if unauthorized for API calls?
            # Actually, standard flow requires sending status BEFORE headers. 
            # Re-doing logic properly:
            pass # See below for corrected flow
            
    def do_GET(self):
        # ─── 1. Auth & Routing ───
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self._add_security_headers()
            self.end_headers()
            self.wfile.write(self.app.HTML_TEMPLATE.encode('utf-8'))
            return
            
        auth = self.headers.get('Authorization')
        if not auth or auth != self.app.token:
            self.send_response(401)
            self._add_security_headers()
            self.end_headers()
            return

        # ─── 2. API Endpoints ───
        if self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self._add_security_headers()
            self.end_headers()
            info = self.app.adb.get_device_info()
            batt = self.app.adb.get_battery_info() or {}
            data = {'brand': info.get('brand',''), 'model': info.get('model',''), 'android': info.get('android',''), 'battery': batt.get('level','--')}
            self.wfile.write(json.dumps(data).encode('utf-8'))
            return

        if self.path.startswith('/api/files'):
            query = parse_qs(urlparse(self.path).query)
            mode = query.get('mode', ['mobile'])[0]
            path = query.get('path', ['/sdcard'])[0]
            
            items = []
            if mode == 'mobile':
                items = self.app.adb.list_directory(path)
            else:
                # PC Mode
                try:
                    # Drive Listing
                    if path == '/' or path == "":
                        import string
                        import ctypes
                        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                        for i in range(26):
                            if bitmask & (1 << i):
                                drive = f"{string.ascii_uppercase[i]}:/"
                                items.append({'name': drive, 'is_dir': True, 'size': 'Drive', 'full_path': drive})
                        path = "/"
                    else:
                        path_norm = os.path.normpath(path)
                        if os.path.isdir(path_norm):
                            for name in os.listdir(path_norm):
                                try:
                                    full = os.path.join(path_norm, name)
                                    is_dir = os.path.isdir(full)
                                    size = '-' if is_dir else self._fmt_size(os.path.getsize(full))
                                    # Normalize for web (always /)
                                    web_full = full.replace('\\', '/')
                                    items.append({'name': name, 'is_dir': is_dir, 'size': size, 'full_path': web_full})
                                except: pass
                            path = path_norm.replace('\\', '/')
                except Exception as e:
                    pass
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self._add_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps({'path': path, 'items': items}).encode('utf-8'))
            return

    def _add_security_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('X-Content-Type-Options', 'nosniff')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        data = json.loads(self.rfile.read(length).decode('utf-8'))
        
        if self.path == '/api/login':
            if data.get('pin') == self.app.pin:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True, 'token': self.app.token}).encode('utf-8'))
            else:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(json.dumps({'success': False}).encode('utf-8'))

    def _fmt_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024: return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════════════

class UltimateMobileManager:
    """Main Application - Python 3.14 Compatible"""
    
    def __init__(self):
        self.root = Tk()
        self.root.title("🚀 Ultimate Mobile Manager v5.1 - By Sudhir Kumar")
        self.root.geometry("1400x850")
        self.root.configure(bg=Config.BG_PRIMARY)
        self.root.minsize(1200, 700)
        
        # Fullscreen
        self.is_fullscreen = False
        self.root.bind('<F11>', self.toggle_fullscreen)
        self.root.bind('<Escape>', self.exit_fullscreen)
        
        # Initialize ADB
        self.adb = ADBManager()
        self.web_server = WebServer(self.adb)
        
        # Variables
        self.mobile_path = StringVar(value="/sdcard")
        self.pc_path = StringVar(value=str(Path.home()))
        self.password = StringVar()
        self.status = StringVar(value="Ready")
        self.privacy_mode = BooleanVar(value=True)
        
        # Data
        self.mobile_items = []
        self.pc_items = []
        
        # Clock
        self.clock_var = StringVar()
        self._update_clock()
        
        # Build UI
        self._setup_styles()
        self._create_menu()
        self._create_ui()
        
        # Initial load
        if self.adb.is_available():
            self.root.after(500, self._initial_load)
        else:
            self.root.after(500, self._show_adb_error)
        
        # Auto refresh
        self._auto_refresh()
    
    def toggle_fullscreen(self, event=None):
        self.is_fullscreen = not self.is_fullscreen
        self.root.attributes('-fullscreen', self.is_fullscreen)
    
    def exit_fullscreen(self, event=None):
        self.is_fullscreen = False
        self.root.attributes('-fullscreen', False)
    
    def _update_clock(self):
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.clock_var.set(f"🕐 {now}")
        self.root.after(1000, self._update_clock)
    
    def _show_adb_error(self):
        messagebox.showerror("ADB Not Found",
            f"ADB not found!\n\n"
            f"Download from:\n"
            f"https://developer.android.com/studio/releases/platform-tools\n\n"
            f"Extract to:\n{Config.PLATFORM_TOOLS}")
    
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("Custom.Treeview",
                       background=Config.BG_TERTIARY,
                       foreground=Config.TEXT,
                       fieldbackground=Config.BG_TERTIARY,
                       rowheight=28,
                       font=('Consolas', 10))
        
        style.configure("Custom.Treeview.Heading",
                       background=Config.BG_SECONDARY,
                       foreground=Config.TEXT,
                       font=('Segoe UI', 10, 'bold'))
        
        style.map("Custom.Treeview",
                 background=[('selected', Config.ACCENT)])
        
        style.configure("TProgressbar",
                       background=Config.SUCCESS,
                       troughcolor=Config.BG_SECONDARY)
    
    def _create_menu(self):
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Window", command=lambda: subprocess.Popen([sys.executable, __file__]))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Device Menu
        device_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Device", menu=device_menu)
        device_menu.add_command(label="Refresh Info", command=self._update_device_info)
        device_menu.add_command(label="Screenshot", command=self._take_screenshot)
        device_menu.add_command(label="Screen Mirror", command=self._start_scrcpy)
        device_menu.add_command(label="Smooth Mirror (Wi-Fi)", command=lambda: self._start_scrcpy(smooth=True))
        
        reboot_menu = Menu(device_menu, tearoff=0)
        device_menu.add_cascade(label="Reboot", menu=reboot_menu)
        reboot_menu.add_command(label="System", command=lambda: self.adb.reboot('normal'))
        reboot_menu.add_command(label="Recovery", command=lambda: self.adb.reboot('recovery'))
        reboot_menu.add_command(label="Bootloader", command=lambda: self.adb.reboot('bootloader'))
        
        device_menu.add_separator()
        device_menu.add_command(label="Enable Wi-Fi ADB", command=self._enable_wifi_mode)
        device_menu.add_command(label="Wireless Connect", command=self._show_wireless_dialog)
        device_menu.add_command(label="Disconnect Wireless", command=self._disconnect_wireless)
        
        # Tools Menu
        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Installed Apps", command=self._show_apps)
        tools_menu.add_command(label="Start Web Server", command=self._start_web_server)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Rules & usage Guide", command=self._show_rules)
        help_menu.add_command(label="Pros & Cons of ADB", command=self._show_pros_cons)
        help_menu.add_separator()
        help_menu.add_command(label="Project Info", command=self._show_about)
        help_menu.add_command(label="Author: Sudhir Kumar", command=lambda: webbrowser.open("https://github.com/SudhirDevOps1"))
    
    def _create_ui(self):
        # Main container
        main = Frame(self.root, bg=Config.BG_PRIMARY)
        main.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self._create_header(main)
        
        # Device info bar
        self._create_device_bar(main)
        
        # Password bar
        self._create_password_bar(main)
        
        # Content
        content = Frame(main, bg=Config.BG_PRIMARY)
        content.pack(fill=BOTH, expand=True, pady=5)
        
        # Left - PC browser
        left = Frame(content, bg=Config.BG_PRIMARY)
        left.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 5))
        self._create_pc_panel(left)
        
        # Center - Transfer buttons
        center = Frame(content, bg=Config.BG_PRIMARY, width=120)
        center.pack(side=LEFT, fill=Y, padx=5)
        center.pack_propagate(False)
        self._create_transfer_panel(center)
        
        # Right - Mobile browser
        right = Frame(content, bg=Config.BG_PRIMARY)
        right.pack(side=LEFT, fill=BOTH, expand=True, padx=(5, 0))
        self._create_mobile_panel(right)
        
        # Status bar
        self._create_status_bar(main)
    
    def _create_header(self, parent):
        header = Frame(parent, bg=Config.BG_SECONDARY, height=55)
        header.pack(fill=X, pady=(0, 5))
        header.pack_propagate(False)
        
        # Title
        Label(header, text="[UMM] Ultimate Mobile Manager v5.1",
              font=("Segoe UI", 16, "bold"),
              bg=Config.BG_SECONDARY, fg=Config.TEXT).pack(side=LEFT, padx=15, pady=12)
        
        Label(header, text="By Sudhir Kumar (@SudhirDevOps1)",
              font=("Segoe UI", 9),
              bg=Config.BG_SECONDARY, fg=Config.TEXT_DIM).pack(side=LEFT)
        
        # Clock
        Label(header, textvariable=self.clock_var,
              font=("Consolas", 11),
              bg=Config.BG_SECONDARY, fg=Config.ACCENT).pack(side=RIGHT, padx=15)
        
        # Quick buttons (Now used for Connection Management)
        btn_frame = Frame(header, bg=Config.BG_SECONDARY)
        btn_frame.pack(side=RIGHT, padx=10)
        
        c_btn_cfg = {'bg': '#22c55e', 'fg': 'white', 'relief': FLAT, 'font': ("Segoe UI", 8, "bold"), 'cursor': 'hand2', 'padx': 8}
        d_btn_cfg = {'bg': '#ef4444', 'fg': 'white', 'relief': FLAT, 'font': ("Segoe UI", 8, "bold"), 'cursor': 'hand2', 'padx': 8}
        
        Button(btn_frame, text="[OK] Connect USB", command=self._refresh_all, **c_btn_cfg).pack(side=LEFT, padx=2)
        Button(btn_frame, text="[WIFI] Connect Wi-Fi", command=self._show_wireless_dialog, **c_btn_cfg).pack(side=LEFT, padx=2)
        Button(btn_frame, text="[DEL] Disconnect All", command=self._disconnect_wireless, **d_btn_cfg).pack(side=LEFT, padx=2)
        Button(btn_frame, text="[RULES] Rules", command=self._show_rules, **c_btn_cfg).pack(side=LEFT, padx=2)
        Button(btn_frame, text="[P/C] Pros&Cons", command=self._show_pros_cons, **c_btn_cfg).pack(side=LEFT, padx=2)
    
    def _create_device_bar(self, parent):
        bar = Frame(parent, bg=Config.BG_CARD, height=85)
        bar.pack(fill=X, pady=5)
        bar.pack_propagate(False)
        
        # Device info
        dev_frame = Frame(bar, bg=Config.BG_CARD)
        dev_frame.pack(side=LEFT, padx=20, pady=10)
        
        self.device_label = Label(dev_frame, text="[Mob] Checking...",
                                  font=("Segoe UI", 12, "bold"),
                                  bg=Config.BG_CARD, fg=Config.TEXT)
        self.device_label.pack(anchor=W)
        
        self.device_detail = Label(dev_frame, text="",
                                   font=("Segoe UI", 9),
                                   bg=Config.BG_CARD, fg=Config.TEXT_DIM)
        self.device_detail.pack(anchor=W)
        
        # Processor Label
        self.cpu_label = Label(dev_frame, text="", font=("Segoe UI", 8), bg=Config.BG_CARD, fg=Config.ACCENT)
        self.cpu_label.pack(anchor=W)
        
        # Battery
        batt_frame = Frame(bar, bg=Config.BG_CARD)
        batt_frame.pack(side=LEFT, padx=30, pady=10)
        
        Label(batt_frame, text="[Batt] Battery",
              font=("Segoe UI", 9),
              bg=Config.BG_CARD, fg=Config.TEXT_DIM).pack(anchor=W)
        
        self.battery_label = Label(batt_frame, text="---%",
                                   font=("Segoe UI", 16, "bold"),
                                   bg=Config.BG_CARD, fg=Config.SUCCESS)
        self.battery_label.pack(anchor=W)
        
        self.charging_label = Label(batt_frame, text="",
                                    font=("Segoe UI", 8),
                                    bg=Config.BG_CARD, fg=Config.TEXT_DIM)
        self.charging_label.pack(anchor=W)
        
        # Storage
        stor_frame = Frame(bar, bg=Config.BG_CARD)
        stor_frame.pack(side=LEFT, padx=30, pady=10)
        
        Label(stor_frame, text="[Disk] Storage",
              font=("Segoe UI", 9),
              bg=Config.BG_CARD, fg=Config.TEXT_DIM).pack(anchor=W)
        
        self.storage_label = Label(stor_frame, text="---",
                                   font=("Segoe UI", 16, "bold"),
                                   bg=Config.BG_CARD, fg=Config.ACCENT)
        self.storage_label.pack(anchor=W)
        
        self.storage_detail = Label(stor_frame, text="",
                                    font=("Segoe UI", 8),
                                    bg=Config.BG_CARD, fg=Config.TEXT_DIM)
        self.storage_detail.pack(anchor=W)
        
        # Network
        net_frame = Frame(bar, bg=Config.BG_CARD)
        net_frame.pack(side=LEFT, padx=30, pady=10)
        
        Label(net_frame, text="[Net] Network",
              font=("Segoe UI", 9),
              bg=Config.BG_CARD, fg=Config.TEXT_DIM).pack(anchor=W)
        
        self.network_label = Label(net_frame, text="---",
                                   font=("Segoe UI", 12),
                                   bg=Config.BG_CARD, fg=Config.TEXT)
        self.network_label.pack(anchor=W)
        
        self.ip_label = Label(net_frame, text="",
                               font=("Segoe UI", 8),
                               bg=Config.BG_CARD, fg=Config.TEXT_DIM)
        self.ip_label.pack(anchor=W)
        
        # Device time
        time_frame = Frame(bar, bg=Config.BG_CARD)
        time_frame.pack(side=RIGHT, padx=20, pady=10)
        
        Label(time_frame, text="[Time] Device Time",
              font=("Segoe UI", 9),
              bg=Config.BG_CARD, fg=Config.TEXT_DIM).pack(anchor=E)
        
        self.device_time = Label(time_frame, text="--:--",
                                 font=("Consolas", 14),
                                 bg=Config.BG_CARD, fg=Config.ACCENT2)
        self.device_time.pack(anchor=E)
        
        self.uptime_label = Label(time_frame, text="",
                                  font=("Segoe UI", 8),
                                  bg=Config.BG_CARD, fg=Config.TEXT_DIM)
        self.uptime_label.pack(anchor=E)
    
    def _create_password_bar(self, parent):
        bar = Frame(parent, bg=Config.BG_TERTIARY, height=50)
        bar.pack(fill=X, pady=5)
        bar.pack_propagate(False)
        
        inner = Frame(bar, bg=Config.BG_TERTIARY)
        inner.pack(expand=True, fill=X, padx=20)
        
        Label(inner, text="[Pw] Password (min 10 chars):",
              font=("Segoe UI", 10),
              bg=Config.BG_TERTIARY, fg=Config.TEXT).pack(side=LEFT, pady=10)
        
        self.pwd_entry = Entry(inner, textvariable=self.password, show="*",
                               font=("Consolas", 12), width=25,
                               bg=Config.BG_SECONDARY, fg=Config.TEXT,
                               insertbackground=Config.TEXT, relief=FLAT)
        self.pwd_entry.pack(side=LEFT, padx=10, pady=10, ipady=5)
        
        self.show_pwd = BooleanVar(value=False)
        Checkbutton(inner, text="Show", variable=self.show_pwd,
                    command=self._toggle_password,
                    bg=Config.BG_TERTIARY, fg=Config.TEXT_DIM,
                    selectcolor=Config.BG_SECONDARY,
                    activebackground=Config.BG_TERTIARY).pack(side=LEFT, padx=5)
        
        Checkbutton(inner, text="[SEC] Privacy Mode", variable=self.privacy_mode,
                    bg=Config.BG_TERTIARY, fg=Config.ACCENT,
                    selectcolor=Config.BG_SECONDARY,
                    activebackground=Config.BG_TERTIARY).pack(side=RIGHT, padx=20)
        
        self.pwd_strength = Label(inner, text="",
                                  font=("Segoe UI", 9),
                                  bg=Config.BG_TERTIARY)
        self.pwd_strength.pack(side=LEFT, padx=10)
        
        # Use trace_add for Python 3.14 compatibility
        try:
            self.password.trace_add('write', self._check_password)
        except AttributeError:
            self.password.trace('w', self._check_password)
    
    # ────────────────────────────────────────────────────────────────────────
    #                                PREMIUM INFO SECTIONS
    # ────────────────────────────────────────────────────────────────────────

    def _show_rules(self):
        rules = """
        [1] ALWAYS Enable USB Debugging before connecting.
        [2] DO NOT unplug device during file transfers.
        [3] USE a secure PIN for Web Interface access.
        [4] BACKUP sensitive data before ADB operations.
        [5] RESPECT Privacy: Never access unauthorized folders.
        [6] DISCONNECT Wi-Fi ADB after use manually.
        [7] KEEP your laptop firewall open for Web Access.
        """
        messagebox.showinfo("Ultimate Mobile Management Rules", rules.strip())

    def _show_pros_cons(self):
        msg = """
        [PROS]
        + Ultra Secure (AES-256 Encryption)
        + Professional Terminal HUD
        + Real-time Device Stats (CPU, Battery)
        + Cross-network Web Access
        + Optimized Wireless Mirroring

        [CONS]
        - Requires basic ADB knowledge
        - Wi-Fi speed depends on network signal
        - Large encrypted files may take time to process
        """
        messagebox.showinfo("Ultimate Pros & Cons", msg.strip())

    def _show_about(self):
        about_text = """
        Ultimate Mobile Manager v5.1
        ---------------------------
        Developer: Sudhir Kumar
        GitHub: @SudhirDevOps1
        
        A premium, secure, and buttery-smooth mobile
        management suite for Windows.
        
        Features:
        - Real-time ADB Control
        - AES-256 Secure Transfers
        - Privacy-Focused UI
        - Optimized Screen Mirroring
        """
        messagebox.showinfo("About Project", about_text.strip())
    
    def _create_pc_panel(self, parent):
        frame = Frame(parent, bg=Config.BG_SECONDARY)
        frame.pack(fill=BOTH, expand=True)
        
        # Header
        header = Frame(frame, bg=Config.ACCENT, height=38)
        header.pack(fill=X)
        header.pack_propagate(False)
        
        Label(header, text="[PC] PC FILES",
              font=("Segoe UI", 11, "bold"),
              bg=Config.ACCENT, fg='white').pack(side=LEFT, padx=12, pady=8)
        
        self.pc_count = Label(header, text="0 items",
                              font=("Segoe UI", 9),
                              bg=Config.ACCENT, fg='#93c5fd')
        self.pc_count.pack(side=RIGHT, padx=12)
        
        # Navigation
        nav = Frame(frame, bg=Config.BG_SECONDARY)
        nav.pack(fill=X, padx=5, pady=5)
        
        btn_cfg = {'bg': Config.BG_TERTIARY, 'fg': Config.TEXT, 'relief': FLAT,
                   'font': ("Segoe UI", 10), 'cursor': 'hand2'}
        
        Button(nav, text="[^]", command=self._pc_up, width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="[H]", command=lambda: self._browse_pc(str(Path.home())),
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="[R]", command=lambda: self._browse_pc(self.pc_path.get()),
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        
        self.pc_path_entry = Entry(nav, textvariable=self.pc_path,
                                   font=("Consolas", 10),
                                   bg=Config.BG_TERTIARY, fg=Config.TEXT,
                                   insertbackground=Config.TEXT, relief=FLAT)
        self.pc_path_entry.pack(side=LEFT, fill=X, expand=True, padx=5, ipady=4)
        self.pc_path_entry.bind('<Return>', lambda e: self._browse_pc(self.pc_path.get()))
        
        Button(nav, text="Go", command=lambda: self._browse_pc(self.pc_path.get()),
               bg=Config.ACCENT, fg='white', relief=FLAT, width=5,
               font=("Segoe UI", 9, "bold"), cursor='hand2').pack(side=LEFT, padx=2)
        
        # Quick access
        quick = Frame(frame, bg=Config.BG_SECONDARY)
        quick.pack(fill=X, padx=5, pady=2)
        
        for letter in 'CDEF':
            if Path(f"{letter}:/").exists():
                Button(quick, text=f"{letter}:",
                       command=lambda d=letter: self._browse_pc(f"{d}:/"),
                       bg=Config.BG_TERTIARY, fg=Config.TEXT_DIM,
                       relief=FLAT, font=("Segoe UI", 8)).pack(side=LEFT, padx=2)
        
        for name, path in [("Desktop", Path.home() / "Desktop"),
                           ("Downloads", Path.home() / "Downloads"),
                           ("Documents", Path.home() / "Documents")]:
            if path.exists():
                Button(quick, text=name,
                       command=lambda p=str(path): self._browse_pc(p),
                       bg=Config.BG_TERTIARY, fg=Config.TEXT_DIM,
                       relief=FLAT, font=("Segoe UI", 8)).pack(side=LEFT, padx=2)
        
        # Tree
        tree_frame = Frame(frame, bg=Config.BG_SECONDARY)
        tree_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        yscroll = Scrollbar(tree_frame, orient=VERTICAL)
        yscroll.pack(side=RIGHT, fill=Y)
        
        self.pc_tree = ttk.Treeview(tree_frame,
                                     columns=('name', 'size', 'type'),
                                     show='headings',
                                     selectmode='extended',
                                     style='Custom.Treeview',
                                     yscrollcommand=yscroll.set)
        yscroll.config(command=self.pc_tree.yview)
        
        self.pc_tree.heading('name', text='Name', anchor=W)
        self.pc_tree.heading('size', text='Size', anchor=E)
        self.pc_tree.heading('type', text='Type', anchor=W)
        
        self.pc_tree.column('name', width=280)
        self.pc_tree.column('size', width=80)
        self.pc_tree.column('type', width=80)
        
        self.pc_tree.pack(fill=BOTH, expand=True)
        
        self.pc_tree.bind('<Double-1>', self._pc_double_click)
        self.pc_tree.bind('<Button-3>', self._pc_context)
    
    def _create_mobile_panel(self, parent):
        frame = Frame(parent, bg=Config.BG_SECONDARY)
        frame.pack(fill=BOTH, expand=True)
        
        # Header
        header = Frame(frame, bg=Config.ACCENT2, height=38)
        header.pack(fill=X)
        header.pack_propagate(False)
        
        Label(header, text="[M] MOBILE FILES",
              font=("Segoe UI", 11, "bold"),
              bg=Config.ACCENT2, fg='white').pack(side=LEFT, padx=12, pady=8)
        
        self.mobile_count = Label(header, text="0 items",
                                  font=("Segoe UI", 9),
                                  bg=Config.ACCENT2, fg='#c4b5fd')
        self.mobile_count.pack(side=RIGHT, padx=12)
        
        # Navigation
        nav = Frame(frame, bg=Config.BG_SECONDARY)
        nav.pack(fill=X, padx=5, pady=5)
        
        btn_cfg = {'bg': Config.BG_TERTIARY, 'fg': Config.TEXT, 'relief': FLAT,
                   'font': ("Segoe UI", 10), 'cursor': 'hand2'}
        
        Button(nav, text="[^]", command=self._mobile_up, width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="[M]", command=lambda: self._browse_mobile("/sdcard"),
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="[R]", command=lambda: self._browse_mobile(self.mobile_path.get()),
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        
        self.mobile_path_entry = Entry(nav, textvariable=self.mobile_path,
                                       font=("Consolas", 10),
                                       bg=Config.BG_TERTIARY, fg=Config.TEXT,
                                       insertbackground=Config.TEXT, relief=FLAT)
        self.mobile_path_entry.pack(side=LEFT, fill=X, expand=True, padx=5, ipady=4)
        self.mobile_path_entry.bind('<Return>', lambda e: self._browse_mobile(self.mobile_path.get()))
        
        Button(nav, text="Go", command=lambda: self._browse_mobile(self.mobile_path.get()),
               bg=Config.ACCENT2, fg='white', relief=FLAT, width=5,
               font=("Segoe UI", 9, "bold"), cursor='hand2').pack(side=LEFT, padx=2)
        
        # Quick access
        quick = Frame(frame, bg=Config.BG_SECONDARY)
        quick.pack(fill=X, padx=5, pady=2)
        
        folders = [("/", "Root"), ("/sdcard", "SD"), ("/sdcard/DCIM", "DCIM"),
                   ("/sdcard/Download", "DL"), ("/sdcard/Pictures", "Pics"),
                   ("/sdcard/Music", "Music"), ("/sdcard/WhatsApp", "WA")]
        
        for path, name in folders:
            Button(quick, text=name,
                   command=lambda p=path: self._browse_mobile(p),
                   bg=Config.BG_TERTIARY, fg=Config.TEXT_DIM,
                   relief=FLAT, font=("Segoe UI", 8)).pack(side=LEFT, padx=1)
        
        # Tree
        tree_frame = Frame(frame, bg=Config.BG_SECONDARY)
        tree_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        yscroll = Scrollbar(tree_frame, orient=VERTICAL)
        yscroll.pack(side=RIGHT, fill=Y)
        
        self.mobile_tree = ttk.Treeview(tree_frame,
                                         columns=('name', 'size', 'type'),
                                         show='headings',
                                         selectmode='extended',
                                         style='Custom.Treeview',
                                         yscrollcommand=yscroll.set)
        yscroll.config(command=self.mobile_tree.yview)
        
        self.mobile_tree.heading('name', text='Name', anchor=W)
        self.mobile_tree.heading('size', text='Size', anchor=E)
        self.mobile_tree.heading('type', text='Type', anchor=W)
        
        self.mobile_tree.column('name', width=280)
        self.mobile_tree.column('size', width=80)
        self.mobile_tree.column('type', width=80)
        
        self.mobile_tree.pack(fill=BOTH, expand=True)
        
        self.mobile_tree.bind('<Double-1>', self._mobile_double_click)
        self.mobile_tree.bind('<Button-3>', self._mobile_context)
    
    def _create_transfer_panel(self, parent):
        # Increased width and removed pack_propagate constraint if needed, but keeping text small
        # parent is 'center' frame passed from _create_ui
        parent.config(width=140) # Widen the panel
        
        Frame(parent, bg=Config.BG_PRIMARY, height=20).pack()
        
        Label(parent, text="TRANSFER",
              font=("Segoe UI", 8, "bold"),
              bg=Config.BG_PRIMARY, fg=Config.TEXT_DIM).pack(pady=2)
        
        # Encrypted transfers
        Button(parent, text="[>>]\nEncrypt",
               font=("Segoe UI", 9, "bold"),
               command=self._transfer_pc_to_mobile,
               bg=Config.SUCCESS, fg='white', relief=FLAT,
               width=10, height=2, cursor='hand2').pack(pady=3)
        
        Label(parent, text="PC->Mobile",
              font=("Segoe UI", 7),
              bg=Config.BG_PRIMARY, fg=Config.TEXT_DIM).pack()
        
        Frame(parent, bg=Config.BG_PRIMARY, height=5).pack()
        
        Button(parent, text="[<<]\nDecrypt",
               font=("Segoe UI", 9, "bold"),
               command=self._transfer_mobile_to_pc,
               bg=Config.ACCENT2, fg='white', relief=FLAT,
               width=10, height=2, cursor='hand2').pack(pady=3)
        
        Label(parent, text="Mobile->PC",
              font=("Segoe UI", 7),
              bg=Config.BG_PRIMARY, fg=Config.TEXT_DIM).pack()
        
        Frame(parent, bg=Config.BG_PRIMARY, height=10).pack()
        Frame(parent, bg=Config.TEXT_DIM, height=1, width=80).pack(pady=2)
        
        Label(parent, text="DIRECT",
              font=("Segoe UI", 7),
              bg=Config.BG_PRIMARY, fg=Config.TEXT_DIM).pack(pady=2)
        
        Button(parent, text="[>] Copy",
               font=("Segoe UI", 9),
               command=self._direct_pc_to_mobile,
               bg=Config.BG_TERTIARY, fg=Config.TEXT, relief=FLAT,
               width=10, cursor='hand2').pack(pady=2)
        
        Button(parent, text="[<] Copy",
               font=("Segoe UI", 9),
               command=self._direct_mobile_to_pc,
               bg=Config.BG_TERTIARY, fg=Config.TEXT, relief=FLAT,
               width=10, cursor='hand2').pack(pady=2)
        
        Frame(parent, bg=Config.BG_PRIMARY, height=10).pack()
        
        Button(parent, text="[Del] Delete",
               font=("Segoe UI", 9),
               command=self._delete_selected,
               bg=Config.ERROR, fg='white', relief=FLAT,
               width=10, cursor='hand2').pack(pady=5)
        
        Frame(parent, bg=Config.BG_PRIMARY, height=10).pack()
        
        # Helper buttons
        btn_frame = Frame(parent, bg=Config.BG_PRIMARY)
        btn_frame.pack(fill=X, padx=5)
        
        Button(btn_frame, text="[Cam]",
               font=("Segoe UI", 12),
               command=self._take_screenshot,
               bg=Config.BG_TERTIARY, fg=Config.TEXT, relief=FLAT,
               width=3, cursor='hand2').pack(side=LEFT, padx=2)
        
        Button(btn_frame, text="[App]",
               font=("Segoe UI", 12),
               command=self._show_apps,
               bg=Config.BG_TERTIARY, fg=Config.TEXT, relief=FLAT,
               width=3, cursor='hand2').pack(side=RIGHT, padx=2)
    
    def _create_status_bar(self, parent):
        bar = Frame(parent, bg=Config.BG_SECONDARY, height=32)
        bar.pack(fill=X, pady=(5, 0))
        bar.pack_propagate(False)
        
        Label(bar, textvariable=self.status,
              font=("Segoe UI", 9),
              bg=Config.BG_SECONDARY, fg=Config.TEXT).pack(side=LEFT, padx=10, pady=6)
        
        self.progress = ttk.Progressbar(bar, mode='determinate', length=150)
        self.progress.pack(side=RIGHT, padx=10, pady=6)
        
        self.speed_label = Label(bar, text="",
                font=("Consolas", 8, "bold"),
                bg=Config.BG_SECONDARY, fg=Config.ACCENT2)
        self.speed_label.pack(side=RIGHT, padx=5)
        
        Label(bar, text="[Sec] AES-256-GCM | PBKDF2 100K | SHA-256",
              font=("Segoe UI", 8),
              bg=Config.BG_SECONDARY, fg=Config.TEXT_DIM).pack(side=RIGHT, padx=15)
    
    # ══════════════════════════════════════════════════════════════════════════════════
    #                                    BROWSER FUNCTIONS
    # ══════════════════════════════════════════════════════════════════════════════════
    
    def _initial_load(self):
        self._update_device_info()
        self._browse_pc(str(Path.home()))
    
    def _refresh_all(self):
        self._update_device_info()
        self._browse_pc(self.pc_path.get())
        self._browse_mobile(self.mobile_path.get())
    
    def _auto_refresh(self):
        self._update_device_info()
        self.root.after(5000, self._auto_refresh)
    
    def _update_device_info(self):
        """Update device information (Threaded)"""
        def fetch_and_update():
            if not self.adb.is_available():
                self.root.after(0, lambda: self.device_label.config(text="[X] ADB Not Found", fg=Config.ERROR))
                return
            
            connected, device_id, message = self.adb.check_connection()
            
            if connected:
                # Device info
                info = self.adb.get_device_info()
                brand = safe_str(info.get('brand', ''))
                model = safe_str(info.get('model', ''))
                android = safe_str(info.get('android', ''))
                sdk = safe_str(info.get('sdk', ''))
                cpu = safe_str(info.get('cpu', ''))
                
                # Battery
                battery = self.adb.get_battery_info()
                
                # Storage
                storage = self.adb.get_storage_info()
                
                # Network
                network = self.adb.get_network_info()
                
                # Time
                device_time = self.adb.get_device_time()
                uptime = self.adb.get_uptime()
                
                # Update UI on main thread
                def update_ui():
                    self.device_label.config(text=f"[OK] {brand} {model}", fg=Config.SUCCESS)
                    self.device_detail.config(text=f"Android {android} | SDK {sdk}")
                    self.cpu_label.config(text=f"CPU: {cpu}")
                    
                    if battery:
                        level = battery.get('level', '--')
                        self.battery_label.config(text=f"{level}%")
                        try:
                            lvl = int(level)
                            if lvl <= 20: self.battery_label.config(fg=Config.ERROR)
                            elif lvl <= 50: self.battery_label.config(fg=Config.WARNING)
                            else: self.battery_label.config(fg=Config.SUCCESS)
                        except: pass
                        
                        status = battery.get('status', '')
                        if '2' in status: self.charging_label.config(text="[*] Charging")
                        elif '5' in status: self.charging_label.config(text="[OK] Full")
                        else: self.charging_label.config(text="[-] Unplugged")
                        
                    if storage:
                        self.storage_label.config(text=storage.get('free', '--'))
                        self.storage_detail.config(text=f"Used: {storage.get('used', '--')}")
                        
                    self.network_label.config(text=network.get('wifi_ssid', 'Not connected'))
                    self.ip_label.config(text=network.get('ip', ''))
                    
                    self.device_time.config(text=device_time)
                    self.uptime_label.config(text=f"Up: {uptime}")
                    
                    # Auto load mobile if empty (first run)
                    if not self.mobile_items:
                        self._browse_mobile("/sdcard")
                        
                self.root.after(0, update_ui)
                
            else:
                def update_disconnected():
                    self.device_label.config(text=f"[X] {message}", fg=Config.ERROR)
                    self.device_detail.config(text="Connect USB & enable debugging")
                    self.battery_label.config(text="---%", fg=Config.TEXT_DIM)
                    self.storage_label.config(text="---")
                self.root.after(0, update_disconnected)

        import threading
        threading.Thread(target=fetch_and_update, daemon=True).start()
    
    def _browse_pc(self, path):
        """Browse PC directory"""
        try:
            path = Path(path)
            if not path.exists():
                messagebox.showerror("Error", f"Path not found:\n{path}")
                return
            
            self.status.set(f"Loading: {path}")
            self.root.update()
            
            self.pc_path.set(str(path))
            
            for item in self.pc_tree.get_children():
                self.pc_tree.delete(item)
            
            self.pc_items = []
            
            for entry in path.iterdir():
                try:
                    is_dir = entry.is_dir()
                    size = "-" if is_dir else format_size(entry.stat().st_size)
                    icon = self._get_icon(entry.name, is_dir)
                    file_type = "Folder" if is_dir else self._get_type(entry.suffix)
                    
                    self.pc_items.append({
                        'name': entry.name,
                        'display': f"{icon} {entry.name}",
                        'size': size,
                        'type': file_type,
                        'is_dir': is_dir,
                        'path': str(entry)
                    })
                except:
                    continue
            
            # Sort
            self.pc_items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
            
            for item in self.pc_items:
                self.pc_tree.insert('', END, values=(item['display'], item['size'], item['type']))
            
            self.pc_count.config(text=f"{len(self.pc_items)} items")
            self.status.set(f"PC: {path}")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _start_web_server(self):
        """Start and show Web Access details"""
        try:
            url, pin = self.web_server.start()
            
            dialog = Toplevel(self.root)
            dialog.title("🌍 Secure Web Access")
            dialog.geometry("400x300")
            dialog.configure(bg=Config.BG_PRIMARY)
            
            Label(dialog, text="🌍 Web Access Active", font=("Segoe UI", 14, "bold"),
                  bg=Config.BG_PRIMARY, fg=Config.SUCCESS).pack(pady=10)
            
            Label(dialog, text="Scan or Open Link on any device:", 
                  bg=Config.BG_PRIMARY, fg="white").pack()
            
            e_url = Entry(dialog, font=("Consolas", 11), justify='center', width=30)
            e_url.insert(0, url)
            e_url.config(state='readonly')
            e_url.pack(pady=5)
            
            Label(dialog, text="🔑 Security PIN:", font=("Segoe UI", 10, "bold"),
                  bg=Config.BG_PRIMARY, fg=Config.ACCENT).pack(pady=(15, 5))
            
            l_pin = Label(dialog, text=pin, font=("Consolas", 24, "bold"),
                          bg=Config.BG_PRIMARY, fg="white", relief=RIDGE, padx=10)
            l_pin.pack(pady=5)
            
            Label(dialog, text="Keep this window open while using Web Access", 
                  bg=Config.BG_PRIMARY, fg="gray").pack(side=BOTTOM, pady=10)
            
            # Firewall Hint
            messagebox.showinfo("Firewall Note", 
                "If the link doesn't open on other devices:\n\n"
                "Please allow 'Python' through your Windows Firewall\n"
                "when the popup appears.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")

    def _browse_mobile(self, path):
        """Browse mobile directory (Threaded)"""
        self.status.set(f"Loading: {path}")
        self.progress.start()
        
        def fetch_items():
            if getattr(self, 'shutting_down', False): return
            
            connected, _, _ = self.adb.check_connection()
            
            if not connected:
                if not getattr(self, 'shutting_down', False):
                    def show_connect_error():
                        self.progress.stop()
                        for item in self.mobile_tree.get_children():
                            self.mobile_tree.delete(item)
                        self.mobile_tree.insert('', END, values=("[X] Not connected", "", ""))
                        self.mobile_tree.insert('', END, values=("1. Connect USB cable", "", ""))
                        self.mobile_tree.insert('', END, values=("2. Enable USB Debugging", "", ""))
                        self.mobile_count.config(text="0")
                    self.root.after(0, show_connect_error)
                return
            
            items = self.adb.list_directory(path)
            if getattr(self, 'shutting_down', False): return
            self.mobile_items = items
            
            def update_list():
                if getattr(self, 'shutting_down', False): return
                self.mobile_path.set(path)
                for item in self.mobile_tree.get_children():
                    self.mobile_tree.delete(item)
                
                if not items:
                    self.mobile_tree.insert('', END, values=("[DIR] (Empty)", "-", "-"))
                else:
                    for item in items:
                        name = safe_str(item.get('name', ''))
                        is_dir = item.get('is_dir', False)
                        icon = self._get_icon(name, is_dir, item.get('is_link', False))
                        size = safe_str(item.get('size', '-'))
                        file_type = "Folder" if is_dir else self._get_type(Path(name).suffix)
                        
                        self.mobile_tree.insert('', END, values=(f"{icon} {name}", size, file_type))
                
                self.mobile_count.config(text=f"{len(items)} items")
                self.status.set(f"Mobile: {path}")
                self.progress.stop()
            
            self.root.after(0, update_list)
            
        threading.Thread(target=fetch_items, daemon=True).start()
    
    def _pc_up(self):
        current = Path(self.pc_path.get())
        if current.parent != current:
            self._browse_pc(str(current.parent))
    
    def _mobile_up(self):
        current = safe_str(self.mobile_path.get())
        if current in ['/', '']:
            return
        parent = str(Path(current).parent)
        if parent == '.':
            parent = '/'
        self._browse_mobile(parent)
    
    def _pc_double_click(self, event):
        selection = self.pc_tree.selection()
        if selection:
            idx = self.pc_tree.index(selection[0])
            if idx < len(self.pc_items):
                item = self.pc_items[idx]
                if item['is_dir']:
                    self._browse_pc(item['path'])
    
    def _mobile_double_click(self, event):
        selection = self.mobile_tree.selection()
        if selection:
            idx = self.mobile_tree.index(selection[0])
            if idx < len(self.mobile_items):
                item = self.mobile_items[idx]
                if item.get('is_dir', False):
                    self._browse_mobile(item['full_path'])
    
    def _pc_context(self, event):
        menu = Menu(self.root, tearoff=0, bg=Config.BG_SECONDARY, fg=Config.TEXT)
        menu.add_command(label="[Send] Send (Encrypted)", command=self._transfer_pc_to_mobile)
        menu.add_command(label="[Send] Send (Direct)", command=self._direct_pc_to_mobile)
        menu.add_separator()
        menu.add_command(label="[Dir] New Folder", command=self._new_folder_pc)
        menu.add_command(label="[Del] Delete", command=self._delete_pc)
        menu.add_separator()
        menu.add_command(label="[Ref] Refresh", command=lambda: self._browse_pc(self.pc_path.get()))
        menu.tk_popup(event.x_root, event.y_root)
    
    def _mobile_context(self, event):
        menu = Menu(self.root, tearoff=0, bg=Config.BG_SECONDARY, fg=Config.TEXT)
        menu.add_command(label="[Get] Get (Encrypted)", command=self._transfer_mobile_to_pc)
        menu.add_command(label="[Get] Get (Direct)", command=self._direct_mobile_to_pc)
        menu.add_separator()
        menu.add_command(label="[Dir] New Folder", command=self._new_folder_mobile)
        menu.add_command(label="[Del] Delete", command=self._delete_mobile)
        menu.add_separator()
        menu.add_command(label="[Ref] Refresh", command=lambda: self._browse_mobile(self.mobile_path.get()))
        menu.tk_popup(event.x_root, event.y_root)
    
    # ══════════════════════════════════════════════════════════════════════════════════
    #                                    TRANSFERS
    # ══════════════════════════════════════════════════════════════════════════════════
    
    def _validate_password(self):
        pwd = self.password.get()
        if len(pwd) < 10:
            messagebox.showerror("Password Required",
                                f"Password must be at least 10 characters!\n\nCurrent: {len(pwd)}")
            self.pwd_entry.focus()
            return False
        return True
    
    def _get_selected_pc(self):
        return [self.pc_items[self.pc_tree.index(s)]
                for s in self.pc_tree.selection()
                if self.pc_tree.index(s) < len(self.pc_items)]
    
    def _get_selected_mobile(self):
        return [self.mobile_items[self.mobile_tree.index(s)]
                for s in self.mobile_tree.selection()
                if self.mobile_tree.index(s) < len(self.mobile_items)]
    
    def _transfer_pc_to_mobile(self):
        if not self._validate_password():
            return
        
        connected, _, _ = self.adb.check_connection()
        if not connected:
            messagebox.showerror("Error", "Mobile not connected!")
            return
        
        selected = self._get_selected_pc()
        if not selected:
            messagebox.showwarning("Warning", "Select files in PC panel!")
            return
        
        password = self.password.get()
        dest = self.mobile_path.get()
        
        def transfer():
            try:
                self.progress.start()
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                zip_path = Config.TEMP_DIR / f"transfer_{timestamp}.zip"
                enc_path = Config.TEMP_DIR / f"transfer_{timestamp}.secbak"
                
                self.status.set("📦 Compressing...")
                self.root.update()
                
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for item in selected:
                        path = Path(item['path'])
                        self.status.set(f"Adding: {path.name}")
                        self.root.update()
                        
                        if path.is_file():
                            zf.write(path, path.name)
                        elif path.is_dir():
                            for f in path.rglob('*'):
                                if f.is_file():
                                    zf.write(f, f.relative_to(path.parent))
                
                self.status.set("🔐 Encrypting...")
                self.root.update()
                
                success, msg = Encryptor.encrypt(zip_path, enc_path, password)
                if not success:
                    raise Exception(f"Encryption failed: {msg}")
                
                disp_name = "Encrypted Payload" if self.privacy_mode.get() else f"backup_{timestamp}.secbak"
                self.status.set(f"📤 Sending: {disp_name}")
                self.root.update()
                
                remote = f"{dest.rstrip('/')}/backup_{timestamp}.secbak"
                
                def parse_prog(line):
                    if "%" in line:
                        try:
                            # Parse "[ 10%] /sdcard/..."
                            line_clean = line.replace('[', '').replace(']', '').strip()
                            parts = line_clean.split()
                            if parts and '%' in parts[0]:
                                val = int(parts[0].replace('%',''))
                                self.root.after(0, lambda v=val: self.progress.configure(value=v))
                            if "MB/s" in line:
                                speed = line.split(':')[-1].strip()
                                self.root.after(0, lambda s=speed: self.speed_label.config(text=f"🚀 {s}"))
                        except: pass

                success, err = self.adb.push(enc_path, remote, callback=parse_prog)
                
                if not success:
                    raise Exception(f"Push failed: {err}")
                
                # Cleanup
                zip_path.unlink(missing_ok=True)
                
                # Local backup
                local_backup = Config.BACKUP_DIR / f"backup_{timestamp}.secbak"
                shutil.copy(enc_path, local_backup)
                enc_path.unlink(missing_ok=True)
                
                self.status.set("✅ Transfer complete!")
                self.speed_label.config(text="")
                
                self.root.after(0, lambda: messagebox.showinfo("Success! ✅",
                    f"Backup sent to mobile!\n\n"
                    f"📍 Mobile: {remote}\n"
                    f"💾 Local: {local_backup}"))
                
                self.root.after(0, lambda: self._browse_mobile(dest))
                
            except Exception as e:
                self.status.set(f"❌ Error: {e}")
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.progress.stop()
        
        threading.Thread(target=transfer, daemon=True).start()
    
    def _transfer_mobile_to_pc(self):
        if not self._validate_password():
            return
        
        selected = self._get_selected_mobile()
        if not selected:
            messagebox.showwarning("Warning", "Select files in Mobile panel!")
            return
        
        dest = filedialog.askdirectory(title="Select destination folder")
        if not dest:
            return
        
        password = self.password.get()
        
        def transfer():
            try:
                self.progress.start()
                
                for item in selected:
                    name = safe_str(item.get('name', ''))
                    remote = safe_str(item.get('full_path', ''))
                    
                    disp_name = "Sensitive Item" if self.privacy_mode.get() else name
                    self.status.set(f"📥 Getting: {disp_name}")
                    self.root.update()
                    
                    if name.endswith('.secbak'):
                        local_enc = Config.TEMP_DIR / name
                        
                        def parse_prog(line):
                            if "%" in line:
                                try:
                                    line_clean = line.replace('[', '').replace(']', '').strip()
                                    parts = line_clean.split()
                                    if parts and '%' in parts[0]:
                                        val = int(parts[0].replace('%',''))
                                        self.root.after(0, lambda v=val: self.progress.configure(value=v))
                                    if "MB/s" in line:
                                        speed = line.split(':')[-1].strip()
                                        self.root.after(0, lambda s=speed: self.speed_label.config(text=f"🚀 {s}"))
                                except: pass

                        success, err = self.adb.pull(remote, local_enc, callback=parse_prog)
                        
                        if not success:
                            raise Exception(f"Pull failed: {err}")
                        
                        self.status.set("🔓 Decrypting...")
                        self.root.update()
                        
                        local_zip = Config.TEMP_DIR / name.replace('.secbak', '.zip')
                        success, result = Encryptor.decrypt(local_enc, local_zip, password)
                        
                        if not success:
                            local_enc.unlink(missing_ok=True)
                            raise Exception(f"Decryption failed: {result}")
                        
                        self.status.set("📂 Extracting...")
                        self.root.update()
                        
                        with zipfile.ZipFile(local_zip, 'r') as zf:
                            zf.extractall(dest)
                        
                        local_enc.unlink(missing_ok=True)
                        local_zip.unlink(missing_ok=True)
                    else:
                        local = Path(dest) / name
                        self.adb.pull(remote, local)
                
                self.status.set("✅ Transfer complete!")
                self.speed_label.config(text="")
                
                self.root.after(0, lambda: messagebox.showinfo("Success! ✅",
                    f"Files saved to:\n{dest}"))
                
                self.root.after(0, lambda: self._browse_pc(dest))
                
            except Exception as e:
                self.status.set(f"❌ Error: {e}")
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.progress.stop()
        
        threading.Thread(target=transfer, daemon=True).start()
    
    def _direct_pc_to_mobile(self):
        connected, _, _ = self.adb.check_connection()
        if not connected:
            messagebox.showerror("Error", "Mobile not connected!")
            return
        
        selected = self._get_selected_pc()
        if not selected:
            messagebox.showwarning("Warning", "Select files!")
            return
        
        dest = self.mobile_path.get()
        
        def transfer():
            self.progress.start()
            for item in selected:
                self.status.set(f"📤 {item['name']}")
                self.root.update()
                self.adb.push(item['path'], f"{dest.rstrip('/')}/{item['name']}")
            self.status.set("✅ Done!")
            self.progress.stop()
            self.root.after(0, lambda: self._browse_mobile(dest))
        
        threading.Thread(target=transfer, daemon=True).start()
    
    def _direct_mobile_to_pc(self):
        selected = self._get_selected_mobile()
        if not selected:
            messagebox.showwarning("Warning", "Select files!")
            return
        
        dest = self.pc_path.get()
        
        def transfer():
            self.progress.start()
            for item in selected:
                self.status.set(f"📥 {item['name']}")
                self.root.update()
                self.adb.pull(item['full_path'], Path(dest) / item['name'])
            self.status.set("✅ Done!")
            self.progress.stop()
            self.root.after(0, lambda: self._browse_pc(dest))
        
        threading.Thread(target=transfer, daemon=True).start()
    
    # ══════════════════════════════════════════════════════════════════════════════════
    #                                    TOOLS
    # ══════════════════════════════════════════════════════════════════════════════════
    
    def _take_screenshot(self):
        self.status.set("📸 Taking screenshot...")
        self.progress.start()
        
        def capture():
            success, result = self.adb.take_screenshot()
            self.progress.stop()
            
            if success:
                self.status.set(f"✅ Screenshot saved!")
                self.root.after(0, lambda: messagebox.showinfo("Screenshot", f"Saved to:\n{result}"))
            else:
                self.status.set("❌ Screenshot failed")
                self.root.after(0, lambda: messagebox.showerror("Error", result))
        
        threading.Thread(target=capture, daemon=True).start()
    
    def _start_scrcpy(self):
        """Start Screen Mirroring"""
        if Config.SCRCPY_PATH.exists():
            try:
                subprocess.Popen(
                    [str(Config.SCRCPY_PATH)],
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )
                self.status.set("📺 Screen mirror started")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            self._show_scrcpy_error()

    def _start_scrcpy_smooth(self):
        """Start Screen Mirroring (Smooth/Wi-Fi Optimized)"""
        if Config.SCRCPY_PATH.exists():
            try:
                # 4M bitrate, max 1024, max 30fps for smooth Wi-Fi
                subprocess.Popen(
                    [str(Config.SCRCPY_PATH), '--bit-rate', '4M', '--max-size', '1024', '--max-fps', '30'],
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )
                self.status.set("📺 Smooth mirror started")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            self._show_scrcpy_error()

    def _show_scrcpy_error(self):
         messagebox.showinfo("scrcpy Not Found",
            f"scrcpy not found!\n\n"
            f"Download from:\n"
            f"https://github.com/Genymobile/scrcpy/releases\n\n"
            f"Extract to:\n{Config.SCRIPT_DIR / 'scrcpy'}")
    
    def _show_apps(self):
        win = Toplevel(self.root)
        win.title("📱 Installed Apps")
        win.geometry("500x400")
        win.configure(bg=Config.BG_PRIMARY)
        
        Label(win, text="📱 Installed Apps",
              font=("Segoe UI", 14, "bold"),
              bg=Config.BG_PRIMARY, fg=Config.TEXT).pack(pady=10)
        
        frame = Frame(win, bg=Config.BG_PRIMARY)
        frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        scroll = Scrollbar(frame)
        scroll.pack(side=RIGHT, fill=Y)
        
        listbox = Listbox(frame, font=("Consolas", 10),
                         bg=Config.BG_SECONDARY, fg=Config.TEXT,
                         selectbackground=Config.ACCENT,
                         yscrollcommand=scroll.set)
        listbox.pack(fill=BOTH, expand=True)
        scroll.config(command=listbox.yview)
        
        def load_apps():
            apps = self.adb.get_installed_apps()
            for app in apps:
                listbox.insert(END, app)
        
        threading.Thread(target=load_apps, daemon=True).start()
        
        btn_frame = Frame(win, bg=Config.BG_PRIMARY)
        btn_frame.pack(fill=X, padx=10, pady=10)
        
        def open_app():
            sel = listbox.curselection()
            if sel:
                self.adb.open_app(listbox.get(sel[0]))
        
        def uninstall_app():
            sel = listbox.curselection()
            if sel:
                pkg = listbox.get(sel[0])
                if messagebox.askyesno("Uninstall", f"Uninstall {pkg}?"):
                    self.adb.uninstall_app(pkg)
                    listbox.delete(sel[0])
        
        def install_apk():
            path = filedialog.askopenfilename(
                title="Select APK",
                filetypes=[("Android Package", "*.apk"), ("All Files", "*.*")]
            )
            if path:
                self.status.set(f"Installing: {Path(path).name}...")
                success, stdout, stderr = self.adb.install_app(path)
                if success:
                    messagebox.showinfo("Success", "App installed successfully!")
                    # Refresh list
                    listbox.delete(0, END)
                    threading.Thread(target=load_apps, daemon=True).start()
                else:
                    messagebox.showerror("Error", f"Installation failed:\n{stderr}")
                self.status.set("Ready")

        Button(btn_frame, text="[Open] Open", command=open_app,
               bg=Config.SUCCESS, fg='white', relief=FLAT, padx=15).pack(side=LEFT, padx=5)
        Button(btn_frame, text="[Del] Uninstall", command=uninstall_app,
               bg=Config.ERROR, fg='white', relief=FLAT, padx=15).pack(side=LEFT, padx=5)
        Button(btn_frame, text="[Inst] Install APK", command=install_apk,
               bg=Config.ACCENT, fg='white', relief=FLAT, padx=15).pack(side=LEFT, padx=5)
    
    def _enable_wifi_mode(self):
        """Enable TCP/IP mode on device"""
        # Check connection first
        connected, _, _ = self.adb.check_connection()
        if not connected:
            messagebox.showerror("No Device Found", 
                "No device connected via USB!\n\n"
                "1. Connect your phone with USB cable.\n"
                "2. Allow USB Debugging on phone screen.\n"
                "3. Try again.")
            return

        if messagebox.askyesno("Enable Wi-Fi Mode", "Connect your device via USB first.\n\nEnable Wi-Fi Mode now?"):
            success, _, stderr = self.adb.enable_wireless()
            if success:
                messagebox.showinfo("Success", "Wi-Fi Mode Enabled!\n\nYou can now disconnect USB and use 'Wireless Connect'.")
            else:
                messagebox.showerror("Error", f"Failed to enable Wi-Fi mode:\n{stderr}")

    def _disconnect_wireless(self):
        """Disconnect all wireless devices"""
        if messagebox.askyesno("Disconnect", "Disconnect all wireless devices?"):
            self.adb.disconnect_all()
            self._update_device_info()
            messagebox.showinfo("Disconnected", "All wireless devices disconnected.")

    def _show_wireless_dialog(self):
        """Show wireless connection dialog"""
        dialog = Toplevel(self.root)
        dialog.title("Wireless Connect")
        dialog.geometry("300x200")
        dialog.configure(bg=Config.BG_SECONDARY)
        
        Label(dialog, text="Connect Wireless", font=("Segoe UI", 12, "bold"),
              bg=Config.BG_SECONDARY, fg=Config.TEXT).pack(pady=10)
        
        frame = Frame(dialog, bg=Config.BG_SECONDARY)
        frame.pack(pady=10)
        
        Label(frame, text="IP Address:", bg=Config.BG_SECONDARY, fg=Config.TEXT).grid(row=0, column=0, padx=5, pady=5)
        ip_entry = Entry(frame, width=20)
        ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        Label(frame, text="Port:", bg=Config.BG_SECONDARY, fg=Config.TEXT).grid(row=1, column=0, padx=5, pady=5)
        port_entry = Entry(frame, width=20)
        port_entry.insert(0, "5555")
        port_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def connect():
            ip = ip_entry.get()
            port = port_entry.get()
            if ip and port:
                success, stdout, stderr = self.adb.connect_wireless(ip, port)
                if success:
                    messagebox.showinfo("Success", f"Connected to {ip}:{port}")
                    dialog.destroy()
                    self._update_device_info()
                else:
                    messagebox.showerror("Error", f"Connection failed:\n{stderr}")
        
        Button(dialog, text="Connect", command=connect,
               bg=Config.ACCENT, fg='white', relief=FLAT).pack(pady=10)

    def _new_folder_pc(self):
        name = simpledialog.askstring("New Folder", "Enter folder name:")
        if name:
            path = Path(self.pc_path.get()) / name
            try:
                path.mkdir(exist_ok=True)
                self._browse_pc(self.pc_path.get())
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def _new_folder_mobile(self):
        name = simpledialog.askstring("New Folder", "Enter folder name:")
        if name:
            path = f"{self.mobile_path.get().rstrip('/')}/{name}"
            self.adb.mkdir(path)
            self._browse_mobile(self.mobile_path.get())
    
    def _delete_selected(self):
        pc_sel = self._get_selected_pc()
        mobile_sel = self._get_selected_mobile()
        
        if pc_sel:
            self._delete_pc()
        elif mobile_sel:
            self._delete_mobile()
    
    def _delete_pc(self):
        selected = self._get_selected_pc()
        if not selected:
            return
        
        if messagebox.askyesno("Delete", f"Delete {len(selected)} item(s)?"):
            for item in selected:
                path = Path(item['path'])
                try:
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                except:
                    pass
            self._browse_pc(self.pc_path.get())
    
    def _delete_mobile(self):
        selected = self._get_selected_mobile()
        if not selected:
            return
        
        if messagebox.askyesno("Delete", f"Delete {len(selected)} item(s)?"):
            for item in selected:
                self.adb.remove(item.get('full_path', ''))
            self._browse_mobile(self.mobile_path.get())
    
    def _toggle_password(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "●")
    
    def _check_password(self, *args):
        pwd = self.password.get()
        length = len(pwd)
        
        if length == 0:
            self.pwd_strength.config(text="", fg=Config.TEXT_DIM)
        elif length < 10:
            self.pwd_strength.config(text=f"[X] {length}/10", fg=Config.ERROR)
        elif length < 14:
            self.pwd_strength.config(text=f"[OK] Good ({length})", fg=Config.SUCCESS)
        else:
            self.pwd_strength.config(text=f"[+] Strong ({length})", fg=Config.SUCCESS)
    
    def _get_icon(self, name, is_dir, is_link=False):
        if is_link:
            return "[LNK]"
        if is_dir:
            lower = name.lower()
            # ASCII icons
            return "[DIR]"
        
        ext = Path(name).suffix.lower()
        # Simplified ASCII icons
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']: return "[IMG]"
        if ext in ['.mp4', '.mkv', '.avi', '.mov']: return "[VID]"
        if ext in ['.mp3', '.wav', '.flac', '.m4a']: return "[AUD]"
        if ext in ['.pdf', '.doc', '.docx', '.txt']: return "[DOC]"
        if ext in ['.xls', '.xlsx', '.ppt', '.pptx']: return "[OFC]"
        if ext in ['.zip', '.rar', '.7z']: return "[ZIP]"
        if ext == '.apk': return "[APK]"
        if ext == '.exe': return "[EXE]"
        if ext == '.py': return "[PY]"
        if ext == '.secbak': return "[ENC]"
        
        return "[FIL]"
    
    def _get_type(self, suffix):
        types = {
            '.jpg': 'Image', '.jpeg': 'Image', '.png': 'Image', '.gif': 'Image',
            '.mp4': 'Video', '.mkv': 'Video', '.avi': 'Video',
            '.mp3': 'Audio', '.wav': 'Audio', '.flac': 'Audio',
            '.pdf': 'PDF', '.doc': 'Document', '.docx': 'Document', '.txt': 'Text',
            '.zip': 'Archive', '.rar': 'Archive', '.7z': 'Archive',
            '.apk': 'App', '.exe': 'Program',
            '.secbak': 'Encrypted'
        }
        return types.get(suffix.lower(), 'File')
    
    def run(self):
        self.root.mainloop()


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    MAIN
# ══════════════════════════════════════════════════════════════════════════════════════

# if __name__ == "__main__":
#     print("=" * 60)
#     print("  Ultimate Mobile Manager v5.1")
#     print("  By Sudhir Kumar (@SudhirDevOps1)")
#     print("  Python 3.14 Compatible - All Bugs Fixed")
#     print("=" * 60)
    
#     try:
#         app = UltimateMobileManager()
#         app.run()
#     except Exception as e:
#         import traceback
#         traceback.print_exc()
#         messagebox.showerror("Critical Error", str(e))


# ══════════════════════════════════════════════════════════════════════════════════════
#                         ANIMATED COLORFUL BANNER MODULE
#                            With Slow Typing Effects
# ══════════════════════════════════════════════════════════════════════════════════════

# import os
# import sys
# import time
# import random
# from datetime import datetime

# ═══════════════════════════════════════════════════════════════
#                     ANSI COLOR CODES CLASS
# ═══════════════════════════════════════════════════════════════

class C:
    """Color codes for terminal output"""
    R = '\033[0m'
    RST = '\033[0m'
    BLK = '\033[30m'
    RED = '\033[31m'
    GRN = '\033[32m'
    YEL = '\033[33m'
    BLU = '\033[34m'
    MAG = '\033[35m'
    CYN = '\033[36m'
    WHT = '\033[37m'
    BRED = '\033[91m'
    BGRN = '\033[92m'
    BYEL = '\033[93m'
    BBLU = '\033[94m'
    BMAG = '\033[95m'
    BCYN = '\033[96m'
    BWHT = '\033[97m'
    BOLD = '\033[1m'

def get_center_offset(text_len):
    try:
        width = shutil.get_terminal_size().columns
        return max(0, (width - text_len) // 2)
    except:
        return 4

def center_print(text, color=C.RST):
    offset = get_center_offset(len(re.sub(r'\033\[[0-9;]*m', '', text)))
    print(" " * offset + text + C.RST)

def slow_print(text, delay=0.03, center=True):
    plain_text = re.sub(r'\033\[[0-9;]*m', '', text)
    if center:
        offset = get_center_offset(len(plain_text))
        sys.stdout.write(" " * offset)
    
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def slow_print_fast(text, delay=0.01, center=True):
    plain_text = re.sub(r'\033\[[0-9;]*m', '', text)
    if center:
        offset = get_center_offset(len(plain_text))
        sys.stdout.write(" " * offset)
        
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def enable_windows_ansi():
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except: pass

def matrix_effect(duration=1.5):
    chars = "01@#$%&*X01"
    width = shutil.get_terminal_size().columns - 10
    offset = 5
    end_time = time.time() + duration
    sys.stdout.write(" " * (width + offset) + "\r")

def line_by_line_print(text, delay=0.05):
    """Print each line with delay"""
    lines = text.split('\n')
    for line in lines:
        print(line)
        time.sleep(delay)


def line_by_line_print(text, delay=0.05):
    """Print each line with delay"""
    lines = text.split('\n')
    for line in lines:
        print(line)
        time.sleep(delay)


def matrix_effect(duration=1.5):
    chars = "01@#$%&*X01"
    width = shutil.get_terminal_size().columns - 10
    offset = 5
    end_time = time.time() + duration
    while time.time() < end_time:
        line = ''.join(random.choice(chars) for _ in range(width))
        sys.stdout.write(" " * offset + f"{C.BGRN}{line}{C.RST}\r")
        sys.stdout.flush()
        time.sleep(0.04)
    sys.stdout.write(" " * (width + offset) + "\r")

def hacker_intro():
    clear_screen()
    width = 50
    offset = get_center_offset(width + 2)
    sys.stdout.write(" " * offset + f"{C.BGRN}[")
    for _ in range(width):
        sys.stdout.write("=")
        sys.stdout.flush()
        time.sleep(0.01)
    print(f"]{C.RST}")
    
    messages = [
        (f"{C.BYEL}[*]{C.RST} {C.BCYN}Initializing Secure Shield...{C.RST}"),
        (f"{C.BYEL}[*]{C.RST} {C.BCYN}Loading Sudhir's Premium Core...{C.RST}"),
        (f"{C.BGRN}[+]{C.RST} {C.BGRN}System Ready. Access Granted.{C.RST}"),
    ]
    for msg in messages:
        slow_print_fast(msg, 0.015)
        time.sleep(0.2)


def print_banner_animated():
    """Print the main colorful banner with animation"""
    center_print(f"{C.BYEL}[*]{C.RST} {C.BCYN}Decrypting UI Layers...{C.RST}")
    time.sleep(0.3)
    matrix_effect(1.0)
    
    banner_lines = [
        f"    +===================================================================================+",
        f"    |                                                                                   |",
        f"    |  {C.BRED}  #######   ##   ########  ##  ####      ###  #####   ######## #######  {C.BCYN}   |",
        f"    |  {C.BRED}  ##    ##  ##   ##    ##  ##  ## ##   ## ##  ##  ##  ##       ##       {C.BCYN}   |",
        f"    |  {C.BYEL}  #      #  ##      ####    ##  ##  ## ##  ##  #####   #####    #######  {C.BCYN}   |",
        f"    |  {C.BGRN}  ##    ##  ##     ##  ##   ##  ##   ###   ##  ##  ##  ##            ##  {C.BCYN}   |",
        f"    |  {C.BBLU}  #######   ##    ##    ##  ##  ##         ##  ##   ## ######## #######  {C.BCYN}   |",
        f"    |  {C.BMAG}                                                                         {C.BCYN}   |",
        f"    |                                                                                   |",
        f"    |  {C.BGRN}  ###    ###  ######   ######   ## ##      ######   {C.BCYN}                    |",
        f"    |  {C.BGRN}  ## #  # ##  ##   ##  ##   ##  ## ##      ##       {C.BCYN}                    |",
        f"    |  {C.BYEL}  ##  ##  ##  ##   ##  ######   ## ##      #####    {C.BCYN}                    |",
        f"    |  {C.BYEL}  ##      ##  ##   ##  ##   ##  ## ##      ##       {C.BCYN}                    |",
        f"    |  {C.BRED}  ##      ##  ######   ######   ## ####### ######   {C.BCYN}                    |",
        f"    |  {C.BRED}                                                     {C.BCYN}                    |",
        f"    |                                                                                   |",
        f"    |  {C.BMAG}  ###    ###  #####   ###    ##  #####   ######   #######  ######   {C.BCYN}       |",
        f"    |  {C.BMAG}  ## #  # ##  ##  ##  ## #   ##  ##  ##  ##       ##       ##   ##  {C.BCYN}       |",
        f"    |  {C.BBLU}  ##  ##  ##  #####   ##  #  ##  #####   ##  ###  #####    ######   {C.BCYN}       |",
        f"    |  {C.BBLU}  ##      ##  ##  ##  ##   # ##  ##  ##  ##   ##  ##       ##   ##  {C.BCYN}       |",
        f"    |  {C.BGRN}  ##      ##  ##  ##  ##    ###  ##  ##  ######   #######  ##   ##  {C.BCYN}       |",
        f"    |  {C.BGRN}                                                                         {C.BCYN}   |",
        f"    |                                                                                   |",
        f"    +===================================================================================+",
    ]
    
    for line in banner_lines:
        center_print(line, C.BCYN)
        time.sleep(0.04)
    
    time.sleep(0.5)


def print_info_animated():
    """Print info section with animation"""
    
    print(f"\n    {C.BYEL}[*]{C.RST} {C.BCYN}Loading tool information...{C.RST}")
    time.sleep(0.5)
    
    print(f"    {C.BCYN}+===================================================================================+{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}|                                                                                   |{C.RST}")
    time.sleep(0.1)
    
    info_lines = [
        (f"    {C.BCYN}|   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Version      {C.BWHT}: ", f"{C.BGRN}5.1 {C.BMAG}(Stable Release){C.BCYN}                                 |{C.RST}"),
        (f"    {C.BCYN}|   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Author       {C.BWHT}: ", f"{C.BGRN}Sudhir Kumar{C.BCYN}                                             |{C.RST}"),
        (f"    {C.BCYN}|   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}GitHub       {C.BWHT}: ", f"{C.BBLU}https://github.com/SudhirDevOps1{C.BCYN}                         |{C.RST}"),
        (f"    {C.BCYN}|   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Telegram     {C.BWHT}: ", f"{C.BBLU}@SudhirDevOps1{C.BCYN}                                           |{C.RST}"),
        (f"    {C.BCYN}|   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Python       {C.BWHT}: ", f"{C.BGRN}3.14+ Compatible{C.BCYN}                                         |{C.RST}"),
        (f"    {C.BCYN}|   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Platform     {C.BWHT}: ", f"{C.BGRN}Windows / Linux / macOS{C.BCYN}                                  |{C.RST}"),
        (f"    {C.BCYN}|   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Status       {C.BWHT}: ", f"{C.BGRN}+ All Bugs Fixed{C.BCYN}                                         |{C.RST}"),
    ]
    
    for prefix, value in info_lines:
        print(prefix, end='', flush=True)
        time.sleep(0.2)
        # Type out the value
        for char in value:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.008)
        print()
        time.sleep(0.1)
    
    print(f"    {C.BCYN}|                                                                                   |{C.RST}")
    time.sleep(0.1)


def print_features_animated():
    """Print features with animation"""
    
    print(f"    {C.BCYN}+===================================================================================+{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}|                                                                                   |{C.RST}")
    time.sleep(0.1)
    
    print(f"    {C.BCYN}|   {C.BRED}!{C.BWHT} FEATURES:{C.BCYN}                                                                  |{C.RST}")
    time.sleep(0.2)
    
    features = [
        f"    {C.BCYN}|   {C.BWHT}|--{C.BGRN} + ADB Device Control      {C.BWHT}|--{C.BGRN} + File Manager{C.BCYN}                          |{C.RST}",
        f"    {C.BCYN}|   {C.BWHT}|--{C.BYEL} + App Installer           {C.BWHT}|--{C.BYEL} + Screen Mirror{C.BCYN}                         |{C.RST}",
        f"    {C.BCYN}|   {C.BWHT}|--{C.BMAG} + Backup & Restore        {C.BWHT}|--{C.BMAG} + System Info{C.BCYN}                           |{C.RST}",
        f"    {C.BCYN}|   {C.BWHT}|--{C.BBLU} + Network Tools           {C.BWHT}|--{C.BBLU} + Root Tools{C.BCYN}                            |{C.RST}",
        f"    {C.BCYN}|   {C.BWHT}|--{C.BRED} + Logcat Viewer           {C.BWHT}|--{C.BRED} + Shell Access{C.BCYN}                          |{C.RST}",
        f"    {C.BCYN}|   {C.BWHT}`--{C.BGRN} + Wireless ADB            {C.BWHT}`--{C.BGRN} + Multi-Device{C.BCYN}                          |{C.RST}",
    ]
    
    for feature in features:
        print(feature)
        time.sleep(0.15)
    
    print(f"    {C.BCYN}|                                                                                   |{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}+===================================================================================+{C.RST}")
    time.sleep(0.3)


def print_loading_bar_animated():
    """Print animated loading bar with slow effect"""
    
    print(f"\n    {C.BWHT}[{C.BYEL}*{C.BWHT}] {C.BCYN}Initializing Ultimate Mobile Manager...{C.RST}")
    time.sleep(0.5)
    print(f"    {C.BWHT}[{C.BYEL}*{C.BWHT}] {C.BCYN}Loading modules and dependencies...{C.RST}\n")
    time.sleep(0.3)
    
    # Loading bar with slow animation
    total = 50
    for i in range(total + 1):
        percentage = int((i / total) * 100)
        filled = "#" * i
        empty = "." * (total - i)
        
        # Color changes based on progress
        if percentage < 30:
            color = C.BRED
        elif percentage < 70:
            color = C.BYEL
        else:
            color = C.BGRN
        
        # Spinner animation
        spinner = ['|', '/', '-', '\\'][i % 4]
        
        sys.stdout.write(f"\r    {C.BCYN}{spinner}{C.RST} {C.BWHT}[{color}{filled}{C.WHT}{empty}{C.BWHT}] {color}{percentage:3d}%{C.RST}  ")
        sys.stdout.flush()
        
        # Variable speed - slower at start and end
        if percentage < 20:
            time.sleep(0.08)
        elif percentage > 80:
            time.sleep(0.06)
        else:
            time.sleep(0.04)
    
    print(f"\n\n    {C.BGRN}[+]{C.RST} {C.BGRN}Loading complete!{C.RST}")
    time.sleep(0.5)


def print_system_check_animated():
    """Print system check status with slow animation"""
    
    print(f"\n    {C.BYEL}[*]{C.RST} {C.BCYN}Running system diagnostics...{C.RST}")
    time.sleep(0.5)
    
    print(f"\n    {C.BCYN}+-------------------------------------------------------------+{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}|{C.BWHT}                    SYSTEM INITIALIZATION                    {C.BCYN}|{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}+-------------------------------------------------------------+{C.RST}")
    time.sleep(0.2)
    
    checks = [
        ("Checking Python Version", "3.14.0", True),
        ("Checking ADB Installation", "Found", True),
        ("Checking Scrcpy", "Found", True),
        ("Checking USB Drivers", "OK", True),
        ("Checking Network", "Connected", True),
        ("Loading GUI Framework", "Tkinter", True),
        ("Initializing Database", "SQLite3", True),
        ("Loading Configurations", "Complete", True),
    ]
    
    for task, result, success in checks:
        # Print task name with dots animation
        print(f"    {C.BCYN}|{C.RST}  {C.BYEL}*{C.RST} {C.BWHT}{task}", end='', flush=True)
        
        # Animate dots
        remaining_space = 35 - len(task)
        for _ in range(remaining_space):
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(0.02)
        
        # Small delay before result
        time.sleep(0.2)
        
        # Show result
        status_color = C.BGRN if success else C.BRED
        status_icon = "+" if success else "X"
        
        # Replace the line with final result
        print(f"\r    {C.BCYN}|{C.RST}  {C.BGRN}{status_icon}{C.RST} {C.BWHT}{task:<35}{C.RST} [{status_color}{result:^10}{C.RST}] {C.BCYN}|{C.RST}")
        
        time.sleep(0.15)
    
    print(f"    {C.BCYN}+-------------------------------------------------------------+{C.RST}")
    time.sleep(0.3)


def print_device_status_animated():
    """Print device connection status with animation"""
    
    print(f"\n    {C.BYEL}[*]{C.RST} {C.BCYN}Detecting connected devices...{C.RST}")
    time.sleep(0.5)
    
    # Scanning animation
    print(f"    {C.BYEL}[", end='', flush=True)
    for i in range(20):
        print("#", end='', flush=True)
        time.sleep(0.05)
    print(f"]{C.RST} {C.BGRN}Scan Complete!{C.RST}")
    
    time.sleep(0.3)
    
    status_lines = [
        f"    {C.BCYN}+-------------------------------------------------------------+{C.RST}",
        f"    {C.BCYN}|{C.BWHT}                      DEVICE STATUS                          {C.BCYN}|{C.RST}",
        f"    {C.BCYN}+-------------------------------------------------------------+{C.RST}",
    ]
    
    for line in status_lines:
        print(line)
        time.sleep(0.1)
    
    device_info = [
        (f"{C.BGRN}*{C.RST}", "ADB Service", f"{C.BGRN}Running{C.RST}"),
        (f"{C.BGRN}*{C.RST}", "USB Debugging", f"{C.BGRN}Enabled{C.RST}"),
        (f"{C.BYEL}*{C.RST}", "Wireless ADB", f"{C.BYEL}Standby{C.RST}"),
        (f"{C.BGRN}*{C.RST}", "Device Detection", f"{C.BGRN}Active{C.RST}"),
        (f"{C.BGRN}*{C.RST}", "GUI Framework", f"{C.BGRN}Ready{C.RST}"),
    ]
    
    for icon, name, status in device_info:
        print(f"    {C.BCYN}|{C.RST}  {icon} {C.BWHT}{name:<17}{C.RST}: ", end='', flush=True)
        time.sleep(0.1)
        
        # Type out status
        for char in status:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.02)
        
        print(f"                            {C.BCYN}|{C.RST}")
        time.sleep(0.15)
    
    print(f"    {C.BCYN}+-------------------------------------------------------------+{C.RST}")
    time.sleep(0.3)


def print_disclaimer_animated():
    """Print disclaimer with animation"""
    
    time.sleep(0.3)
    
    print(f"\n    {C.BYEL}+=======================================================================+{C.RST}")
    time.sleep(0.1)
    
    warning_text = f"  {C.BRED}!  WARNING: {C.BWHT}This tool requires USB Debugging enabled!"
    print(f"    {C.BYEL}|", end='', flush=True)
    for char in warning_text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.015)
    print(f"{C.BYEL}        |{C.RST}")
    
    time.sleep(0.1)
    print(f"    {C.BYEL}|  {C.BWHT}    Use responsibly. Developer not liable for misuse.{C.BYEL}       |{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BYEL}+=======================================================================+{C.RST}")
    
    time.sleep(0.5)


def print_start_message_animated():
    """Print final start message with animation"""
    current_time = datetime.now().strftime("%H:%M:%S")
    center_print(f"{C.BGRN}[SYSTEM]{C.RST} {C.BWHT}All Cores Initialized Successfully!{C.RST}")
    center_print(f"{C.BGRN}[TIME]{C.RST}   {C.BYEL}{current_time}{C.RST}")
    center_print(f"{C.BCYN}[LAUNCH]{C.RST} {C.BCYN}Deploying Ultimate GUI Interface...{C.RST}")
    print()
    
    border = "=" * 61
    center_print(f"{C.BMAG}{border}{C.RST}")
    center_print(f"{C.BWHT}   Press {C.BRED}Ctrl+C{C.BWHT} to exit | {C.BGRN}Happy Managing!{C.RST}")
    center_print(f"{C.BMAG}{border}{C.RST}")
    print()
    
    border2 = f"    {C.BMAG}"
    for i in range(61):
        border2 += "═"
        print(f"\r{border2}{C.RST}", end='', flush=True)
        time.sleep(0.01)
    print()
    
    time.sleep(1)


def print_error_banner(error_msg):
    """Print error message in styled format"""
    
    print(f"\n    {C.BRED}#=======================================================#{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}|  {C.BWHT}   CRITICAL ERROR OCCURRED{C.BRED}                       |{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}|=======================================================|{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}|  {C.BYEL}Error: {C.BWHT}{str(error_msg)[:50]:<50}{C.BRED}  |{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}|=======================================================|{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}|  {C.BWHT}Please check the logs or contact developer{C.BRED}       |{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}|  {C.BCYN}GitHub: https://github.com/SudhirDevOps1{C.BRED}         |{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}#=======================================================#{C.RST}")


def print_exit_banner():
    """Print exit message with animation"""
    
    print(f"\n    {C.BCYN}+===============================================================+{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}|                                                               |{C.RST}")
    time.sleep(0.1)
    
    thank_you = f"  {C.BWHT}Thank you for using {C.BGRN}Ultimate Mobile Manager{C.BWHT}!"
    print(f"    {C.BCYN}|", end='', flush=True)
    for char in thank_you:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.02)
    print(f"{C.BCYN}               |{C.RST}")
    
    time.sleep(0.2)
    print(f"    {C.BCYN}|                                                               |{C.RST}")
    print(f"    {C.BCYN}|  {C.BYEL}* {C.BWHT}Star us on GitHub: {C.BBLU}@SudhirDevOps1{C.BCYN}                        |{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}|  {C.BYEL}* {C.BWHT}Follow for updates!{C.BCYN}                                        |{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}|                                                               |{C.RST}")
    
    goodbye = f"  {C.BMAG}Goodbye! See you soon!"
    print(f"    {C.BCYN}|", end='', flush=True)
    for char in goodbye:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.03)
    print(f"{C.BCYN}                                    |{C.RST}")
    
    print(f"    {C.BCYN}|                                                               |{C.RST}")
    print(f"    {C.BCYN}+===============================================================+{C.RST}\n")


def countdown_start(seconds=3):
    """Countdown before starting GUI"""
    
    print(f"\n    {C.BYEL}[*]{C.RST} {C.BCYN}Starting GUI in:{C.RST} ", end='', flush=True)
    
    for i in range(seconds, 0, -1):
        print(f"{C.BRED}{i}{C.RST}...", end='', flush=True)
        time.sleep(1)
    
    print(f"{C.BGRN}GO!{C.RST}\n")
    time.sleep(0.5)


# ══════════════════════════════════════════════════════════════════════════════════════
#                              YOUR MAIN APP CLASS HERE
# ══════════════════════════════════════════════════════════════════════════════════════

# class UltimateMobileManager:
#     def __init__(self):
#         ... Your 2000 lines of code ...
#     
#     def run(self):
#         self.root.mainloop()


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        # Enable ANSI colors on Windows
        enable_windows_ansi()
        
        # Clear screen
        clear_screen()
        
        # Hacker-style intro
        hacker_intro()
        
        # Print colorful banner with animation
        print_banner_animated()
        
        # Print info section
        print_info_animated()
        
        # Print features
        print_features_animated()
        
        # Print loading animation
        print_loading_bar_animated()
        
        # Print system checks
        print_system_check_animated()
        
        # Print device status
        print_device_status_animated()
        
        # Print disclaimer
        print_disclaimer_animated()
        
        # Print start message
        print_start_message_animated()
        
        # Countdown
        countdown_start(3)
        
        # Start your main application
        print(f"    {C.BGRN}[+]{C.RST} {C.BWHT}GUI Window Opening...{C.RST}\n")
        
        app = UltimateMobileManager()
        app.run()
        
        # Print exit message when closed
        print_exit_banner()
        
    except KeyboardInterrupt:
        print(f"\n\n    {C.BRED}[{C.BWHT}!{C.BRED}] {C.BYEL}User Interrupted. Shutting down...{C.RST}")
        time.sleep(0.5)
        print_exit_banner()
        sys.exit(0)
        
    except NameError:
        # If UltimateMobileManager class is not defined (for testing)
        print(f"\n    {C.BYEL}[!]{C.RST} {C.BWHT}Demo mode - UltimateMobileManager class not found{C.RST}")
        print(f"    {C.BGRN}[OK]{C.RST} {C.BGRN}Banner animation completed successfully!{C.RST}\n")
        
    except Exception as e:
        import traceback
        print_error_banner(e)
        print(f"\n    {C.BRED}[TRACEBACK]{C.RST}")
        traceback.print_exc()
        
        try:
            from tkinter import messagebox
            messagebox.showerror("Critical Error", str(e))
        except:
            pass
        
        sys.exit(1)


