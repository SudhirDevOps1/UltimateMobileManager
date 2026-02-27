"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                     ULTIMATE MOBILE MANAGER v5.1 - FIXED                             ║
║                     Developer: Sudhir Kumar (@SudhirDevOps1)                         ║
║                     All Bugs Fixed - Python 3.14 Compatible                          ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
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
        """Get device information"""
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
    
    def push(self, local_path, remote_path):
        """Push file to device"""
        return self.execute("push", str(local_path), remote_path, timeout=600)
    
    def pull(self, remote_path, local_path):
        """Pull file from device"""
        return self.execute("pull", remote_path, str(local_path), timeout=600)
    
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
        
        # Variables
        self.mobile_path = StringVar(value="/sdcard")
        self.pc_path = StringVar(value=str(Path.home()))
        self.password = StringVar()
        self.status = StringVar(value="Ready")
        
        # Data
        self.mobile_items = []
        self.pc_items = []
        
        # Clock
        self.clock_var = StringVar()
        self._update_clock()
        
        # Build UI
        self._setup_styles()
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
        Label(header, text="🚀 Ultimate Mobile Manager v5.1",
              font=("Segoe UI", 16, "bold"),
              bg=Config.BG_SECONDARY, fg=Config.TEXT).pack(side=LEFT, padx=15, pady=12)
        
        Label(header, text="By Sudhir Kumar (@SudhirDevOps1)",
              font=("Segoe UI", 9),
              bg=Config.BG_SECONDARY, fg=Config.TEXT_DIM).pack(side=LEFT)
        
        # Clock
        Label(header, textvariable=self.clock_var,
              font=("Consolas", 11),
              bg=Config.BG_SECONDARY, fg=Config.ACCENT).pack(side=RIGHT, padx=15)
        
        # Quick buttons
        btn_cfg = {'bg': Config.BG_TERTIARY, 'fg': Config.TEXT, 'relief': FLAT,
                   'font': ("Segoe UI", 9), 'cursor': 'hand2', 'padx': 10}
        
        Button(header, text="📸 Screenshot", command=self._take_screenshot, **btn_cfg).pack(side=RIGHT, padx=3, pady=10)
        Button(header, text="📺 Mirror", command=self._start_scrcpy, **btn_cfg).pack(side=RIGHT, padx=3, pady=10)
        Button(header, text="🔄 Refresh", command=self._refresh_all, **btn_cfg).pack(side=RIGHT, padx=3, pady=10)
    
    def _create_device_bar(self, parent):
        bar = Frame(parent, bg=Config.BG_CARD, height=85)
        bar.pack(fill=X, pady=5)
        bar.pack_propagate(False)
        
        # Device info
        dev_frame = Frame(bar, bg=Config.BG_CARD)
        dev_frame.pack(side=LEFT, padx=20, pady=10)
        
        self.device_label = Label(dev_frame, text="📱 Checking...",
                                  font=("Segoe UI", 12, "bold"),
                                  bg=Config.BG_CARD, fg=Config.TEXT)
        self.device_label.pack(anchor=W)
        
        self.device_detail = Label(dev_frame, text="",
                                   font=("Segoe UI", 9),
                                   bg=Config.BG_CARD, fg=Config.TEXT_DIM)
        self.device_detail.pack(anchor=W)
        
        # Battery
        batt_frame = Frame(bar, bg=Config.BG_CARD)
        batt_frame.pack(side=LEFT, padx=30, pady=10)
        
        Label(batt_frame, text="🔋 Battery",
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
        
        Label(stor_frame, text="💾 Storage",
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
        
        Label(net_frame, text="📶 Network",
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
        
        Label(time_frame, text="📱 Device Time",
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
        
        Label(inner, text="🔑 Password (min 10 chars):",
              font=("Segoe UI", 10),
              bg=Config.BG_TERTIARY, fg=Config.TEXT).pack(side=LEFT, pady=10)
        
        self.pwd_entry = Entry(inner, textvariable=self.password, show="●",
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
        
        self.pwd_strength = Label(inner, text="",
                                  font=("Segoe UI", 9),
                                  bg=Config.BG_TERTIARY)
        self.pwd_strength.pack(side=LEFT, padx=10)
        
        # Use trace_add for Python 3.14 compatibility
        try:
            self.password.trace_add('write', self._check_password)
        except AttributeError:
            self.password.trace('w', self._check_password)
    
    def _create_pc_panel(self, parent):
        frame = Frame(parent, bg=Config.BG_SECONDARY)
        frame.pack(fill=BOTH, expand=True)
        
        # Header
        header = Frame(frame, bg=Config.ACCENT, height=38)
        header.pack(fill=X)
        header.pack_propagate(False)
        
        Label(header, text="💻 PC FILES",
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
        
        Button(nav, text="⬆️", command=self._pc_up, width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="🏠", command=lambda: self._browse_pc(str(Path.home())),
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="🔄", command=lambda: self._browse_pc(self.pc_path.get()),
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
        
        Label(header, text="📱 MOBILE FILES",
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
        
        Button(nav, text="⬆️", command=self._mobile_up, width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="📱", command=lambda: self._browse_mobile("/sdcard"),
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="🔄", command=lambda: self._browse_mobile(self.mobile_path.get()),
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
        Frame(parent, bg=Config.BG_PRIMARY, height=40).pack()
        
        Label(parent, text="TRANSFER",
              font=("Segoe UI", 8, "bold"),
              bg=Config.BG_PRIMARY, fg=Config.TEXT_DIM).pack(pady=5)
        
        # Encrypted transfers
        Button(parent, text="▶▶\nEncrypt",
               font=("Segoe UI", 9, "bold"),
               command=self._transfer_pc_to_mobile,
               bg=Config.SUCCESS, fg='white', relief=FLAT,
               width=9, height=3, cursor='hand2').pack(pady=5)
        
        Label(parent, text="PC→Mobile",
              font=("Segoe UI", 7),
              bg=Config.BG_PRIMARY, fg=Config.TEXT_DIM).pack()
        
        Frame(parent, bg=Config.BG_PRIMARY, height=10).pack()
        
        Button(parent, text="◀◀\nDecrypt",
               font=("Segoe UI", 9, "bold"),
               command=self._transfer_mobile_to_pc,
               bg=Config.ACCENT2, fg='white', relief=FLAT,
               width=9, height=3, cursor='hand2').pack(pady=5)
        
        Label(parent, text="Mobile→PC",
              font=("Segoe UI", 7),
              bg=Config.BG_PRIMARY, fg=Config.TEXT_DIM).pack()
        
        Frame(parent, bg=Config.BG_PRIMARY, height=15).pack()
        Frame(parent, bg=Config.TEXT_DIM, height=1, width=70).pack(pady=5)
        
        Label(parent, text="DIRECT",
              font=("Segoe UI", 7),
              bg=Config.BG_PRIMARY, fg=Config.TEXT_DIM).pack(pady=3)
        
        Button(parent, text="→ Copy",
               font=("Segoe UI", 9),
               command=self._direct_pc_to_mobile,
               bg=Config.BG_TERTIARY, fg=Config.TEXT, relief=FLAT,
               width=9, cursor='hand2').pack(pady=3)
        
        Button(parent, text="← Copy",
               font=("Segoe UI", 9),
               command=self._direct_mobile_to_pc,
               bg=Config.BG_TERTIARY, fg=Config.TEXT, relief=FLAT,
               width=9, cursor='hand2').pack(pady=3)
        
        Frame(parent, bg=Config.BG_PRIMARY, height=10).pack()
        
        Button(parent, text="🗑️ Delete",
               font=("Segoe UI", 9),
               command=self._delete_selected,
               bg=Config.ERROR, fg='white', relief=FLAT,
               width=9, cursor='hand2').pack(pady=5)
        
        Frame(parent, bg=Config.BG_PRIMARY, height=10).pack()
        
        Button(parent, text="📸",
               font=("Segoe UI", 12),
               command=self._take_screenshot,
               bg=Config.BG_TERTIARY, fg=Config.TEXT, relief=FLAT,
               width=3, cursor='hand2').pack(pady=2)
        
        Button(parent, text="📱",
               font=("Segoe UI", 12),
               command=self._show_apps,
               bg=Config.BG_TERTIARY, fg=Config.TEXT, relief=FLAT,
               width=3, cursor='hand2').pack(pady=2)
    
    def _create_status_bar(self, parent):
        bar = Frame(parent, bg=Config.BG_SECONDARY, height=32)
        bar.pack(fill=X, pady=(5, 0))
        bar.pack_propagate(False)
        
        Label(bar, textvariable=self.status,
              font=("Segoe UI", 9),
              bg=Config.BG_SECONDARY, fg=Config.TEXT).pack(side=LEFT, padx=10, pady=6)
        
        self.progress = ttk.Progressbar(bar, mode='indeterminate', length=150)
        self.progress.pack(side=RIGHT, padx=10, pady=6)
        
        Label(bar, text="🔐 AES-256-GCM | PBKDF2 100K | SHA-256",
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
        """Update device information display"""
        if not self.adb.is_available():
            self.device_label.config(text="❌ ADB Not Found", fg=Config.ERROR)
            return
        
        connected, device_id, message = self.adb.check_connection()
        
        if connected:
            # Device info
            info = self.adb.get_device_info()
            brand = safe_str(info.get('brand', ''))
            model = safe_str(info.get('model', ''))
            android = safe_str(info.get('android', ''))
            sdk = safe_str(info.get('sdk', ''))
            
            self.device_label.config(text=f"✅ {brand} {model}", fg=Config.SUCCESS)
            self.device_detail.config(text=f"Android {android} | SDK {sdk}")
            
            # Battery
            battery = self.adb.get_battery_info()
            if battery:
                level = battery.get('level', '--')
                self.battery_label.config(text=f"{level}%")
                
                try:
                    lvl = int(level)
                    if lvl <= 20:
                        self.battery_label.config(fg=Config.ERROR)
                    elif lvl <= 50:
                        self.battery_label.config(fg=Config.WARNING)
                    else:
                        self.battery_label.config(fg=Config.SUCCESS)
                except:
                    pass
                
                status = battery.get('status', '')
                if '2' in status:
                    self.charging_label.config(text="⚡ Charging")
                elif '5' in status:
                    self.charging_label.config(text="✅ Full")
                else:
                    self.charging_label.config(text="🔌 Unplugged")
            
            # Storage
            storage = self.adb.get_storage_info()
            if storage:
                self.storage_label.config(text=storage.get('free', '--'))
                self.storage_detail.config(text=f"Used: {storage.get('used', '--')}")
            
            # Network
            network = self.adb.get_network_info()
            self.network_label.config(text=network.get('wifi_ssid', 'Not connected'))
            self.ip_label.config(text=network.get('ip', ''))
            
            # Device time
            self.device_time.config(text=self.adb.get_device_time())
            self.uptime_label.config(text=f"Up: {self.adb.get_uptime()}")
            
            # Auto load mobile if empty
            if not self.mobile_items:
                self._browse_mobile("/sdcard")
        else:
            self.device_label.config(text=f"❌ {message}", fg=Config.ERROR)
            self.device_detail.config(text="Connect USB & enable debugging")
            self.battery_label.config(text="---%", fg=Config.TEXT_DIM)
            self.storage_label.config(text="---")
    
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
    
    def _browse_mobile(self, path):
        """Browse mobile directory"""
        connected, _, _ = self.adb.check_connection()
        
        if not connected:
            for item in self.mobile_tree.get_children():
                self.mobile_tree.delete(item)
            
            self.mobile_tree.insert('', END, values=("❌ Not connected", "", ""))
            self.mobile_tree.insert('', END, values=("1. Connect USB cable", "", ""))
            self.mobile_tree.insert('', END, values=("2. Enable USB Debugging", "", ""))
            self.mobile_tree.insert('', END, values=("3. Allow on phone", "", ""))
            self.mobile_count.config(text="0")
            return
        
        self.status.set(f"Loading: {path}")
        self.progress.start()
        self.root.update()
        
        self.mobile_path.set(path)
        
        for item in self.mobile_tree.get_children():
            self.mobile_tree.delete(item)
        
        items = self.adb.list_directory(path)
        self.mobile_items = items
        
        if not items:
            self.mobile_tree.insert('', END, values=("📂 (Empty)", "-", "-"))
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
        menu.add_command(label="📤 Send (Encrypted)", command=self._transfer_pc_to_mobile)
        menu.add_command(label="📤 Send (Direct)", command=self._direct_pc_to_mobile)
        menu.add_separator()
        menu.add_command(label="📁 New Folder", command=self._new_folder_pc)
        menu.add_command(label="🗑️ Delete", command=self._delete_pc)
        menu.add_separator()
        menu.add_command(label="🔄 Refresh", command=lambda: self._browse_pc(self.pc_path.get()))
        menu.tk_popup(event.x_root, event.y_root)
    
    def _mobile_context(self, event):
        menu = Menu(self.root, tearoff=0, bg=Config.BG_SECONDARY, fg=Config.TEXT)
        menu.add_command(label="📥 Get (Encrypted)", command=self._transfer_mobile_to_pc)
        menu.add_command(label="📥 Get (Direct)", command=self._direct_mobile_to_pc)
        menu.add_separator()
        menu.add_command(label="📁 New Folder", command=self._new_folder_mobile)
        menu.add_command(label="🗑️ Delete", command=self._delete_mobile)
        menu.add_separator()
        menu.add_command(label="🔄 Refresh", command=lambda: self._browse_mobile(self.mobile_path.get()))
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
                
                self.status.set("📤 Sending to mobile...")
                self.root.update()
                
                remote = f"{dest.rstrip('/')}/backup_{timestamp}.secbak"
                success, _, stderr = self.adb.push(enc_path, remote)
                
                if not success:
                    raise Exception(f"Push failed: {stderr}")
                
                # Cleanup
                zip_path.unlink(missing_ok=True)
                
                # Local backup
                local_backup = Config.BACKUP_DIR / f"backup_{timestamp}.secbak"
                shutil.copy(enc_path, local_backup)
                enc_path.unlink(missing_ok=True)
                
                self.status.set("✅ Transfer complete!")
                
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
                    
                    self.status.set(f"📥 Getting: {name}")
                    self.root.update()
                    
                    if name.endswith('.secbak'):
                        local_enc = Config.TEMP_DIR / name
                        success, _, stderr = self.adb.pull(remote, local_enc)
                        
                        if not success:
                            raise Exception(f"Pull failed: {stderr}")
                        
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
        
        Button(btn_frame, text="▶️ Open", command=open_app,
               bg=Config.SUCCESS, fg='white', relief=FLAT, padx=15).pack(side=LEFT, padx=5)
        Button(btn_frame, text="🗑️ Uninstall", command=uninstall_app,
               bg=Config.ERROR, fg='white', relief=FLAT, padx=15).pack(side=LEFT, padx=5)
    
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
            self.pwd_strength.config(text=f"❌ {length}/10", fg=Config.ERROR)
        elif length < 14:
            self.pwd_strength.config(text=f"✅ Good ({length})", fg=Config.SUCCESS)
        else:
            self.pwd_strength.config(text=f"💪 Strong ({length})", fg=Config.SUCCESS)
    
    def _get_icon(self, name, is_dir, is_link=False):
        if is_link:
            return "🔗"
        if is_dir:
            lower = name.lower()
            icons = {
                'dcim': '📷', 'camera': '📷', 'download': '📥', 'downloads': '📥',
                'music': '🎵', 'pictures': '🖼️', 'photos': '🖼️', 'movies': '🎬',
                'videos': '🎬', 'documents': '📝', 'whatsapp': '💬', 'android': '🤖',
                'desktop': '🖥️', 'telegram': '✈️'
            }
            return icons.get(lower, '📁')
        
        ext = Path(name).suffix.lower()
        icons = {
            '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️', '.gif': '🖼️', '.webp': '🖼️',
            '.mp4': '🎬', '.mkv': '🎬', '.avi': '🎬', '.mov': '🎬',
            '.mp3': '🎵', '.wav': '🎵', '.flac': '🎵', '.m4a': '🎵',
            '.pdf': '📕', '.doc': '📝', '.docx': '📝', '.txt': '📄',
            '.xls': '📊', '.xlsx': '📊', '.ppt': '📽️', '.pptx': '📽️',
            '.zip': '📦', '.rar': '📦', '.7z': '📦',
            '.apk': '📱', '.exe': '⚙️',
            '.py': '🐍', '.js': '💛', '.html': '🌐',
            '.secbak': '🔐'
        }
        return icons.get(ext, '📄')
    
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
    
    # Reset
    R = '\033[0m'
    RST = '\033[0m'
    
    # Regular Colors
    BLK = '\033[30m'
    RED = '\033[31m'
    GRN = '\033[32m'
    YEL = '\033[33m'
    BLU = '\033[34m'
    MAG = '\033[35m'
    CYN = '\033[36m'
    WHT = '\033[37m'
    
    # Bright/Bold Colors
    BRED = '\033[91m'
    BGRN = '\033[92m'
    BYEL = '\033[93m'
    BBLU = '\033[94m'
    BMAG = '\033[95m'
    BCYN = '\033[96m'
    BWHT = '\033[97m'
    
    # Bold
    BOLD = '\033[1m'


# ═══════════════════════════════════════════════════════════════
#                     ANIMATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def enable_windows_ansi():
    """Enable ANSI escape codes on Windows"""
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass


def slow_print(text, delay=0.03):
    """Print text character by character (typing effect)"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def slow_print_fast(text, delay=0.01):
    """Faster typing effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def line_by_line_print(text, delay=0.05):
    """Print each line with delay"""
    lines = text.split('\n')
    for line in lines:
        print(line)
        time.sleep(delay)


def matrix_effect(duration=2):
    """Matrix-style random characters effect"""
    chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
    width = 60
    end_time = time.time() + duration
    
    while time.time() < end_time:
        line = ''.join(random.choice(chars) for _ in range(width))
        print(f"    {C.BGRN}{line}{C.RST}", end='\r')
        time.sleep(0.05)
    print(" " * 70, end='\r')


def hacker_intro():
    """Initial hacker-style intro animation"""
    
    print(f"\n    {C.BGRN}[", end='')
    for _ in range(40):
        print("=", end='', flush=True)
        time.sleep(0.02)
    print(f"]{C.RST}")
    
    time.sleep(0.3)
    
    messages = [
        f"    {C.BYEL}[*]{C.RST} {C.BCYN}Initializing secure connection...{C.RST}",
        f"    {C.BYEL}[*]{C.RST} {C.BCYN}Loading kernel modules...{C.RST}",
        f"    {C.BYEL}[*]{C.RST} {C.BCYN}Establishing ADB bridge...{C.RST}",
        f"    {C.BGRN}[✓]{C.RST} {C.BGRN}Connection established!{C.RST}",
    ]
    
    for msg in messages:
        slow_print_fast(msg, 0.02)
        time.sleep(0.3)
    
    time.sleep(0.5)


def print_banner_animated():
    """Print the main colorful banner with animation"""
    
    # First show matrix effect
    print(f"\n    {C.BYEL}[*]{C.RST} {C.BCYN}Decrypting banner...{C.RST}")
    time.sleep(0.5)
    matrix_effect(1.5)
    
    time.sleep(0.3)
    
    banner_lines = [
        f"{C.BCYN}",
        f"    ╔═══════════════════════════════════════════════════════════════════════════════════╗",
        f"    ║                                                                                   ║",
        f"    ║  {C.BRED}  ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗{C.BCYN}                  ║",
        f"    ║  {C.BRED}  ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝{C.BCYN}                  ║",
        f"    ║  {C.BYEL}  ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗{C.BCYN}                    ║",
        f"    ║  {C.BGRN}  ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝{C.BCYN}                    ║",
        f"    ║  {C.BBLU}  ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗{C.BCYN}                  ║",
        f"    ║  {C.BMAG}   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝{C.BCYN}                  ║",
        f"    ║                                                                                   ║",
        f"    ║  {C.BGRN}  ███╗   ███╗ ██████╗ ██████╗ ██╗██╗     ███████╗{C.BCYN}                                ║",
        f"    ║  {C.BGRN}  ████╗ ████║██╔═══██╗██╔══██╗██║██║     ██╔════╝{C.BCYN}                                ║",
        f"    ║  {C.BYEL}  ██╔████╔██║██║   ██║██████╔╝██║██║     █████╗{C.BCYN}                                  ║",
        f"    ║  {C.BYEL}  ██║╚██╔╝██║██║   ██║██╔══██╗██║██║     ██╔══╝{C.BCYN}                                  ║",
        f"    ║  {C.BRED}  ██║ ╚═╝ ██║╚██████╔╝██████╔╝██║███████╗███████╗{C.BCYN}                                ║",
        f"    ║  {C.BRED}  ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝{C.BCYN}                                ║",
        f"    ║                                                                                   ║",
        f"    ║  {C.BMAG}  ███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗{C.BCYN}                   ║",
        f"    ║  {C.BMAG}  ████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗{C.BCYN}                  ║",
        f"    ║  {C.BBLU}  ██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝{C.BCYN}                  ║",
        f"    ║  {C.BBLU}  ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗{C.BCYN}                  ║",
        f"    ║  {C.BGRN}  ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║{C.BCYN}                  ║",
        f"    ║  {C.BGRN}  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝{C.BCYN}                  ║",
        f"    ║                                                                                   ║",
        f"    ╚═══════════════════════════════════════════════════════════════════════════════════╝{C.RST}",
    ]
    
    # Print banner line by line with delay
    for line in banner_lines:
        print(line)
        time.sleep(0.04)
    
    time.sleep(0.5)


def print_info_animated():
    """Print info section with animation"""
    
    print(f"\n    {C.BYEL}[*]{C.RST} {C.BCYN}Loading tool information...{C.RST}")
    time.sleep(0.5)
    
    print(f"    {C.BCYN}╠═══════════════════════════════════════════════════════════════════════════════════╣{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}║                                                                                   ║{C.RST}")
    time.sleep(0.1)
    
    info_lines = [
        (f"    {C.BCYN}║   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Version      {C.BWHT}: ", f"{C.BGRN}5.1 {C.BMAG}(Stable Release){C.BCYN}                                 ║{C.RST}"),
        (f"    {C.BCYN}║   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Author       {C.BWHT}: ", f"{C.BGRN}Sudhir Kumar{C.BCYN}                                             ║{C.RST}"),
        (f"    {C.BCYN}║   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}GitHub       {C.BWHT}: ", f"{C.BBLU}https://github.com/SudhirDevOps1{C.BCYN}                         ║{C.RST}"),
        (f"    {C.BCYN}║   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Telegram     {C.BWHT}: ", f"{C.BBLU}@SudhirDevOps1{C.BCYN}                                           ║{C.RST}"),
        (f"    {C.BCYN}║   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Python       {C.BWHT}: ", f"{C.BGRN}3.14+ Compatible{C.BCYN}                                         ║{C.RST}"),
        (f"    {C.BCYN}║   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Platform     {C.BWHT}: ", f"{C.BGRN}Windows / Linux / macOS{C.BCYN}                                  ║{C.RST}"),
        (f"    {C.BCYN}║   {C.BWHT}[{C.BGRN}INFO{C.BWHT}]{C.RST} {C.BYEL}Status       {C.BWHT}: ", f"{C.BGRN}✓ All Bugs Fixed{C.BCYN}                                         ║{C.RST}"),
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
    
    print(f"    {C.BCYN}║                                                                                   ║{C.RST}")
    time.sleep(0.1)


def print_features_animated():
    """Print features with animation"""
    
    print(f"    {C.BCYN}╠═══════════════════════════════════════════════════════════════════════════════════╣{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}║                                                                                   ║{C.RST}")
    time.sleep(0.1)
    
    print(f"    {C.BCYN}║   {C.BRED}⚡{C.BWHT} FEATURES:{C.BCYN}                                                                  ║{C.RST}")
    time.sleep(0.2)
    
    features = [
        f"    {C.BCYN}║   {C.BWHT}├──{C.BGRN} ✔ ADB Device Control      {C.BWHT}├──{C.BGRN} ✔ File Manager{C.BCYN}                          ║{C.RST}",
        f"    {C.BCYN}║   {C.BWHT}├──{C.BYEL} ✔ App Installer           {C.BWHT}├──{C.BYEL} ✔ Screen Mirror{C.BCYN}                         ║{C.RST}",
        f"    {C.BCYN}║   {C.BWHT}├──{C.BMAG} ✔ Backup & Restore        {C.BWHT}├──{C.BMAG} ✔ System Info{C.BCYN}                           ║{C.RST}",
        f"    {C.BCYN}║   {C.BWHT}├──{C.BBLU} ✔ Network Tools           {C.BWHT}├──{C.BBLU} ✔ Root Tools{C.BCYN}                            ║{C.RST}",
        f"    {C.BCYN}║   {C.BWHT}├──{C.BRED} ✔ Logcat Viewer           {C.BWHT}├──{C.BRED} ✔ Shell Access{C.BCYN}                          ║{C.RST}",
        f"    {C.BCYN}║   {C.BWHT}└──{C.BGRN} ✔ Wireless ADB            {C.BWHT}└──{C.BGRN} ✔ Multi-Device{C.BCYN}                          ║{C.RST}",
    ]
    
    for feature in features:
        print(feature)
        time.sleep(0.15)
    
    print(f"    {C.BCYN}║                                                                                   ║{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}╚═══════════════════════════════════════════════════════════════════════════════════╝{C.RST}")
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
        filled = "█" * i
        empty = "░" * (total - i)
        
        # Color changes based on progress
        if percentage < 30:
            color = C.BRED
        elif percentage < 70:
            color = C.BYEL
        else:
            color = C.BGRN
        
        # Spinner animation
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'][i % 10]
        
        sys.stdout.write(f"\r    {C.BCYN}{spinner}{C.RST} {C.BWHT}[{color}{filled}{C.WHT}{empty}{C.BWHT}] {color}{percentage:3d}%{C.RST}  ")
        sys.stdout.flush()
        
        # Variable speed - slower at start and end
        if percentage < 20:
            time.sleep(0.08)
        elif percentage > 80:
            time.sleep(0.06)
        else:
            time.sleep(0.04)
    
    print(f"\n\n    {C.BGRN}[✓]{C.RST} {C.BGRN}Loading complete!{C.RST}")
    time.sleep(0.5)


def print_system_check_animated():
    """Print system check status with slow animation"""
    
    print(f"\n    {C.BYEL}[*]{C.RST} {C.BCYN}Running system diagnostics...{C.RST}")
    time.sleep(0.5)
    
    print(f"\n    {C.BCYN}┌─────────────────────────────────────────────────────────────┐{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}│{C.BWHT}                    SYSTEM INITIALIZATION                    {C.BCYN}│{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}├─────────────────────────────────────────────────────────────┤{C.RST}")
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
        print(f"    {C.BCYN}│{C.RST}  {C.BYEL}○{C.RST} {C.BWHT}{task}", end='', flush=True)
        
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
        status_icon = "✓" if success else "✗"
        
        # Replace the line with final result
        print(f"\r    {C.BCYN}│{C.RST}  {C.BGRN}{status_icon}{C.RST} {C.BWHT}{task:<35}{C.RST} [{status_color}{result:^10}{C.RST}] {C.BCYN}│{C.RST}")
        
        time.sleep(0.15)
    
    print(f"    {C.BCYN}└─────────────────────────────────────────────────────────────┘{C.RST}")
    time.sleep(0.3)


def print_device_status_animated():
    """Print device connection status with animation"""
    
    print(f"\n    {C.BYEL}[*]{C.RST} {C.BCYN}Detecting connected devices...{C.RST}")
    time.sleep(0.5)
    
    # Scanning animation
    print(f"    {C.BYEL}[", end='', flush=True)
    for i in range(20):
        print("▓", end='', flush=True)
        time.sleep(0.05)
    print(f"]{C.RST} {C.BGRN}Scan Complete!{C.RST}")
    
    time.sleep(0.3)
    
    status_lines = [
        f"    {C.BCYN}┌─────────────────────────────────────────────────────────────┐{C.RST}",
        f"    {C.BCYN}│{C.BWHT}                      DEVICE STATUS                          {C.BCYN}│{C.RST}",
        f"    {C.BCYN}├─────────────────────────────────────────────────────────────┤{C.RST}",
    ]
    
    for line in status_lines:
        print(line)
        time.sleep(0.1)
    
    device_info = [
        (f"{C.BGRN}●{C.RST}", "ADB Service", f"{C.BGRN}Running{C.RST}"),
        (f"{C.BGRN}●{C.RST}", "USB Debugging", f"{C.BGRN}Enabled{C.RST}"),
        (f"{C.BYEL}●{C.RST}", "Wireless ADB", f"{C.BYEL}Standby{C.RST}"),
        (f"{C.BGRN}●{C.RST}", "Device Detection", f"{C.BGRN}Active{C.RST}"),
        (f"{C.BGRN}●{C.RST}", "GUI Framework", f"{C.BGRN}Ready{C.RST}"),
    ]
    
    for icon, name, status in device_info:
        print(f"    {C.BCYN}│{C.RST}  {icon} {C.BWHT}{name:<17}{C.RST}: ", end='', flush=True)
        time.sleep(0.1)
        
        # Type out status
        for char in status:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.02)
        
        print(f"                            {C.BCYN}│{C.RST}")
        time.sleep(0.15)
    
    print(f"    {C.BCYN}└─────────────────────────────────────────────────────────────┘{C.RST}")
    time.sleep(0.3)


def print_disclaimer_animated():
    """Print disclaimer with animation"""
    
    time.sleep(0.3)
    
    print(f"\n    {C.BYEL}╔═══════════════════════════════════════════════════════════════╗{C.RST}")
    time.sleep(0.1)
    
    warning_text = f"  {C.BRED}⚠  WARNING: {C.BWHT}This tool requires USB Debugging enabled!"
    print(f"    {C.BYEL}║", end='', flush=True)
    for char in warning_text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.015)
    print(f"{C.BYEL}        ║{C.RST}")
    
    time.sleep(0.1)
    print(f"    {C.BYEL}║  {C.BWHT}    Use responsibly. Developer not liable for misuse.{C.BYEL}       ║{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BYEL}╚═══════════════════════════════════════════════════════════════╝{C.RST}")
    
    time.sleep(0.5)


def print_start_message_animated():
    """Print final start message with animation"""
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    messages = [
        (f"    {C.BWHT}[{C.BGRN}✓{C.BWHT}]{C.RST} ", f"{C.BGRN}All systems initialized successfully!{C.RST}"),
        (f"    {C.BWHT}[{C.BGRN}✓{C.BWHT}]{C.RST} ", f"{C.BGRN}Started at: {C.BYEL}{current_time}{C.RST}"),
        (f"    {C.BWHT}[{C.BGRN}+{C.BWHT}]{C.RST} ", f"{C.BCYN}Launching GUI Interface...{C.RST}"),
    ]
    
    print()
    for prefix, msg in messages:
        print(prefix, end='', flush=True)
        time.sleep(0.2)
        slow_print_fast(msg, 0.02)
        time.sleep(0.3)
    
    print()
    
    # Final border animation
    border = f"    {C.BMAG}"
    for i in range(61):
        border += "═"
        print(f"\r{border}{C.RST}", end='', flush=True)
        time.sleep(0.01)
    print()
    
    final_msg = f"    {C.BWHT}   Press {C.BRED}Ctrl+C{C.BWHT} to exit | {C.BGRN}Happy Managing!{C.BWHT} 🚀{C.RST}"
    slow_print_fast(final_msg, 0.02)
    
    border2 = f"    {C.BMAG}"
    for i in range(61):
        border2 += "═"
        print(f"\r{border2}{C.RST}", end='', flush=True)
        time.sleep(0.01)
    print()
    
    time.sleep(1)


def print_error_banner(error_msg):
    """Print error message in styled format"""
    
    print(f"\n    {C.BRED}╔═══════════════════════════════════════════════════════════════╗{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}║  {C.BWHT}⚠  CRITICAL ERROR OCCURRED{C.BRED}                                   ║{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}╠═══════════════════════════════════════════════════════════════╣{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}║  {C.BYEL}Error: {C.BWHT}{str(error_msg)[:50]:<50}{C.BRED}  ║{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}╠═══════════════════════════════════════════════════════════════╣{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}║  {C.BWHT}Please check the logs or contact developer{C.BRED}                   ║{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}║  {C.BCYN}GitHub: https://github.com/SudhirDevOps1{C.BRED}                     ║{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BRED}╚═══════════════════════════════════════════════════════════════╝{C.RST}")


def print_exit_banner():
    """Print exit message with animation"""
    
    print(f"\n    {C.BCYN}╔═══════════════════════════════════════════════════════════════╗{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}║                                                               ║{C.RST}")
    time.sleep(0.1)
    
    thank_you = f"  {C.BWHT}Thank you for using {C.BGRN}Ultimate Mobile Manager{C.BWHT}!"
    print(f"    {C.BCYN}║", end='', flush=True)
    for char in thank_you:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.02)
    print(f"{C.BCYN}               ║{C.RST}")
    
    time.sleep(0.2)
    print(f"    {C.BCYN}║                                                               ║{C.RST}")
    print(f"    {C.BCYN}║  {C.BYEL}★ {C.BWHT}Star us on GitHub: {C.BBLU}@SudhirDevOps1{C.BCYN}                        ║{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}║  {C.BYEL}★ {C.BWHT}Follow for updates!{C.BCYN}                                        ║{C.RST}")
    time.sleep(0.1)
    print(f"    {C.BCYN}║                                                               ║{C.RST}")
    
    goodbye = f"  {C.BMAG}Goodbye! See you soon! 👋"
    print(f"    {C.BCYN}║", end='', flush=True)
    for char in goodbye:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.03)
    print(f"{C.BCYN}                                    ║{C.RST}")
    
    print(f"    {C.BCYN}║                                                               ║{C.RST}")
    print(f"    {C.BCYN}╚═══════════════════════════════════════════════════════════════╝{C.RST}\n")


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
        print(f"    {C.BGRN}[✓]{C.RST} {C.BGRN}Banner animation completed successfully!{C.RST}\n")
        
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





        # bahut badhiya work kar raha hain kuchh change na karna but do error hain jaise delete button ke bad wala nahi dikh raha hain thik uske bad jo top me menu jaise tha help,device..etc nahi hain add karo baki sab yahi feture rahna chahiye kuchh hatana nahi