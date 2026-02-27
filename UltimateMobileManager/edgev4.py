"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                     ULTIMATE SECURE FILE BROWSER v5.0                                ║
║                     All-in-One Mobile Management Tool                                ║
║                                                                                      ║
║  Features: File Browser | Screen Mirror | Battery | Apps | Contacts | And More!     ║
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
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import *
from tkinter import ttk, messagebox, filedialog, simpledialog

# Install required packages
def install_packages():
    packages = ['cryptography', 'pillow']
    for pkg in packages:
        try:
            __import__(pkg.replace('-', '_'))
        except:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg], 
                         creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)

install_packages()

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except:
    PIL_AVAILABLE = False


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
    LOG_FILE = SCRIPT_DIR / "debug.log"
    
    # Create directories
    for d in [BACKUP_DIR, TEMP_DIR, SCREENSHOTS_DIR]:
        d.mkdir(exist_ok=True)
    
    # Theme Colors
    THEMES = {
        'dark': {
            'bg_primary': '#0a0e17',
            'bg_secondary': '#131a27',
            'bg_tertiary': '#1c2636',
            'accent': '#3b82f6',
            'accent2': '#8b5cf6',
            'success': '#10b981',
            'warning': '#f59e0b',
            'error': '#ef4444',
            'text': '#f1f5f9',
            'text_dim': '#64748b',
        },
        'light': {
            'bg_primary': '#f8fafc',
            'bg_secondary': '#e2e8f0',
            'bg_tertiary': '#cbd5e1',
            'accent': '#2563eb',
            'accent2': '#7c3aed',
            'success': '#059669',
            'warning': '#d97706',
            'error': '#dc2626',
            'text': '#1e293b',
            'text_dim': '#64748b',
        },
        'blue': {
            'bg_primary': '#0c1929',
            'bg_secondary': '#132f4c',
            'bg_tertiary': '#1e4976',
            'accent': '#5090d3',
            'accent2': '#b388ff',
            'success': '#66bb6a',
            'warning': '#ffa726',
            'error': '#f44336',
            'text': '#ffffff',
            'text_dim': '#8796a5',
        }
    }
    
    CURRENT_THEME = 'dark'


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    UTILITIES
# ══════════════════════════════════════════════════════════════════════════════════════

def safe_str(value, default=""):
    if value is None:
        return default
    try:
        return str(value).strip()
    except:
        return default

def get_theme():
    return Config.THEMES[Config.CURRENT_THEME]

def format_size(size):
    try:
        size = int(size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
    except:
        return str(size)
    return str(size)


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    ADB MANAGER
# ══════════════════════════════════════════════════════════════════════════════════════

class ADBManager:
    def __init__(self):
        self.adb_path = None
        self.device_id = None
        self._find_adb()
    
    def _find_adb(self):
        if Config.ADB_PATH.exists():
            self.adb_path = str(Config.ADB_PATH)
            return True
        
        try:
            result = subprocess.run(["adb", "version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.adb_path = "adb"
                return True
        except:
            pass
        
        return False
    
    def is_available(self):
        return self.adb_path is not None
    
    def execute(self, *args, timeout=60):
        if not self.adb_path:
            return False, "", "ADB not found"
        
        cmd = [self.adb_path] + list(args)
        
        try:
            kwargs = {'capture_output': True, 'text': True, 'timeout': timeout}
            if os.name == 'nt':
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            
            result = subprocess.run(cmd, **kwargs)
            return result.returncode == 0, safe_str(result.stdout), safe_str(result.stderr)
        except Exception as e:
            return False, "", str(e)
    
    def shell(self, command, timeout=30):
        return self.execute("shell", command, timeout=timeout)
    
    def check_connection(self):
        if not self.adb_path:
            return False, None, "ADB not installed"
        
        success, stdout, _ = self.execute("devices")
        if not success:
            return False, None, "ADB error"
        
        for line in stdout.strip().split('\n'):
            line = safe_str(line)
            if '\tdevice' in line:
                self.device_id = line.split('\t')[0]
                return True, self.device_id, "Connected"
            elif '\tunauthorized' in line:
                return False, line.split('\t')[0], "Unauthorized"
        
        return False, None, "No device"
    
    # ═══════════════════ DEVICE INFO ═══════════════════
    
    def get_device_info(self):
        info = {}
        props = {
            'brand': 'ro.product.brand',
            'model': 'ro.product.model',
            'device': 'ro.product.device',
            'android': 'ro.build.version.release',
            'sdk': 'ro.build.version.sdk',
            'security_patch': 'ro.build.version.security_patch',
            'build_id': 'ro.build.id',
            'hardware': 'ro.hardware',
            'serial': 'ro.serialno',
        }
        
        for key, prop in props.items():
            success, stdout, _ = self.shell(f"getprop {prop}")
            if success and stdout:
                info[key] = safe_str(stdout)
        
        return info
    
    def get_battery_info(self):
        success, stdout, _ = self.shell("dumpsys battery")
        
        if not success:
            return None
        
        info = {}
        for line in stdout.split('\n'):
            line = safe_str(line).strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                info[key] = value
        
        return info
    
    def get_storage_info(self):
        success, stdout, _ = self.shell("df -h /sdcard 2>/dev/null")
        
        if success and stdout:
            lines = stdout.strip().split('\n')
            for line in lines:
                if '/sdcard' in line or 'emulated' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        return {
                            'total': parts[1],
                            'used': parts[2],
                            'free': parts[3],
                            'percent': parts[4] if len(parts) > 4 else 'N/A'
                        }
        return None
    
    def get_memory_info(self):
        success, stdout, _ = self.shell("cat /proc/meminfo")
        
        if not success:
            return None
        
        info = {}
        for line in stdout.split('\n'):
            if 'MemTotal' in line:
                info['total'] = line.split(':')[1].strip()
            elif 'MemFree' in line:
                info['free'] = line.split(':')[1].strip()
            elif 'MemAvailable' in line:
                info['available'] = line.split(':')[1].strip()
        
        return info
    
    def get_cpu_info(self):
        success, stdout, _ = self.shell("cat /proc/cpuinfo | grep -E 'processor|model name|Hardware'")
        
        if not success:
            return None
        
        lines = stdout.strip().split('\n')
        cpu_count = sum(1 for l in lines if 'processor' in l.lower())
        hardware = ""
        
        for line in lines:
            if 'Hardware' in line:
                hardware = line.split(':')[1].strip() if ':' in line else ""
                break
        
        return {'cores': cpu_count, 'hardware': hardware}
    
    def get_screen_info(self):
        success, stdout, _ = self.shell("wm size")
        
        if success and stdout:
            match = re.search(r'(\d+)x(\d+)', stdout)
            if match:
                return {'width': match.group(1), 'height': match.group(2)}
        return None
    
    def get_network_info(self):
        info = {}
        
        # WiFi
        success, stdout, _ = self.shell("dumpsys wifi | grep 'mWifiInfo'")
        if success and stdout:
            ssid_match = re.search(r'SSID: ([^,]+)', stdout)
            if ssid_match:
                info['wifi_ssid'] = ssid_match.group(1).strip('"')
        
        # IP Address
        success, stdout, _ = self.shell("ip addr show wlan0 | grep 'inet '")
        if success and stdout:
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', stdout)
            if ip_match:
                info['ip'] = ip_match.group(1)
        
        return info
    
    def get_device_time(self):
        success, stdout, _ = self.shell("date '+%Y-%m-%d %H:%M:%S'")
        return safe_str(stdout) if success else "Unknown"
    
    def get_uptime(self):
        success, stdout, _ = self.shell("uptime -p 2>/dev/null || uptime")
        return safe_str(stdout).split(',')[0] if success else "Unknown"
    
    # ═══════════════════ FILE OPERATIONS ═══════════════════
    
    def list_directory(self, path):
        path = safe_str(path).strip()
        if not path:
            path = "/sdcard"
        if not path.startswith('/'):
            path = '/' + path
        path = path.rstrip('/') + '/'
        if path == '//':
            path = '/'
        
        items = []
        success, stdout, _ = self.shell(f'ls -la "{path}" 2>/dev/null')
        
        if not success or not stdout:
            return items
        
        for line in stdout.strip().split('\n'):
            line = safe_str(line)
            if not line or line.startswith('total') or line.startswith('ls:'):
                continue
            
            item = self._parse_ls_line(line, path)
            if item:
                items.append(item)
        
        items.sort(key=lambda x: (not x.get('is_dir', False), x.get('name', '').lower()))
        return items
    
    def _parse_ls_line(self, line, base_path):
        parts = line.split()
        if len(parts) < 5:
            return None
        
        permissions = safe_str(parts[0])
        last_part = safe_str(parts[-1])
        
        if last_part in ['.', '..']:
            return None
        
        is_dir = permissions.startswith('d')
        is_link = permissions.startswith('l')
        
        name = None
        size = '-'
        
        for i, part in enumerate(parts):
            if re.match(r'^\d{1,2}:\d{2}$', safe_str(part)) and i + 1 < len(parts):
                name = ' '.join(parts[i+1:])
                if not is_dir:
                    for j in range(i-1, 0, -1):
                        if parts[j].isdigit():
                            size = parts[j]
                            break
                break
        
        if not name:
            name = parts[-1]
        
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
            'permissions': permissions[:10],
            'full_path': f"{base_path.rstrip('/')}/{name}"
        }
    
    def push(self, local, remote):
        return self.execute("push", str(local), remote, timeout=600)
    
    def pull(self, remote, local):
        return self.execute("pull", remote, str(local), timeout=600)
    
    def mkdir(self, path):
        return self.shell(f'mkdir -p "{path}"')
    
    def remove(self, path):
        return self.shell(f'rm -rf "{path}"')
    
    # ═══════════════════ APPS ═══════════════════
    
    def get_installed_apps(self, system=False):
        flag = "" if system else "-3"  # -3 for third party only
        success, stdout, _ = self.shell(f"pm list packages {flag}")
        
        if not success:
            return []
        
        apps = []
        for line in stdout.strip().split('\n'):
            line = safe_str(line)
            if line.startswith('package:'):
                package = line.replace('package:', '').strip()
                apps.append(package)
        
        return sorted(apps)
    
    def get_app_info(self, package):
        success, stdout, _ = self.shell(f"dumpsys package {package} | grep -E 'versionName|versionCode|firstInstallTime|lastUpdateTime'")
        
        info = {'package': package}
        if success:
            for line in stdout.split('\n'):
                line = safe_str(line).strip()
                if 'versionName' in line:
                    info['version'] = line.split('=')[1] if '=' in line else ''
                elif 'firstInstallTime' in line:
                    info['installed'] = line.split('=')[1] if '=' in line else ''
        
        return info
    
    def install_apk(self, apk_path):
        return self.execute("install", "-r", str(apk_path), timeout=120)
    
    def uninstall_app(self, package):
        return self.shell(f"pm uninstall {package}")
    
    def open_app(self, package):
        return self.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
    
    def force_stop_app(self, package):
        return self.shell(f"am force-stop {package}")
    
    def clear_app_data(self, package):
        return self.shell(f"pm clear {package}")
    
    # ═══════════════════ SCREEN ═══════════════════
    
    def take_screenshot(self, save_path=None):
        if save_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = Config.SCREENSHOTS_DIR / f"screenshot_{timestamp}.png"
        
        remote_path = "/sdcard/screenshot_temp.png"
        
        # Take screenshot
        success, _, _ = self.shell(f"screencap -p {remote_path}")
        if not success:
            return False, "Failed to capture"
        
        # Pull to PC
        success, _, stderr = self.pull(remote_path, save_path)
        if not success:
            return False, stderr
        
        # Cleanup
        self.shell(f"rm {remote_path}")
        
        return True, str(save_path)
    
    def start_screen_record(self, duration=180):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        remote_path = f"/sdcard/recording_{timestamp}.mp4"
        
        # Start recording in background
        self.shell(f"screenrecord --time-limit {duration} {remote_path} &")
        return remote_path
    
    def stop_screen_record(self):
        self.shell("pkill -l SIGINT screenrecord")
    
    # ═══════════════════ CONTACTS ═══════════════════
    
    def get_contacts(self):
        success, stdout, _ = self.shell(
            "content query --uri content://contacts/phones/ --projection display_name:number"
        )
        
        if not success:
            return []
        
        contacts = []
        for line in stdout.split('\n'):
            if 'display_name=' in line:
                try:
                    name_match = re.search(r'display_name=([^,]+)', line)
                    number_match = re.search(r'number=([^,\s]+)', line)
                    
                    if name_match:
                        contact = {
                            'name': name_match.group(1),
                            'number': number_match.group(1) if number_match else ''
                        }
                        contacts.append(contact)
                except:
                    pass
        
        return contacts
    
    # ═══════════════════ SMS ═══════════════════
    
    def get_sms(self, limit=50):
        success, stdout, _ = self.shell(
            f"content query --uri content://sms/inbox --projection address:body:date --sort 'date DESC' | head -{limit}"
        )
        
        if not success:
            return []
        
        messages = []
        for line in stdout.split('\n'):
            if 'address=' in line:
                try:
                    addr_match = re.search(r'address=([^,]+)', line)
                    body_match = re.search(r'body=([^,]+)', line)
                    
                    if addr_match:
                        msg = {
                            'address': addr_match.group(1),
                            'body': body_match.group(1) if body_match else ''
                        }
                        messages.append(msg)
                except:
                    pass
        
        return messages
    
    # ═══════════════════ SYSTEM CONTROLS ═══════════════════
    
    def reboot(self, mode='normal'):
        modes = {
            'normal': 'reboot',
            'recovery': 'reboot recovery',
            'bootloader': 'reboot bootloader',
            'fastboot': 'reboot bootloader',
        }
        cmd = modes.get(mode, 'reboot')
        return self.execute(cmd)
    
    def screen_on(self):
        return self.shell("input keyevent KEYCODE_WAKEUP")
    
    def screen_off(self):
        return self.shell("input keyevent KEYCODE_SLEEP")
    
    def press_key(self, keycode):
        return self.shell(f"input keyevent {keycode}")
    
    def input_text(self, text):
        text = text.replace(' ', '%s').replace("'", "\\'")
        return self.shell(f"input text '{text}'")
    
    def tap(self, x, y):
        return self.shell(f"input tap {x} {y}")
    
    def swipe(self, x1, y1, x2, y2, duration=300):
        return self.shell(f"input swipe {x1} {y1} {x2} {y2} {duration}")
    
    def set_brightness(self, level):
        return self.shell(f"settings put system screen_brightness {level}")
    
    def set_volume(self, stream, level):
        # stream: 0=voice, 1=system, 2=ring, 3=media, 4=alarm
        return self.shell(f"media volume --stream {stream} --set {level}")


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    ENCRYPTION
# ══════════════════════════════════════════════════════════════════════════════════════

class Encryptor:
    @staticmethod
    def derive_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
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
                'v': '5.0', 'hash': hashlib.sha256(data).hexdigest(),
                'size': len(data), 'time': datetime.now().isoformat()
            }).encode()
            
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
                header = json.loads(f.read(header_len).decode())
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

class UltimateFileBrowser:
    def __init__(self):
        self.root = Tk()
        self.root.title("🚀 Ultimate Mobile Manager v5.0")
        self.root.geometry("1500x900")
        self.root.configure(bg=get_theme()['bg_primary'])
        
        # Fullscreen toggle
        self.is_fullscreen = False
        self.root.bind('<F11>', self.toggle_fullscreen)
        self.root.bind('<Escape>', self.exit_fullscreen)
        
        # Initialize
        self.adb = ADBManager()
        
        # Variables
        self.mobile_path = StringVar(value="/sdcard")
        self.pc_path = StringVar(value=str(Path.home()))
        self.password = StringVar()
        self.status = StringVar(value="Ready")
        self.search_var = StringVar()
        
        # Data
        self.mobile_items = []
        self.pc_items = []
        self.installed_apps = []
        
        # Clock update
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
        self._auto_refresh_device()
    
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
            f"ADB not found!\n\nDownload from:\n"
            f"https://developer.android.com/studio/releases/platform-tools\n\n"
            f"Extract to: {Config.PLATFORM_TOOLS}")
    
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        theme = get_theme()
        
        style.configure("Custom.Treeview",
            background=theme['bg_tertiary'],
            foreground=theme['text'],
            fieldbackground=theme['bg_tertiary'],
            rowheight=26,
            font=('Consolas', 10))
        
        style.configure("Custom.Treeview.Heading",
            background=theme['bg_secondary'],
            foreground=theme['text'],
            font=('Segoe UI', 10, 'bold'))
        
        style.map("Custom.Treeview",
            background=[('selected', theme['accent'])])
        
        style.configure("Custom.TNotebook",
            background=theme['bg_primary'])
        
        style.configure("Custom.TNotebook.Tab",
            background=theme['bg_secondary'],
            foreground=theme['text'],
            padding=[15, 8],
            font=('Segoe UI', 10))
        
        style.map("Custom.TNotebook.Tab",
            background=[('selected', theme['accent'])])
    
    def _create_menu(self):
        theme = get_theme()
        menubar = Menu(self.root, bg=theme['bg_secondary'], fg=theme['text'])
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0, bg=theme['bg_secondary'], fg=theme['text'])
        file_menu.add_command(label="📁 New Folder", command=self._new_folder)
        file_menu.add_command(label="🔄 Refresh All", command=self._refresh_all)
        file_menu.add_separator()
        file_menu.add_command(label="⚙️ Settings", command=self._show_settings)
        file_menu.add_separator()
        file_menu.add_command(label="❌ Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View Menu
        view_menu = Menu(menubar, tearoff=0, bg=theme['bg_secondary'], fg=theme['text'])
        view_menu.add_command(label="🖥️ Fullscreen (F11)", command=self.toggle_fullscreen)
        view_menu.add_separator()
        view_menu.add_command(label="🌙 Dark Theme", command=lambda: self._change_theme('dark'))
        view_menu.add_command(label="☀️ Light Theme", command=lambda: self._change_theme('light'))
        view_menu.add_command(label="🔵 Blue Theme", command=lambda: self._change_theme('blue'))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools Menu
        tools_menu = Menu(menubar, tearoff=0, bg=theme['bg_secondary'], fg=theme['text'])
        tools_menu.add_command(label="📸 Screenshot", command=self._take_screenshot)
        tools_menu.add_command(label="🎬 Screen Record", command=self._screen_record)
        tools_menu.add_command(label="📺 Screen Mirror", command=self._start_scrcpy)
        tools_menu.add_separator()
        tools_menu.add_command(label="📱 Device Info", command=self._show_device_info)
        tools_menu.add_command(label="🔋 Battery Info", command=self._show_battery_info)
        tools_menu.add_command(label="💾 Storage Info", command=self._show_storage_info)
        tools_menu.add_separator()
        tools_menu.add_command(label="📋 Installed Apps", command=self._show_apps)
        tools_menu.add_command(label="📇 Contacts", command=self._show_contacts)
        tools_menu.add_command(label="💬 SMS", command=self._show_sms)
        tools_menu.add_separator()
        tools_menu.add_command(label="💻 Terminal", command=self._show_terminal)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Device Menu
        device_menu = Menu(menubar, tearoff=0, bg=theme['bg_secondary'], fg=theme['text'])
        device_menu.add_command(label="🔄 Reboot", command=lambda: self._reboot('normal'))
        device_menu.add_command(label="🔧 Reboot Recovery", command=lambda: self._reboot('recovery'))
        device_menu.add_command(label="⚡ Reboot Bootloader", command=lambda: self._reboot('bootloader'))
        device_menu.add_separator()
        device_menu.add_command(label="🌙 Screen Off", command=lambda: self.adb.screen_off())
        device_menu.add_command(label="☀️ Screen On", command=lambda: self.adb.screen_on())
        menubar.add_cascade(label="Device", menu=device_menu)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0, bg=theme['bg_secondary'], fg=theme['text'])
        help_menu.add_command(label="📖 Guide", command=self._show_guide)
        help_menu.add_command(label="ℹ️ About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def _create_ui(self):
        theme = get_theme()
        
        # Main container
        main = Frame(self.root, bg=theme['bg_primary'])
        main.pack(fill=BOTH, expand=True)
        
        # ═══════════════════ TOP BAR ═══════════════════
        self._create_top_bar(main)
        
        # ═══════════════════ DEVICE INFO BAR ═══════════════════
        self._create_device_bar(main)
        
        # ═══════════════════ PASSWORD BAR ═══════════════════
        self._create_password_bar(main)
        
        # ═══════════════════ MAIN CONTENT ═══════════════════
        content = Frame(main, bg=theme['bg_primary'])
        content.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Left panel - PC
        left = Frame(content, bg=theme['bg_primary'])
        left.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 5))
        self._create_pc_panel(left)
        
        # Center - Transfer buttons
        center = Frame(content, bg=theme['bg_primary'], width=120)
        center.pack(side=LEFT, fill=Y, padx=5)
        center.pack_propagate(False)
        self._create_transfer_panel(center)
        
        # Right panel - Mobile
        right = Frame(content, bg=theme['bg_primary'])
        right.pack(side=LEFT, fill=BOTH, expand=True, padx=(5, 0))
        self._create_mobile_panel(right)
        
        # ═══════════════════ STATUS BAR ═══════════════════
        self._create_status_bar(main)
    
    def _create_top_bar(self, parent):
        theme = get_theme()
        
        bar = Frame(parent, bg=theme['bg_secondary'], height=50)
        bar.pack(fill=X, padx=10, pady=(10, 5))
        bar.pack_propagate(False)
        
        # Title
        Label(bar, text="🚀 Ultimate Mobile Manager", font=("Segoe UI", 16, "bold"),
              bg=theme['bg_secondary'], fg=theme['text']).pack(side=LEFT, padx=15, pady=10)
        
        # Clock
        Label(bar, textvariable=self.clock_var, font=("Consolas", 11),
              bg=theme['bg_secondary'], fg=theme['accent']).pack(side=RIGHT, padx=15)
        
        # Quick buttons
        btn_cfg = {'bg': theme['bg_tertiary'], 'fg': theme['text'], 'relief': FLAT,
                   'font': ("Segoe UI", 9), 'cursor': 'hand2', 'padx': 10}
        
        Button(bar, text="📸 Screenshot", command=self._take_screenshot, **btn_cfg).pack(side=RIGHT, padx=3, pady=8)
        Button(bar, text="📺 Mirror", command=self._start_scrcpy, **btn_cfg).pack(side=RIGHT, padx=3, pady=8)
        Button(bar, text="🔄 Refresh", command=self._refresh_all, **btn_cfg).pack(side=RIGHT, padx=3, pady=8)
    
    def _create_device_bar(self, parent):
        theme = get_theme()
        
        bar = Frame(parent, bg=theme['bg_tertiary'], height=80)
        bar.pack(fill=X, padx=10, pady=5)
        bar.pack_propagate(False)
        
        # Device status
        left = Frame(bar, bg=theme['bg_tertiary'])
        left.pack(side=LEFT, padx=15, pady=10)
        
        self.device_status = Label(left, text="📱 Checking...", font=("Segoe UI", 12, "bold"),
                                   bg=theme['bg_tertiary'], fg=theme['text'])
        self.device_status.pack(anchor=W)
        
        self.device_details = Label(left, text="", font=("Segoe UI", 9),
                                    bg=theme['bg_tertiary'], fg=theme['text_dim'])
        self.device_details.pack(anchor=W)
        
        # Battery
        battery_frame = Frame(bar, bg=theme['bg_tertiary'])
        battery_frame.pack(side=LEFT, padx=30, pady=10)
        
        Label(battery_frame, text="🔋 Battery", font=("Segoe UI", 9),
              bg=theme['bg_tertiary'], fg=theme['text_dim']).pack(anchor=W)
        
        self.battery_label = Label(battery_frame, text="---%", font=("Segoe UI", 14, "bold"),
                                   bg=theme['bg_tertiary'], fg=theme['success'])
        self.battery_label.pack(anchor=W)
        
        self.charging_label = Label(battery_frame, text="", font=("Segoe UI", 8),
                                    bg=theme['bg_tertiary'], fg=theme['text_dim'])
        self.charging_label.pack(anchor=W)
        
        # Storage
        storage_frame = Frame(bar, bg=theme['bg_tertiary'])
        storage_frame.pack(side=LEFT, padx=30, pady=10)
        
        Label(storage_frame, text="💾 Storage", font=("Segoe UI", 9),
              bg=theme['bg_tertiary'], fg=theme['text_dim']).pack(anchor=W)
        
        self.storage_label = Label(storage_frame, text="---", font=("Segoe UI", 14, "bold"),
                                   bg=theme['bg_tertiary'], fg=theme['accent'])
        self.storage_label.pack(anchor=W)
        
        self.storage_detail = Label(storage_frame, text="", font=("Segoe UI", 8),
                                    bg=theme['bg_tertiary'], fg=theme['text_dim'])
        self.storage_detail.pack(anchor=W)
        
        # Network
        network_frame = Frame(bar, bg=theme['bg_tertiary'])
        network_frame.pack(side=LEFT, padx=30, pady=10)
        
        Label(network_frame, text="📶 Network", font=("Segoe UI", 9),
              bg=theme['bg_tertiary'], fg=theme['text_dim']).pack(anchor=W)
        
        self.network_label = Label(network_frame, text="---", font=("Segoe UI", 11),
                                   bg=theme['bg_tertiary'], fg=theme['text'])
        self.network_label.pack(anchor=W)
        
        self.ip_label = Label(network_frame, text="", font=("Segoe UI", 8),
                              bg=theme['bg_tertiary'], fg=theme['text_dim'])
        self.ip_label.pack(anchor=W)
        
        # Device Time
        time_frame = Frame(bar, bg=theme['bg_tertiary'])
        time_frame.pack(side=RIGHT, padx=15, pady=10)
        
        Label(time_frame, text="📱 Device Time", font=("Segoe UI", 9),
              bg=theme['bg_tertiary'], fg=theme['text_dim']).pack(anchor=E)
        
        self.device_time = Label(time_frame, text="--:--:--", font=("Consolas", 12),
                                 bg=theme['bg_tertiary'], fg=theme['accent2'])
        self.device_time.pack(anchor=E)
        
        self.uptime_label = Label(time_frame, text="", font=("Segoe UI", 8),
                                  bg=theme['bg_tertiary'], fg=theme['text_dim'])
        self.uptime_label.pack(anchor=E)
    
    def _create_password_bar(self, parent):
        theme = get_theme()
        
        bar = Frame(parent, bg=theme['bg_secondary'], height=50)
        bar.pack(fill=X, padx=10, pady=5)
        bar.pack_propagate(False)
        
        inner = Frame(bar, bg=theme['bg_secondary'])
        inner.pack(expand=True, fill=X, padx=20)
        
        Label(inner, text="🔑 Password (min 10 chars):", font=("Segoe UI", 10),
              bg=theme['bg_secondary'], fg=theme['text']).pack(side=LEFT, pady=10)
        
        self.pwd_entry = Entry(inner, textvariable=self.password, show="●",
                               font=("Consolas", 12), width=25,
                               bg=theme['bg_tertiary'], fg=theme['text'],
                               insertbackground=theme['text'], relief=FLAT)
        self.pwd_entry.pack(side=LEFT, padx=10, pady=10, ipady=5)
        
        self.show_pwd = BooleanVar(value=False)
        Checkbutton(inner, text="Show", variable=self.show_pwd, command=self._toggle_pwd,
                    bg=theme['bg_secondary'], fg=theme['text_dim'],
                    selectcolor=theme['bg_tertiary']).pack(side=LEFT, padx=5)
        
        self.pwd_strength = Label(inner, text="", font=("Segoe UI", 9), bg=theme['bg_secondary'])
        self.pwd_strength.pack(side=LEFT, padx=10)
        
        self.password.trace('w', self._check_password)
        
        # Search
        Label(inner, text="🔍", font=("Segoe UI", 12),
              bg=theme['bg_secondary'], fg=theme['text_dim']).pack(side=RIGHT, padx=5)
        
        search_entry = Entry(inner, textvariable=self.search_var, font=("Segoe UI", 10),
                            width=20, bg=theme['bg_tertiary'], fg=theme['text'],
                            relief=FLAT, insertbackground=theme['text'])
        search_entry.pack(side=RIGHT, padx=5, pady=10, ipady=4)
        search_entry.bind('<Return>', self._search)
        
        Label(inner, text="Search:", font=("Segoe UI", 9),
              bg=theme['bg_secondary'], fg=theme['text_dim']).pack(side=RIGHT, padx=5)
    
    def _create_pc_panel(self, parent):
        theme = get_theme()
        
        frame = Frame(parent, bg=theme['bg_secondary'])
        frame.pack(fill=BOTH, expand=True)
        
        # Header
        header = Frame(frame, bg=theme['accent'], height=36)
        header.pack(fill=X)
        header.pack_propagate(False)
        
        Label(header, text="💻 PC FILES", font=("Segoe UI", 11, "bold"),
              bg=theme['accent'], fg='white').pack(side=LEFT, padx=12, pady=6)
        
        self.pc_count = Label(header, text="0", font=("Segoe UI", 9),
                              bg=theme['accent'], fg='#93c5fd')
        self.pc_count.pack(side=RIGHT, padx=12)
        
        # Navigation
        nav = Frame(frame, bg=theme['bg_secondary'])
        nav.pack(fill=X, padx=5, pady=5)
        
        btn_cfg = {'bg': theme['bg_tertiary'], 'fg': theme['text'], 'relief': FLAT,
                   'font': ("Segoe UI", 10), 'cursor': 'hand2'}
        
        Button(nav, text="⬆️", command=self._pc_up, width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="🏠", command=lambda: self._browse_pc(str(Path.home())), 
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="🔄", command=lambda: self._browse_pc(self.pc_path.get()), 
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        
        self.pc_path_entry = Entry(nav, textvariable=self.pc_path, font=("Consolas", 10),
                                   bg=theme['bg_tertiary'], fg=theme['text'], relief=FLAT)
        self.pc_path_entry.pack(side=LEFT, fill=X, expand=True, padx=5, ipady=4)
        self.pc_path_entry.bind('<Return>', lambda e: self._browse_pc(self.pc_path.get()))
        
        Button(nav, text="Go", command=lambda: self._browse_pc(self.pc_path.get()),
               bg=theme['accent'], fg='white', relief=FLAT, width=5,
               font=("Segoe UI", 9, "bold")).pack(side=LEFT, padx=2)
        
        # Quick access
        quick = Frame(frame, bg=theme['bg_secondary'])
        quick.pack(fill=X, padx=5, pady=2)
        
        for letter in 'CDEF':
            if Path(f"{letter}:/").exists():
                Button(quick, text=f"{letter}:", command=lambda d=letter: self._browse_pc(f"{d}:/"),
                       bg=theme['bg_tertiary'], fg=theme['text_dim'],
                       relief=FLAT, font=("Segoe UI", 8)).pack(side=LEFT, padx=2)
        
        for name, path in [("Desktop", Path.home() / "Desktop"),
                          ("Downloads", Path.home() / "Downloads"),
                          ("Documents", Path.home() / "Documents")]:
            if path.exists():
                Button(quick, text=name, command=lambda p=str(path): self._browse_pc(p),
                       bg=theme['bg_tertiary'], fg=theme['text_dim'],
                       relief=FLAT, font=("Segoe UI", 8)).pack(side=LEFT, padx=2)
        
        # Tree
        tree_frame = Frame(frame, bg=theme['bg_secondary'])
        tree_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        yscroll = Scrollbar(tree_frame, orient=VERTICAL)
        yscroll.pack(side=RIGHT, fill=Y)
        
        self.pc_tree = ttk.Treeview(tree_frame, columns=('name', 'size', 'type'),
                                     show='headings', selectmode='extended',
                                     style='Custom.Treeview', yscrollcommand=yscroll.set)
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
        theme = get_theme()
        
        frame = Frame(parent, bg=theme['bg_secondary'])
        frame.pack(fill=BOTH, expand=True)
        
        # Header
        header = Frame(frame, bg=theme['accent2'], height=36)
        header.pack(fill=X)
        header.pack_propagate(False)
        
        Label(header, text="📱 MOBILE FILES", font=("Segoe UI", 11, "bold"),
              bg=theme['accent2'], fg='white').pack(side=LEFT, padx=12, pady=6)
        
        self.mobile_count = Label(header, text="0", font=("Segoe UI", 9),
                                  bg=theme['accent2'], fg='#c4b5fd')
        self.mobile_count.pack(side=RIGHT, padx=12)
        
        # Navigation
        nav = Frame(frame, bg=theme['bg_secondary'])
        nav.pack(fill=X, padx=5, pady=5)
        
        btn_cfg = {'bg': theme['bg_tertiary'], 'fg': theme['text'], 'relief': FLAT,
                   'font': ("Segoe UI", 10), 'cursor': 'hand2'}
        
        Button(nav, text="⬆️", command=self._mobile_up, width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="📱", command=lambda: self._browse_mobile("/sdcard"),
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        Button(nav, text="🔄", command=lambda: self._browse_mobile(self.mobile_path.get()),
               width=3, **btn_cfg).pack(side=LEFT, padx=2)
        
        self.mobile_path_entry = Entry(nav, textvariable=self.mobile_path, font=("Consolas", 10),
                                       bg=theme['bg_tertiary'], fg=theme['text'], relief=FLAT)
        self.mobile_path_entry.pack(side=LEFT, fill=X, expand=True, padx=5, ipady=4)
        self.mobile_path_entry.bind('<Return>', lambda e: self._browse_mobile(self.mobile_path.get()))
        
        Button(nav, text="Go", command=lambda: self._browse_mobile(self.mobile_path.get()),
               bg=theme['accent2'], fg='white', relief=FLAT, width=5,
               font=("Segoe UI", 9, "bold")).pack(side=LEFT, padx=2)
        
        # Quick access
        quick = Frame(frame, bg=theme['bg_secondary'])
        quick.pack(fill=X, padx=5, pady=2)
        
        folders = [("/", "Root"), ("/sdcard", "SD"), ("/sdcard/DCIM", "DCIM"),
                   ("/sdcard/Download", "DL"), ("/sdcard/Pictures", "Pics"),
                   ("/sdcard/Music", "Music"), ("/sdcard/WhatsApp", "WA")]
        
        for path, name in folders:
            Button(quick, text=name, command=lambda p=path: self._browse_mobile(p),
                   bg=theme['bg_tertiary'], fg=theme['text_dim'],
                   relief=FLAT, font=("Segoe UI", 8)).pack(side=LEFT, padx=1)
        
        # Tree
        tree_frame = Frame(frame, bg=theme['bg_secondary'])
        tree_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
        
        yscroll = Scrollbar(tree_frame, orient=VERTICAL)
        yscroll.pack(side=RIGHT, fill=Y)
        
        self.mobile_tree = ttk.Treeview(tree_frame, columns=('name', 'size', 'type'),
                                         show='headings', selectmode='extended',
                                         style='Custom.Treeview', yscrollcommand=yscroll.set)
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
        theme = get_theme()
        
        Frame(parent, bg=theme['bg_primary'], height=50).pack()
        
        Label(parent, text="TRANSFER", font=("Segoe UI", 8, "bold"),
              bg=theme['bg_primary'], fg=theme['text_dim']).pack(pady=5)
        
        # Encrypted
        Button(parent, text="▶▶\nEncrypt", font=("Segoe UI", 9, "bold"),
               command=self._transfer_pc_to_mobile,
               bg=theme['success'], fg='white', relief=FLAT,
               width=9, height=3, cursor='hand2').pack(pady=5)
        
        Label(parent, text="PC→Mobile", font=("Segoe UI", 7),
              bg=theme['bg_primary'], fg=theme['text_dim']).pack()
        
        Frame(parent, bg=theme['bg_primary'], height=10).pack()
        
        Button(parent, text="◀◀\nDecrypt", font=("Segoe UI", 9, "bold"),
               command=self._transfer_mobile_to_pc,
               bg=theme['accent2'], fg='white', relief=FLAT,
               width=9, height=3, cursor='hand2').pack(pady=5)
        
        Label(parent, text="Mobile→PC", font=("Segoe UI", 7),
              bg=theme['bg_primary'], fg=theme['text_dim']).pack()
        
        Frame(parent, bg=theme['bg_primary'], height=15).pack()
        Frame(parent, bg=theme['text_dim'], height=1, width=70).pack(pady=5)
        
        Label(parent, text="DIRECT", font=("Segoe UI", 7),
              bg=theme['bg_primary'], fg=theme['text_dim']).pack(pady=3)
        
        Button(parent, text="→ Copy", font=("Segoe UI", 9),
               command=self._direct_pc_to_mobile,
               bg=theme['bg_tertiary'], fg=theme['text'], relief=FLAT,
               width=9, cursor='hand2').pack(pady=3)
        
        Button(parent, text="← Copy", font=("Segoe UI", 9),
               command=self._direct_mobile_to_pc,
               bg=theme['bg_tertiary'], fg=theme['text'], relief=FLAT,
               width=9, cursor='hand2').pack(pady=3)
        
        Frame(parent, bg=theme['bg_primary'], height=10).pack()
        
        Button(parent, text="🗑️ Delete", font=("Segoe UI", 9),
               command=self._delete_selected,
               bg=theme['error'], fg='white', relief=FLAT,
               width=9, cursor='hand2').pack(pady=5)
        
        Frame(parent, bg=theme['bg_primary'], height=10).pack()
        
        # Quick tools
        Button(parent, text="📸", font=("Segoe UI", 10),
               command=self._take_screenshot,
               bg=theme['bg_tertiary'], fg=theme['text'], relief=FLAT,
               width=3, cursor='hand2').pack(pady=2)
        
        Button(parent, text="📺", font=("Segoe UI", 10),
               command=self._start_scrcpy,
               bg=theme['bg_tertiary'], fg=theme['text'], relief=FLAT,
               width=3, cursor='hand2').pack(pady=2)
        
        Button(parent, text="📱", font=("Segoe UI", 10),
               command=self._show_apps,
               bg=theme['bg_tertiary'], fg=theme['text'], relief=FLAT,
               width=3, cursor='hand2').pack(pady=2)
    
    def _create_status_bar(self, parent):
        theme = get_theme()
        
        bar = Frame(parent, bg=theme['bg_secondary'], height=32)
        bar.pack(fill=X, padx=10, pady=(5, 10))
        bar.pack_propagate(False)
        
        Label(bar, textvariable=self.status, font=("Segoe UI", 9),
              bg=theme['bg_secondary'], fg=theme['text']).pack(side=LEFT, padx=10, pady=6)
        
        self.progress = ttk.Progressbar(bar, mode='indeterminate', length=150)
        self.progress.pack(side=RIGHT, padx=10, pady=6)
        
        Label(bar, text="🔐 AES-256-GCM | PBKDF2 100K | SHA-256", font=("Segoe UI", 8),
              bg=theme['bg_secondary'], fg=theme['text_dim']).pack(side=RIGHT, padx=15)
    
    # ══════════════════════════════════════════════════════════════════════════════════════
    #                                    BROWSER FUNCTIONS
    # ══════════════════════════════════════════════════════════════════════════════════════
    
    def _initial_load(self):
        self._update_device_info()
        self._browse_pc(str(Path.home()))
    
    def _refresh_all(self):
        self._update_device_info()
        self._browse_pc(self.pc_path.get())
        self._browse_mobile(self.mobile_path.get())
    
    def _auto_refresh_device(self):
        self._update_device_info()
        self.root.after(5000, self._auto_refresh_device)
    
    def _update_device_info(self):
        theme = get_theme()
        
        if not self.adb.is_available():
            self.device_status.config(text="❌ ADB Not Found", fg=theme['error'])
            return
        
        connected, device_id, message = self.adb.check_connection()
        
        if connected:
            # Device info
            info = self.adb.get_device_info()
            self.device_status.config(
                text=f"✅ {info.get('brand', '')} {info.get('model', '')}",
                fg=theme['success'])
            self.device_details.config(
                text=f"Android {info.get('android', '')} | SDK {info.get('sdk', '')}")
            
            # Battery
            battery = self.adb.get_battery_info()
            if battery:
                level = battery.get('level', '--')
                self.battery_label.config(text=f"{level}%")
                
                # Color based on level
                try:
                    lvl = int(level)
                    if lvl <= 20:
                        self.battery_label.config(fg=theme['error'])
                    elif lvl <= 50:
                        self.battery_label.config(fg=theme['warning'])
                    else:
                        self.battery_label.config(fg=theme['success'])
                except:
                    pass
                
                status = battery.get('status', '')
                if '2' in status or 'Charging' in status:
                    self.charging_label.config(text="⚡ Charging")
                elif '5' in status or 'Full' in status:
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
            if network:
                self.network_label.config(text=network.get('wifi_ssid', 'Not connected'))
                self.ip_label.config(text=network.get('ip', ''))
            
            # Device time
            device_time = self.adb.get_device_time()
            self.device_time.config(text=device_time)
            
            uptime = self.adb.get_uptime()
            self.uptime_label.config(text=f"Up: {uptime[:30]}")
            
            # Auto load mobile if not loaded
            if not self.mobile_items:
                self._browse_mobile("/sdcard")
        else:
            self.device_status.config(text=f"❌ {message}", fg=theme['error'])
            self.device_details.config(text="Connect USB & enable debugging")
            self.battery_label.config(text="---%", fg=theme['text_dim'])
            self.storage_label.config(text="---")
    
    def _browse_pc(self, path):
        theme = get_theme()
        
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
            items = []
            
            for entry in path.iterdir():
                try:
                    is_dir = entry.is_dir()
                    size = "-" if is_dir else format_size(entry.stat().st_size)
                    icon = self._get_icon(entry.name, is_dir)
                    file_type = "Folder" if is_dir else self._get_type(entry.suffix)
                    
                    items.append({
                        'name': entry.name,
                        'display': f"{icon} {entry.name}",
                        'size': size,
                        'type': file_type,
                        'is_dir': is_dir,
                        'path': str(entry)
                    })
                except:
                    continue
            
            items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
            self.pc_items = items
            
            for item in items:
                self.pc_tree.insert('', END, values=(item['display'], item['size'], item['type']))
            
            self.pc_count.config(text=f"{len(items)} items")
            self.status.set(f"PC: {path}")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _browse_mobile(self, path):
        theme = get_theme()
        
        connected, _, _ = self.adb.check_connection()
        if not connected:
            for item in self.mobile_tree.get_children():
                self.mobile_tree.delete(item)
            
            self.mobile_tree.insert('', END, values=("❌ Not connected", "", ""))
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
        theme = get_theme()
        menu = Menu(self.root, tearoff=0, bg=theme['bg_secondary'], fg=theme['text'])
        menu.add_command(label="📤 Send (Encrypted)", command=self._transfer_pc_to_mobile)
        menu.add_command(label="📤 Send (Direct)", command=self._direct_pc_to_mobile)
        menu.add_separator()
        menu.add_command(label="📁 New Folder", command=self._new_folder_pc)
        menu.add_command(label="🗑️ Delete", command=self._delete_pc)
        menu.add_separator()
        menu.add_command(label="🔄 Refresh", command=lambda: self._browse_pc(self.pc_path.get()))
        menu.tk_popup(event.x_root, event.y_root)
    
    def _mobile_context(self, event):
        theme = get_theme()
        menu = Menu(self.root, tearoff=0, bg=theme['bg_secondary'], fg=theme['text'])
        menu.add_command(label="📥 Get (Encrypted)", command=self._transfer_mobile_to_pc)
        menu.add_command(label="📥 Get (Direct)", command=self._direct_mobile_to_pc)
        menu.add_separator()
        menu.add_command(label="📁 New Folder", command=self._new_folder_mobile)
        menu.add_command(label="🗑️ Delete", command=self._delete_mobile)
        menu.add_separator()
        menu.add_command(label="🔄 Refresh", command=lambda: self._browse_mobile(self.mobile_path.get()))
        menu.tk_popup(event.x_root, event.y_root)
    
    # ══════════════════════════════════════════════════════════════════════════════════════
    #                                    TRANSFERS
    # ══════════════════════════════════════════════════════════════════════════════════════
    
    def _validate_password(self):
        pwd = self.password.get()
        if len(pwd) < 10:
            messagebox.showerror("Password", f"Min 10 characters!\nCurrent: {len(pwd)}")
            self.pwd_entry.focus()
            return False
        return True
    
    def _get_selected_pc(self):
        return [self.pc_items[self.pc_tree.index(s)] for s in self.pc_tree.selection() 
                if self.pc_tree.index(s) < len(self.pc_items)]
    
    def _get_selected_mobile(self):
        return [self.mobile_items[self.mobile_tree.index(s)] for s in self.mobile_tree.selection() 
                if self.mobile_tree.index(s) < len(self.mobile_items)]
    
    def _transfer_pc_to_mobile(self):
        if not self._validate_password():
            return
        
        connected, _, _ = self.adb.check_connection()
        if not connected:
            messagebox.showerror("Error", "Not connected!")
            return
        
        selected = self._get_selected_pc()
        if not selected:
            messagebox.showwarning("Warning", "Select files!")
            return
        
        password = self.password.get()
        dest = self.mobile_path.get()
        
        def transfer():
            try:
                self.progress.start()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                zip_path = Config.TEMP_DIR / f"t_{timestamp}.zip"
                enc_path = Config.TEMP_DIR / f"t_{timestamp}.secbak"
                
                self.status.set("📦 Compressing...")
                self.root.update()
                
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for item in selected:
                        path = Path(item['path'])
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
                    raise Exception(msg)
                
                self.status.set("📤 Sending...")
                self.root.update()
                
                remote = f"{dest.rstrip('/')}/backup_{timestamp}.secbak"
                success, _, stderr = self.adb.push(enc_path, remote)
                if not success:
                    raise Exception(stderr)
                
                zip_path.unlink(missing_ok=True)
                shutil.copy(enc_path, Config.BACKUP_DIR / f"backup_{timestamp}.secbak")
                enc_path.unlink(missing_ok=True)
                
                self.status.set("✅ Done!")
                self.root.after(0, lambda: messagebox.showinfo("Success!", f"Sent to: {remote}"))
                self.root.after(0, lambda: self._browse_mobile(dest))
                
            except Exception as e:
                self.status.set(f"❌ {e}")
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.progress.stop()
        
        threading.Thread(target=transfer, daemon=True).start()
    
    def _transfer_mobile_to_pc(self):
        if not self._validate_password():
            return
        
        selected = self._get_selected_mobile()
        if not selected:
            messagebox.showwarning("Warning", "Select files!")
            return
        
        dest = filedialog.askdirectory(title="Save to")
        if not dest:
            return
        
        password = self.password.get()
        
        def transfer():
            try:
                self.progress.start()
                
                for item in selected:
                    name = safe_str(item.get('name', ''))
                    remote = safe_str(item.get('full_path', ''))
                    
                    self.status.set(f"📥 {name}")
                    self.root.update()
                    
                    if name.endswith('.secbak'):
                        local_enc = Config.TEMP_DIR / name
                        success, _, _ = self.adb.pull(remote, local_enc)
                        
                        self.status.set("🔓 Decrypting...")
                        local_zip = Config.TEMP_DIR / name.replace('.secbak', '.zip')
                        success, result = Encryptor.decrypt(local_enc, local_zip, password)
                        
                        if not success:
                            raise Exception(result)
                        
                        with zipfile.ZipFile(local_zip, 'r') as zf:
                            zf.extractall(dest)
                        
                        local_enc.unlink(missing_ok=True)
                        local_zip.unlink(missing_ok=True)
                    else:
                        self.adb.pull(remote, Path(dest) / name)
                
                self.status.set("✅ Done!")
                self.root.after(0, lambda: messagebox.showinfo("Success!", f"Saved to: {dest}"))
                self.root.after(0, lambda: self._browse_pc(dest))
                
            except Exception as e:
                self.status.set(f"❌ {e}")
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.progress.stop()
        
        threading.Thread(target=transfer, daemon=True).start()
    
    def _direct_pc_to_mobile(self):
        selected = self._get_selected_pc()
        if not selected:
            return
        
        dest = self.mobile_path.get()
        
        def transfer():
            self.progress.start()
            for item in selected:
                self.status.set(f"📤 {item['name']}")
                self.adb.push(item['path'], f"{dest.rstrip('/')}/{item['name']}")
            self.status.set("✅ Done!")
            self.progress.stop()
            self.root.after(0, lambda: self._browse_mobile(dest))
        
        threading.Thread(target=transfer, daemon=True).start()
    
    def _direct_mobile_to_pc(self):
        selected = self._get_selected_mobile()
        if not selected:
            return
        
        dest = self.pc_path.get()
        
        def transfer():
            self.progress.start()
            for item in selected:
                self.status.set(f"📥 {item['name']}")
                self.adb.pull(item['full_path'], Path(dest) / item['name'])
            self.status.set("✅ Done!")
            self.progress.stop()
            self.root.after(0, lambda: self._browse_pc(dest))
        
        threading.Thread(target=transfer, daemon=True).start()
    
    # ══════════════════════════════════════════════════════════════════════════════════════
    #                                    TOOLS
    # ══════════════════════════════════════════════════════════════════════════════════════
    
    def _take_screenshot(self):
        self.status.set("📸 Taking screenshot...")
        self.progress.start()
        
        def capture():
            success, path = self.adb.take_screenshot()
            self.progress.stop()
            
            if success:
                self.status.set(f"✅ Saved: {path}")
                self.root.after(0, lambda: messagebox.showinfo("Screenshot", f"Saved to:\n{path}"))
            else:
                self.status.set("❌ Failed")
                self.root.after(0, lambda: messagebox.showerror("Error", path))
        
        threading.Thread(target=capture, daemon=True).start()
    
    def _screen_record(self):
        if messagebox.askyesno("Screen Record", "Start recording? (Max 3 min)"):
            self.adb.start_screen_record(180)
            self.status.set("🎬 Recording... (Click again to stop)")
    
    def _start_scrcpy(self):
        if Config.SCRCPY_PATH.exists():
            subprocess.Popen([str(Config.SCRCPY_PATH)], 
                           creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            self.status.set("📺 Screen mirror started")
        else:
            messagebox.showinfo("scrcpy", 
                f"scrcpy not found!\n\nDownload from:\n"
                f"https://github.com/Genymobile/scrcpy/releases\n\n"
                f"Extract to:\n{Config.SCRIPT_DIR / 'scrcpy'}")
    
    def _show_device_info(self):
        info = self.adb.get_device_info()
        cpu = self.adb.get_cpu_info()
        mem = self.adb.get_memory_info()
        screen = self.adb.get_screen_info()
        
        msg = f"📱 DEVICE INFO\n{'='*40}\n\n"
        msg += f"Brand: {info.get('brand', 'N/A')}\n"
        msg += f"Model: {info.get('model', 'N/A')}\n"
        msg += f"Device: {info.get('device', 'N/A')}\n"
        msg += f"Android: {info.get('android', 'N/A')}\n"
        msg += f"SDK: {info.get('sdk', 'N/A')}\n"
        msg += f"Build: {info.get('build_id', 'N/A')}\n"
        msg += f"Security: {info.get('security_patch', 'N/A')}\n"
        msg += f"\n💻 HARDWARE\n{'='*40}\n\n"
        
        if cpu:
            msg += f"CPU Cores: {cpu.get('cores', 'N/A')}\n"
            msg += f"Hardware: {cpu.get('hardware', 'N/A')}\n"
        
        if mem:
            msg += f"RAM: {mem.get('total', 'N/A')}\n"
            msg += f"Available: {mem.get('available', 'N/A')}\n"
        
        if screen:
            msg += f"Screen: {screen.get('width')}x{screen.get('height')}\n"
        
        messagebox.showinfo("Device Info", msg)
    
    def _show_battery_info(self):
        battery = self.adb.get_battery_info()
        if not battery:
            messagebox.showerror("Error", "Cannot get battery info")
            return
        
        msg = f"🔋 BATTERY INFO\n{'='*40}\n\n"
        for key, value in battery.items():
            msg += f"{key}: {value}\n"
        
        messagebox.showinfo("Battery", msg)
    
    def _show_storage_info(self):
        storage = self.adb.get_storage_info()
        if not storage:
            messagebox.showerror("Error", "Cannot get storage info")
            return
        
        messagebox.showinfo("Storage",
            f"💾 STORAGE\n{'='*30}\n\n"
            f"Total: {storage.get('total', 'N/A')}\n"
            f"Used: {storage.get('used', 'N/A')}\n"
            f"Free: {storage.get('free', 'N/A')}\n"
            f"Usage: {storage.get('percent', 'N/A')}")
    
    def _show_apps(self):
        theme = get_theme()
        
        win = Toplevel(self.root)
        win.title("📱 Installed Apps")
        win.geometry("600x500")
        win.configure(bg=theme['bg_primary'])
        
        # Header
        Label(win, text="📱 Installed Apps", font=("Segoe UI", 14, "bold"),
              bg=theme['bg_primary'], fg=theme['text']).pack(pady=10)
        
        # List
        frame = Frame(win, bg=theme['bg_primary'])
        frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        scroll = Scrollbar(frame)
        scroll.pack(side=RIGHT, fill=Y)
        
        listbox = Listbox(frame, font=("Consolas", 10),
                         bg=theme['bg_secondary'], fg=theme['text'],
                         selectbackground=theme['accent'],
                         yscrollcommand=scroll.set)
        listbox.pack(fill=BOTH, expand=True)
        scroll.config(command=listbox.yview)
        
        # Load apps
        def load():
            apps = self.adb.get_installed_apps()
            for app in apps:
                listbox.insert(END, app)
        
        threading.Thread(target=load, daemon=True).start()
        
        # Buttons
        btn_frame = Frame(win, bg=theme['bg_primary'])
        btn_frame.pack(fill=X, padx=10, pady=10)
        
        def open_app():
            sel = listbox.curselection()
            if sel:
                self.adb.open_app(listbox.get(sel[0]))
        
        def uninstall():
            sel = listbox.curselection()
            if sel:
                pkg = listbox.get(sel[0])
                if messagebox.askyesno("Uninstall", f"Uninstall {pkg}?"):
                    self.adb.uninstall_app(pkg)
                    listbox.delete(sel[0])
        
        Button(btn_frame, text="▶️ Open", command=open_app,
               bg=theme['success'], fg='white', relief=FLAT).pack(side=LEFT, padx=5)
        Button(btn_frame, text="🗑️ Uninstall", command=uninstall,
               bg=theme['error'], fg='white', relief=FLAT).pack(side=LEFT, padx=5)
    
    def _show_contacts(self):
        theme = get_theme()
        
        win = Toplevel(self.root)
        win.title("📇 Contacts")
        win.geometry("500x400")
        win.configure(bg=theme['bg_primary'])
        
        Label(win, text="📇 Contacts", font=("Segoe UI", 14, "bold"),
              bg=theme['bg_primary'], fg=theme['text']).pack(pady=10)
        
        text = Text(win, font=("Consolas", 10),
                   bg=theme['bg_secondary'], fg=theme['text'], wrap=WORD)
        text.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        contacts = self.adb.get_contacts()
        for c in contacts:
            text.insert(END, f"{c['name']}: {c['number']}\n")
        
        text.config(state=DISABLED)
    
    def _show_sms(self):
        theme = get_theme()
        
        win = Toplevel(self.root)
        win.title("💬 SMS")
        win.geometry("600x500")
        win.configure(bg=theme['bg_primary'])
        
        Label(win, text="💬 SMS Messages", font=("Segoe UI", 14, "bold"),
              bg=theme['bg_primary'], fg=theme['text']).pack(pady=10)
        
        text = Text(win, font=("Consolas", 10),
                   bg=theme['bg_secondary'], fg=theme['text'], wrap=WORD)
        text.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        messages = self.adb.get_sms()
        for m in messages:
            text.insert(END, f"From: {m['address']}\n{m['body']}\n\n")
        
        text.config(state=DISABLED)
    
    def _show_terminal(self):
        theme = get_theme()
        
        win = Toplevel(self.root)
        win.title("💻 ADB Shell")
        win.geometry("800x500")
        win.configure(bg=theme['bg_primary'])
        
        # Output
        output = Text(win, font=("Consolas", 10),
                     bg='black', fg='#00ff00', wrap=WORD)
        output.pack(fill=BOTH, expand=True, padx=10, pady=10)
        output.insert(END, "ADB Shell Terminal\nType commands below:\n\n")
        
        # Input
        input_frame = Frame(win, bg=theme['bg_primary'])
        input_frame.pack(fill=X, padx=10, pady=5)
        
        Label(input_frame, text="$", font=("Consolas", 12),
              bg=theme['bg_primary'], fg='#00ff00').pack(side=LEFT)
        
        cmd_var = StringVar()
        entry = Entry(input_frame, textvariable=cmd_var, font=("Consolas", 12),
                     bg='black', fg='#00ff00', insertbackground='#00ff00', relief=FLAT)
        entry.pack(side=LEFT, fill=X, expand=True, padx=5, ipady=5)
        
        def run_cmd(event=None):
            cmd = cmd_var.get()
            if cmd:
                output.insert(END, f"$ {cmd}\n")
                success, stdout, stderr = self.adb.shell(cmd)
                output.insert(END, stdout + stderr + "\n")
                output.see(END)
                cmd_var.set("")
        
        entry.bind('<Return>', run_cmd)
        entry.focus()
    
    def _reboot(self, mode):
        if messagebox.askyesno("Reboot", f"Reboot device ({mode})?"):
            self.adb.reboot(mode)
    
    def _new_folder(self):
        # Check focus
        if self.root.focus_get() == self.mobile_tree:
            self._new_folder_mobile()
        else:
            self._new_folder_pc()
    
    def _new_folder_pc(self):
        name = simpledialog.askstring("New Folder", "Name:")
        if name:
            path = Path(self.pc_path.get()) / name
            path.mkdir(exist_ok=True)
            self._browse_pc(self.pc_path.get())
    
    def _new_folder_mobile(self):
        name = simpledialog.askstring("New Folder", "Name:")
        if name:
            path = f"{self.mobile_path.get().rstrip('/')}/{name}"
            self.adb.mkdir(path)
            self._browse_mobile(self.mobile_path.get())
    
    def _delete_selected(self):
        pc = self._get_selected_pc()
        mobile = self._get_selected_mobile()
        
        if pc:
            self._delete_pc()
        elif mobile:
            self._delete_mobile()
    
    def _delete_pc(self):
        selected = self._get_selected_pc()
        if selected and messagebox.askyesno("Delete", f"Delete {len(selected)} items?"):
            for item in selected:
                path = Path(item['path'])
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            self._browse_pc(self.pc_path.get())
    
    def _delete_mobile(self):
        selected = self._get_selected_mobile()
        if selected and messagebox.askyesno("Delete", f"Delete {len(selected)} items?"):
            for item in selected:
                self.adb.remove(item['full_path'])
            self._browse_mobile(self.mobile_path.get())
    
    def _search(self, event=None):
        query = self.search_var.get().lower()
        if not query:
            return
        
        # Search in current lists
        for i, item in enumerate(self.pc_items):
            if query in item['name'].lower():
                self.pc_tree.selection_set(self.pc_tree.get_children()[i])
                self.pc_tree.see(self.pc_tree.get_children()[i])
                break
        
        for i, item in enumerate(self.mobile_items):
            if query in item.get('name', '').lower():
                self.mobile_tree.selection_set(self.mobile_tree.get_children()[i])
                self.mobile_tree.see(self.mobile_tree.get_children()[i])
                break
    
    def _toggle_pwd(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "●")
    
    def _check_password(self, *args):
        theme = get_theme()
        pwd = self.password.get()
        length = len(pwd)
        
        if length == 0:
            self.pwd_strength.config(text="", fg=theme['text_dim'])
        elif length < 10:
            self.pwd_strength.config(text=f"❌ {length}/10", fg=theme['error'])
        elif length < 14:
            self.pwd_strength.config(text=f"✅ Good", fg=theme['success'])
        else:
            self.pwd_strength.config(text=f"💪 Strong", fg=theme['success'])
    
    def _change_theme(self, theme_name):
        Config.CURRENT_THEME = theme_name
        messagebox.showinfo("Theme", f"Theme changed to {theme_name}!\nRestart app to apply.")
    
    def _show_settings(self):
        messagebox.showinfo("Settings", "Settings coming soon!")
    
    def _show_guide(self):
        webbrowser.open("https://developer.android.com/studio/command-line/adb")
    
    def _show_about(self):
        messagebox.showinfo("About",
            "🚀 Ultimate Mobile Manager v5.0\n\n"
            "All-in-One Mobile Management Tool\n\n"
            "Features:\n"
            "• Dual File Browser\n"
            "• AES-256 Encryption\n"
            "• Screen Mirror/Record\n"
            "• App Management\n"
            "• Contacts/SMS Backup\n"
            "• And much more!")
    
    def _get_icon(self, name, is_dir, is_link=False):
        if is_link:
            return "🔗"
        if is_dir:
            icons = {
                'dcim': '📷', 'download': '📥', 'music': '🎵',
                'pictures': '🖼️', 'movies': '🎬', 'documents': '📝',
                'whatsapp': '💬', 'android': '🤖', 'camera': '📷'
            }
            return icons.get(name.lower(), '📁')
        
        ext = Path(name).suffix.lower()
        icons = {
            '.jpg': '🖼️', '.png': '🖼️', '.gif': '🖼️',
            '.mp4': '🎬', '.mkv': '🎬', '.avi': '🎬',
            '.mp3': '🎵', '.wav': '🎵', '.flac': '🎵',
            '.pdf': '📕', '.doc': '📝', '.txt': '📄',
            '.zip': '📦', '.rar': '📦', '.apk': '📱',
            '.secbak': '🔐'
        }
        return icons.get(ext, '📄')
    
    def _get_type(self, suffix):
        types = {
            '.jpg': 'Image', '.png': 'Image', '.gif': 'Image',
            '.mp4': 'Video', '.mkv': 'Video', '.avi': 'Video',
            '.mp3': 'Audio', '.wav': 'Audio',
            '.pdf': 'PDF', '.doc': 'Doc', '.txt': 'Text',
            '.zip': 'Archive', '.apk': 'App', '.secbak': 'Encrypted'
        }
        return types.get(suffix.lower(), 'File')
    
    def run(self):
        self.root.mainloop()


# ══════════════════════════════════════════════════════════════════════════════════════
#                                    MAIN
# ══════════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  Ultimate Mobile Manager v5.0")
    print("=" * 60)
    
    app = UltimateFileBrowser()
    app.run()