<div align="center">

# 🚀 Ultimate Mobile Manager

### Professional Android Device Management Solution

![Version](https://img.shields.io/badge/Version-5.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)
![ADB](https://img.shields.io/badge/ADB-Platform--Tools-brightgreen?style=for-the-badge&logo=android)
![Encryption](https://img.shields.io/badge/Encryption-AES--256-red?style=for-the-badge&logo=shield)

<br>

**A powerful all-in-one Android device management tool with secure file transfer,**  
**AES-256 encryption, screen mirroring, app management, and much more.**

<br>

[📖 Documentation](#-documentation) •
[⚡ Quick Start](#-quick-start) •
[✨ Features](#-features) •
[📥 Installation](#-installation) •
[🔧 Troubleshooting](#-troubleshooting)

<br>

---

<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/rainbow.png" alt="line" width="100%">

</div>

<br>

## 📋 Table of Contents

<details>
<summary>Click to expand</summary>

- [About The Project](#-about-the-project)
- [Features](#-features)
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [Mobile Setup](#-mobile-setup)
- [Usage Guide](#-usage-guide)
  - [File Transfer](#file-transfer)
  - [Screen Mirroring](#screen-mirroring)
  - [App Management](#app-management)
  - [Backup & Restore](#backup--restore)
- [Keyboard Shortcuts](#-keyboard-shortcuts)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

</details>

<br>

---

## 🎯 About The Project

**Ultimate Mobile Manager** is a comprehensive desktop application designed to streamline Android device management. Built with Python and leveraging the power of ADB (Android Debug Bridge), it provides a seamless interface for file transfers, device monitoring, and advanced operations.

### 🏆 Why Choose Ultimate Mobile Manager?

| Advantage | Description |
|:----------|:------------|
| 🔐 **Security First** | Military-grade AES-256-GCM encryption for all file transfers |
| 🚀 **Performance** | Optimized for speed with USB 3.0 support |
| 🎨 **User Friendly** | Intuitive dual-panel interface with drag-and-drop support |
| 📱 **Universal** | Compatible with all Android devices (5.0+) |
| 💯 **Free & Open Source** | No ads, no tracking, no hidden costs |

<br>

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 📁 File Management
- ✅ Dual-panel file browser (PC & Mobile)
- ✅ Drag-and-drop file transfer
- ✅ Multi-file selection support
- ✅ Quick navigation shortcuts
- ✅ Real-time file synchronization

</td>
<td width="50%">

### 🔐 Security
- ✅ AES-256-GCM encryption
- ✅ PBKDF2 key derivation (100K iterations)
- ✅ SHA-256 integrity verification
- ✅ Zero-knowledge architecture
- ✅ No password storage

</td>
</tr>
<tr>
<td width="50%">

### 📺 Screen Features
- ✅ Real-time screen mirroring (scrcpy)
- ✅ One-click screenshot capture
- ✅ Screen recording (up to 3 min)
- ✅ Keyboard & mouse control
- ✅ Clipboard synchronization

</td>
<td width="50%">

### 📱 Device Management
- ✅ App manager (install/uninstall)
- ✅ Live battery monitoring
- ✅ Storage space analysis
- ✅ Network information
- ✅ ADB terminal access

</td>
</tr>
</table>

<br>

### 📊 Feature Comparison

| Feature | Free Tools | Ultimate Mobile Manager |
|:--------|:----------:|:-----------------------:|
| File Transfer | ✅ | ✅ |
| Encrypted Transfer | ❌ | ✅ |
| Screen Mirroring | ❌ | ✅ |
| App Management | ❌ | ✅ |
| Dual File Browser | ❌ | ✅ |
| Battery Monitoring | ❌ | ✅ |
| Multiple Themes | ❌ | ✅ |
| No Ads | ❌ | ✅ |

<br>

---

## 💻 System Requirements

### Minimum Requirements

| Component | Requirement |
|:----------|:------------|
| **Operating System** | Windows 10 (64-bit) |
| **Python** | 3.8 or higher |
| **RAM** | 4 GB |
| **Storage** | 500 MB available |
| **USB** | USB 2.0 port |
| **Android** | 5.0 (Lollipop) or higher |

### Recommended Specifications

| Component | Recommendation |
|:----------|:---------------|
| **Operating System** | Windows 11 (64-bit) |
| **Python** | 3.10 or higher |
| **RAM** | 8 GB or more |
| **Storage** | 1 GB available |
| **USB** | USB 3.0 port (10x faster) |
| **Android** | 8.0 (Oreo) or higher |

<br>

---

## 📥 Installation

### Prerequisites

Before installation, download and install:

| Software | Download Link | Purpose |
|:---------|:--------------|:--------|
| **Python 3.8+** | [python.org](https://www.python.org/downloads/) | Runtime environment |
| **ADB Platform Tools** | [Android Developers](https://developer.android.com/studio/releases/platform-tools) | Device communication |
| **scrcpy** *(optional)* | [GitHub Releases](https://github.com/Genymobile/scrcpy/releases) | Screen mirroring |

<br>

### Step-by-Step Installation

#### 1️⃣ Install Python

```bash
# Download from python.org and run installer
# ⚠️ IMPORTANT: Check "Add Python to PATH" during installation!

# Verify installation
python --version
```

#### 2️⃣ Create Project Structure

```
📁 UltimateMobileManager/
│
├── 📄 main.py                      # Main application
│
├── 📁 platform-tools/              # ADB tools (Required)
│   ├── adb.exe
│   ├── AdbWinApi.dll
│   ├── AdbWinUsbApi.dll
│   └── fastboot.exe
│
├── 📁 scrcpy/                      # Screen mirror (Optional)
│   ├── scrcpy.exe
│   ├── scrcpy-server
│   └── ...
│
├── 📁 backups/                     # Auto-created
├── 📁 screenshots/                 # Auto-created
├── 📁 temp/                        # Auto-created
└── 📁 logs/                        # Auto-created
```

#### 3️⃣ Install Dependencies

```bash
# Navigate to project directory
cd UltimateMobileManager

# Install required packages
pip install cryptography pillow

# Or use requirements.txt
pip install -r requirements.txt
```

<details>
<summary>📄 requirements.txt</summary>

```txt
cryptography>=41.0.0
pillow>=10.0.0
```

</details>

#### 4️⃣ Setup ADB Platform Tools

```bash
# 1. Download platform-tools from Android Developers website
# 2. Extract the ZIP file
# 3. Copy 'platform-tools' folder to project directory
# 4. Verify installation:

cd platform-tools
adb version
```

#### 5️⃣ Launch Application

```bash
# Method 1: Double-click main.py

# Method 2: Command line
python main.py

# Method 3: Debug mode
python -u main.py
```

<br>

---

## 📱 Mobile Setup

### Enable USB Debugging

<table>
<tr>
<td width="33%" align="center">

**Step 1**

🔧 **Developer Options**

```
Settings
  └── About Phone
      └── Build Number
          (Tap 7 times)
```

</td>
<td width="33%" align="center">

**Step 2**

🐛 **USB Debugging**

```
Settings
  └── Developer Options
      └── USB Debugging
          → Enable ✅
```

</td>
<td width="33%" align="center">

**Step 3**

🔌 **Connect & Allow**

```
Connect USB
  └── Select "File Transfer"
      └── Allow USB Debugging
          → OK ✅
```

</td>
</tr>
</table>

<br>

### Brand-Specific Instructions

<details>
<summary>📱 <b>Samsung</b></summary>

```
Settings → About Phone → Software Information → Build Number (tap 7x)
Settings → Developer Options → USB Debugging → ON
```

</details>

<details>
<summary>📱 <b>Xiaomi / Redmi / POCO</b></summary>

```
Settings → About Phone → MIUI Version (tap 7x)
Settings → Additional Settings → Developer Options:
  ✅ USB Debugging → ON
  ✅ USB Debugging (Security Settings) → ON
  ✅ Install via USB → ON
```

</details>

<details>
<summary>📱 <b>OnePlus</b></summary>

```
Settings → About Phone → Build Number (tap 7x)
Settings → System → Developer Options → USB Debugging → ON
```

</details>

<details>
<summary>📱 <b>Realme / OPPO / Vivo</b></summary>

```
Settings → About Phone → Version/Build Number (tap 7x)
Settings → Additional Settings → Developer Options:
  ✅ USB Debugging → ON
  ✅ Disable Permission Monitoring → ON (if available)
```

</details>

<details>
<summary>📱 <b>Motorola / Stock Android</b></summary>

```
Settings → About Phone → Build Number (tap 7x)
Settings → System → Developer Options → USB Debugging → ON
```

</details>

<br>

---

## 📖 Usage Guide

### Interface Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  🚀 Ultimate Mobile Manager v5.0              [📸] [📺] [⚙️]       │
├─────────────────────────────────────────────────────────────────────┤
│  📱 Device: Samsung M31  │  🔋 85%  │  💾 32GB Free  │  📶 WiFi    │
├─────────────────────────────────────────────────────────────────────┤
│  🔑 Password: [••••••••••]  [Show]     Strength: ✅ Strong         │
├────────────────────┬────────────┬───────────────────────────────────┤
│                    │            │                                   │
│   💻 PC FILES      │  ACTIONS   │   📱 MOBILE FILES                 │
│   ──────────────   │            │   ────────────────                │
│   📁 Documents     │  ▶▶ Send   │   📁 DCIM                         │
│   📁 Downloads     │  ◀◀ Get    │   📁 Download                     │
│   📁 Pictures      │  ────────  │   📁 Pictures                     │
│   📁 Videos        │  → Copy    │   📁 WhatsApp                     │
│   📄 file.txt      │  ← Copy    │   📄 photo.jpg                    │
│                    │  🗑️ Delete │                                   │
├────────────────────┴────────────┴───────────────────────────────────┤
│  ✅ Ready                              🔐 AES-256-GCM Encryption    │
└─────────────────────────────────────────────────────────────────────┘
```

<br>

### File Transfer

#### 🔐 Encrypted Transfer (Recommended)

| Direction | Steps |
|:----------|:------|
| **PC → Mobile** | Select files → Enter password (10+ chars) → Click `▶▶ Encrypt` |
| **Mobile → PC** | Select `.secbak` file → Enter same password → Click `◀◀ Decrypt` |

#### 📋 Direct Transfer (No Encryption)

| Direction | Steps |
|:----------|:------|
| **PC → Mobile** | Select files → Click `→ Copy` |
| **Mobile → PC** | Select files → Click `← Copy` |

<br>

#### ⏱️ Transfer Speed Reference

| File Size | USB 2.0 | USB 3.0 |
|:----------|:-------:|:-------:|
| 10 MB | ~5 sec | ~2 sec |
| 100 MB | ~30 sec | ~10 sec |
| 500 MB | ~2 min | ~45 sec |
| 1 GB | ~5 min | ~1.5 min |
| 5 GB | ~25 min | ~8 min |

<br>

### Screen Mirroring

#### scrcpy Keyboard Shortcuts

| Shortcut | Action |
|:---------|:-------|
| `Ctrl + H` | Home button |
| `Ctrl + B` | Back button |
| `Ctrl + S` | Recent apps |
| `Ctrl + ↑/↓` | Volume Up/Down |
| `Ctrl + P` | Power button |
| `Ctrl + R` | Rotate screen |
| `Ctrl + N` | Notification panel |
| `Ctrl + C/V` | Copy/Paste clipboard |
| `Right Click` | Back |
| `Drag & Drop` | Install APK |

<br>

### App Management

| Action | Description |
|:-------|:------------|
| ▶️ **Open** | Launch the selected app |
| 🗑️ **Uninstall** | Remove app from device |
| ❌ **Force Stop** | Stop running application |
| 🧹 **Clear Data** | Erase all app data |

<br>

### Backup & Restore

#### 📁 Important Folders to Backup

| Folder | Content |
|:-------|:--------|
| `/sdcard/DCIM/` | Camera photos & videos |
| `/sdcard/Download/` | Downloaded files |
| `/sdcard/Pictures/` | Screenshots, saved images |
| `/sdcard/WhatsApp/` | WhatsApp media & chats |
| `/sdcard/Documents/` | Documents |
| `/sdcard/Music/` | Music files |

<br>

---

## ⌨️ Keyboard Shortcuts

### Global Shortcuts

| Shortcut | Action |
|:---------|:-------|
| `F5` | Refresh all panels |
| `Ctrl + R` | Refresh all panels |
| `F11` | Toggle fullscreen |
| `Escape` | Exit fullscreen |

### File Browser

| Shortcut | Action |
|:---------|:-------|
| `Enter` | Open selected folder |
| `Backspace` | Go to parent folder |
| `Ctrl + Click` | Multi-select items |
| `Shift + Click` | Select range |
| `Delete` | Delete selected |

<br>

---

## 🔧 Troubleshooting

<details>
<summary>❌ <b>"ADB Not Found" Error</b></summary>

### Cause
ADB executable not in correct location.

### Solution
1. Download platform-tools from [Android Developers](https://developer.android.com/studio/releases/platform-tools)
2. Extract ZIP file
3. Copy `platform-tools` folder to project directory
4. Verify `adb.exe` exists in the folder
5. Restart application

</details>

<details>
<summary>❌ <b>"No Device Connected" Error</b></summary>

### Possible Causes & Solutions

| Cause | Solution |
|:------|:---------|
| Bad USB cable | Use original manufacturer cable |
| Wrong USB port | Try USB 3.0 port (blue color) |
| USB Debugging disabled | Enable in Developer Options |
| Not authorized | Accept prompt on phone |
| Wrong USB mode | Select "File Transfer" mode |

### Reset ADB Connection
```bash
adb kill-server
adb start-server
adb devices
```

</details>

<details>
<summary>❌ <b>"Unauthorized" Device Error</b></summary>

### Solution
1. Look at your phone screen
2. Accept "Allow USB debugging?" popup
3. Check "Always allow from this computer"
4. Tap "OK"

### If no popup appears:
1. Disconnect USB
2. Go to Developer Options
3. Revoke USB debugging authorizations
4. Reconnect USB cable

</details>

<details>
<summary>❌ <b>"Wrong Password" Error</b></summary>

### Important Notes
- Passwords are **CASE-SENSITIVE**
- `Password123` ≠ `password123`

### Check for:
- Caps Lock / Num Lock status
- Extra spaces before/after password
- Use "Show" checkbox to verify

### ⚠️ Warning
If password is forgotten, encrypted files **CANNOT** be recovered. This is a security feature.

</details>

<details>
<summary>❌ <b>"scrcpy Not Working" Error</b></summary>

### Solution
1. Verify scrcpy folder exists with `scrcpy.exe`
2. Test manually:
   ```bash
   cd scrcpy
   scrcpy.exe
   ```
3. Ensure USB debugging is enabled
4. Keep phone screen unlocked
5. Download latest version from [GitHub](https://github.com/Genymobile/scrcpy/releases)

</details>

<br>

---

## ❓ FAQ

<details>
<summary><b>Is my password stored anywhere?</b></summary>

**No.** Your password is never stored. It's used only during encryption/decryption and immediately discarded. Lost password = Lost encrypted files. This is by design for maximum security.

</details>

<details>
<summary><b>How secure is the encryption?</b></summary>

**Military-grade security:**
- 🔐 AES-256-GCM encryption (same as banks)
- 🔑 PBKDF2 with 100,000 iterations
- ✅ SHA-256 integrity verification

Brute-forcing a 10-character password would take millions of years.

</details>

<details>
<summary><b>Does this work with iPhone?</b></summary>

**No.** This tool uses ADB (Android Debug Bridge) which only works with Android devices. iOS uses a completely different ecosystem.

</details>

<details>
<summary><b>Which Android versions are supported?</b></summary>

| Support Level | Android Version |
|:--------------|:----------------|
| Minimum | Android 5.0 (Lollipop) |
| Recommended | Android 8.0+ (Oreo) |
| Tested up to | Android 14 |

</details>

<details>
<summary><b>Is this safe to use?</b></summary>

**Yes, completely safe:**
- ✅ Open source code
- ✅ No internet connection required
- ✅ No data collection or telemetry
- ✅ All processing done locally
- ✅ No ads or tracking

</details>

<details>
<summary><b>Can I backup WhatsApp chats?</b></summary>

**Partially:**
- ✅ Media files (photos, videos, voice notes)
- ✅ Database files (encrypted by WhatsApp)
- ❌ Cannot decrypt WhatsApp's encryption

For full chat restore, use WhatsApp's built-in Google Drive backup.

</details>

<br>

---

## 📜 Version History

| Version | Date | Changes |
|:--------|:-----|:--------|
| **5.0** | Jan 2024 | Full release with all features |
| **4.1** | Jan 2024 | Bug fixes, NoneType errors resolved |
| **4.0** | Jan 2024 | Added screen mirror, app manager |
| **3.0** | Dec 2023 | Dual file browser implementation |
| **2.0** | Dec 2023 | Added AES-256 encryption |
| **1.0** | Dec 2023 | Initial release, basic file transfer |

<br>

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** your feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

<br>

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Sudhir Kumar (@SudhirDevOps1)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

<br>

---

## 👨‍💻 Contact

<div align="center">

### Sudhir Kumar

[![GitHub](https://img.shields.io/badge/GitHub-@SudhirDevOps1-181717?style=for-the-badge&logo=github)](https://github.com/SudhirDevOps1)

<br>

### 🛠️ Built With

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Tkinter](https://img.shields.io/badge/Tkinter-GUI-blue?style=for-the-badge)
![ADB](https://img.shields.io/badge/ADB-Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-AES--256-red?style=for-the-badge)

<br>

---

### ⭐ Star this repository if you found it helpful!

<br>

**Made with ❤️ by Sudhir Kumar**

*© 2024 Ultimate Mobile Manager | Free & Open Source Software*

</div>
