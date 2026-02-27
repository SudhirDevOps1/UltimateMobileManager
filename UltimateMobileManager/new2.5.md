<div align="center">

# 🚀 Ultimate Mobile Manager

### Professional Android Device Management Solution

![Version](https://img.shields.io/badge/Version-5.1-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.14-green?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)
![ADB](https://img.shields.io/badge/ADB-Wireless-brightgreen?style=for-the-badge&logo=android)
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
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [Detailed Usage Guide (Kaise Use Kare)](#-detailed-usage-guide-kaise-use-kare)
  - [1. Connecting Your Device](#1-connecting-your-device)
  - [2. Wireless Connection](#2-wireless-connection-wi-fi)
  - [3. File Transfer & Management](#3-file-transfer--management)
  - [4. Secure Encrypted Transfer](#4-secure-encrypted-transfer)
  - [5. App Management](#5-app-management)
  - [6. Screen Mirroring](#6-screen-mirroring)
  - [7. Device Tools (Reboot/Screenshot)](#7-device-tools)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

</details>

<br>

---

## 🎯 About The Project

**Ultimate Mobile Manager** is a comprehensive desktop application designed to streamline Android device management. Built with Python 3.14+ and leveraging the power of ADB (Android Debug Bridge), it provides a seamless interface for file transfers, device monitoring, and advanced operations without the lag.

### Why Use This?

| Advantage | Description |
|:----------|:------------|
| 🔐 **Security First** | Military-grade **AES-256-GCM** encryption for all file transfers |
| 🚀 **Buttery Smooth** | **Multithreaded** architecture ensures zero lag and instant UI response |
| 🎨 **Modern UI** | Intuitive dual-panel interface with themes and drag-and-drop |
| 📡 **Wireless** | Connect to your device over **Wi-Fi** - no cables needed! |
| 📱 **Universal** | Compatible with all Android devices (5.0+) |

<br>

---

## � System Requirements

| Component | Requirement |
|:----------|:------------|
| **OS** | Windows 10/11 (64-bit) |
| **Python** | 3.8 or higher (3.14 recommended) |
| **RAM** | 4 GB |
| **Connectivity** | USB Cable or Wi-Fi |

<br>

---

## 📥 Installation

```bash
# 1. Install Dependencies
pip install -r requirements.txt

# 2. Run Application
python main1.py
```

<br>

---

## � Detailed Usage Guide (Kaise Use Kare)

Follow these steps to master every feature of the Ultimate Mobile Manager.

### 1. Connecting Your Device
Before doing anything, you need to connect your phone.

1.  **Enable Developer Options**: Go to Settings -> About Phone -> Tap **Build Number** 7 times.
2.  **Enable USB Debugging**: Go to Settings -> System -> Developer Options -> Turn ON **USB Debugging**.
3.  **Connect USB**: Plug your phone into the PC.
4.  **Allow Permission**: Look at your phone screen and tap **"Always allow from this computer"** -> **OK**.
5.  **Status Check**: The app should show `[OK] Samsung SM-A505` (or your model) in green at the top.

<br>

### 2. Wireless Connection (Wi-Fi)
Connect without cables - no terminal commands needed!

1.  **Connect USB First**: You need USB for the initial setup.
2.  **Enable Wi-Fi Mode**:
    *   Go to **Device** -> **Enable Wi-Fi Mode**.
    *   Click **Yes** on the confirmation.
    *   Wait for the "Success" message.
3.  **Disconnect USB**: Remove the cable.
4.  **Connect Wirelessly**:
    *   Go to **Device** -> **Wireless Connect**.
    *   Enter **IP Address** (e.g., `192.168.1.5`) and **Port** (`5555`).
    *   Click **Connect**.

<br>

### 3. Web Access Dashboard (New! 🌍)
Manage your device from any browser on your network.

1.  **Start Server**:
    *   Go to **Tools** -> **Start Web Access**.
    *   A window will appear showing a **Link** (e.g., `http://192.168.1.5:54321`) and a **PIN** (e.g., `AB12`).
2.  **Open Browser**:
    *   Type the link into Chrome, Safari, or Edge on ANY device (Laptop, iPad, another Phone).
3.  **Login**:
    *   Enter the **4-digit PIN** shown in the PC app.
    *   Click **Access Dashboard**.
4.  **Use**:
    *   View real-time battery and storage stats.
    *   Browse files.
    *   **Pro Tip**: If the link doesn't load, allow "Python" through your Windows Firewall when prompted.

<br>

### 4. File Transfer & Management
Move files between PC and Phone easily.

*   **Left Panel**: Computers Files (PC).
*   **Right Panel**: Mobile Files (Phone).

**To Copy Files:**
1.  **Select**: Click a file in either panel (Hold `Ctrl` to select multiple).
2.  **Transfer**:
    *   Click **▶▶ Send** to copy from PC to Phone.
    *   Click **◀◀ Get** to copy from Phone to PC.
    *   OR simply click **→ Copy** / **← Copy**.
3.  **Progress**: A status bar will show the transfer progress.

**To Delete:**
1.  Select the file/folder.
2.  Click **🗑️ Delete**.

### 5. Secure Encrypted Transfer
Send secret files that only **YOU** can open.

**Encrypt & Send (PC -> Phone):**
1.  **Select File**: Choose the file on PC.
2.  **Set Password**: Enter a strong password in the "Password" box at the top.
3.  **Encrypt**: Click **▶▶ Encrypt**.
4.  **Result**: The file is encrypted (AES-256) and sent to the phone with a `.enc` extension.

**Decrypt & Save (Phone -> PC):**
1.  **Select File**: Choose the `.enc` file on the Phone.
2.  **Enter Password**: Enter the **SAME** password used for encryption.
3.  **Decrypt**: Click **◀◀ Decrypt**.
4.  **Result**: The file is decrypted and saved to your PC in its original form.

<br>

### 5. App Management
Install or remove apps directly from your PC.

1.  **Open Tool**: Go to **Tools** -> **Installed Apps**.
2.  **Install APK**:
    *   Click **[Inst] Install APK**.
    *   Select the `.apk` file from your computer.
    *   Wait for the success message.
3.  **Uninstall App**:
    *   Select an app from the list.
    *   Click **[Del] Uninstall**.
    *   Confirm the action.
4.  **Launch App**: Select an app and click **[Open]**.

<br>

### 6. Screen Mirroring
View and control your phone screen on your monitor.

1.  **Start**: Go to **Device** -> **Screen Mirror**.
2.  **Control**:
    *   **Click**: Taps the screen.
    *   **Right Click**: Goes Back.
    *   **Type**: Uses PC keyboard to type on phone.
3.  **Shortcuts**:
    *   `Ctrl+F`: Fullscreen.
    *   `Ctrl+H`: Home.
    *   `Ctrl+S`: App Switcher.

<br>

### 7. Device Tools
Quick actions for power users.

*   **Screenshot**: Go to **Device** -> **Screenshot**. The image is saved to your PC automatically.
*   **Reboot**: Go to **Device** -> **Reboot**:
    *   **System**: Normal restart.
    *   **Recovery**: Boot into recovery mode (useful for flashing).
    *   **Bootloader**: Boot into fastboot mode.
*   **Refresh**: Press **F5** or go to **Device** -> **Refresh Info** to update battery/storage stats.

<br>

---

## � Troubleshooting

| Problem | Solution |
|:--------|:---------|
| **ADB Not Found** | Check connection, ensure USB Debugging is ON. |
| **Permission Denied** | Look at your phone and click "Allow" on the popup. |
| **Laggy UI** | We fixed this in v5.1! If it persists, restart the app. |
| **Wireless Fail** | Ensure PC and Phone are on the **same Wi-Fi network**. |

<br>

---

## 👨‍💻 Contact

<div align="center">

### Sudhir Kumar

[![GitHub](https://img.shields.io/badge/GitHub-@SudhirDevOps1-181717?style=for-the-badge&logo=github)](https://github.com/SudhirDevOps1)

<br>

**Made with ❤️ by Sudhir Kumar**

*© 2026 Ultimate Mobile Manager | Open Source*

</div>
