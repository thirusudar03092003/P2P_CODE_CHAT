# SecureChat: P2P Anonymous Communication Tool

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.6+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Cross--platform-lightgrey.svg" alt="Platform">
</p>

A peer-to-peer secure chat application that enables direct, anonymous communication between users without requiring a central server. This tool uses access code authentication to create private chat spaces accessible only to those who know the secret code.

## 🔒 Key Features

- **True Peer-to-Peer Architecture**: No central server or message storage
- **Access Code Authentication**: Secure connections using a shared secret code
- **No Account Required**: Complete anonymity with no registration
- **Cross-Platform Support**: Works on Windows, macOS, Linux, and Android (via Termux)
- **Dual Interface**: Both GUI and terminal versions available
- **Multi-Peer Support**: Connect with multiple users simultaneously
- **Zero Metadata**: No tracking of who communicates with whom

## 📋 Prerequisites

- Python 3.6+
- For GUI version: Tkinter
- For Termux: Python package installed

## 🚀 Installation

### Desktop/Laptop

1. Clone the repository:
```bash
git clone https://github.com/thirusudar03092003/P2P_CODE_CHAT.git
cd P2P_CODE_CHAT
```

2. Install dependencies (for GUI version):
```bash
# For Debian/Ubuntu
sudo apt-get update
sudo apt-get install python3-tk

# For Fedora
sudo dnf install python3-tkinter

# For macOS
brew install python-tk
```

3. Make scripts executable:
```bash
chmod +x p2p_chat.py termux_chat.py
```

### Android (Termux)

1. Install Termux from Google Play Store or F-Droid.
2. Install Python:
```bash
pkg update
pkg install python
```
3. Download the application:
```bash
git clone https://github.com/thirusudar03092003/P2P_CODE_CHAT.git
cd P2P_CODE_CHAT
chmod +x termux_chat.py
```

## 💻 Usage

### Starting the Chat

#### GUI Version (Desktop)
```bash
python3 p2p_chat.py -c YOUR_SECRET_CODE -n YOUR_NICKNAME
```
Example:
```bash
python3 p2p_chat.py -c meeting123 -n Alice
```

#### Terminal Version (Works everywhere including Termux)
```bash
python3 termux_chat.py -c YOUR_SECRET_CODE -n YOUR_NICKNAME
```
Example:
```bash
python3 termux_chat.py -c meeting123 -n Bob
```

### Command Line Arguments
| Argument | Description |
|----------|-------------|
| `-c` or `--code` | The secret access code (required) |
| `-n` or `--nickname` | Your display name (default: "Anonymous") |
| `-p` or `--port` | Specific port to use (default: random port) |

### Connecting with Friends
1. Start the application with the same secret code.
2. Find your connection info:
   - **GUI**: Connection → View Connection Info
   - **Terminal**: Type `/info` command
3. Share your IP:port with your friend through a separate channel.
4. Have your friend connect to you:
   - **GUI**: Connection → Connect to Peer → Enter your IP:port
   - **Terminal**: Type `/connect YOUR_IP:PORT`

### Terminal Commands
| Command | Description |
|---------|-------------|
| `/connect IP:PORT` | Connect to a peer |
| `/code NEW_CODE` | Change your access code |
| `/nick NICKNAME` | Change your display name |
| `/info` | Show your connection information |
| `/peers` | List connected peers |
| `/help` | Show available commands |
| `/clear` | Clear the screen |
| `/exit` | Exit the chat |

## 🔒 Security Model

### How It Works

**Access Code Authentication:**
- Both users must know the same secret code.
- The code is hashed using SHA-256 before transmission.
- Connection is only established if code hashes match.

**Direct P2P Communication:**
- Messages travel directly between peers.
- No server stores or forwards messages.
- No logs or chat history saved.

**Connection Security:**
- Each chat instance creates a unique peer ID.
- IP addresses are only visible to connected peers.
- Failed authentication attempts are rejected immediately.

### Security Considerations
- The access code should be shared through a secure channel.
- Your IP address is visible to peers you connect with.
- Messages are **not encrypted** during transit (only authenticated).
- For highest security, use on a trusted network.

## 📲 Use Cases
- Private conversations without account registration.
- Communication in environments where privacy is essential.
- Temporary chat rooms that leave no digital footprint.
- Ad-hoc secure communication channels.

## 🛠️ Technical Architecture
This application uses:
- **Socket programming** for network communication.
- **Threading** for handling multiple simultaneous connections.
- **JSON** for message formatting.
- **SHA-256** for access code verification.

## 📝 License
This project is licensed under the MIT License - see the `LICENSE` file for details.

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 🙏 Acknowledgements
Developed by **Thiru Sudar S L**
Inspired by the need for simple, private communication tools.

