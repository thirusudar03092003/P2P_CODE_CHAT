#!/usr/bin/env python3
import socket
import threading
import json
import time
import argparse
import random
import string
import hashlib
import os
import sys
from datetime import datetime

class P2PChatNode:
    def __init__(self):
        self.peers = {}  # {peer_id: (ip, port)}
        self.messages = []
        self.nickname = "Anonymous"
        self.server_socket = None
        self.is_listening = False
        self.listen_thread = None
        self.port = random.randint(10000, 65000)
        self.peer_id = self.generate_id()
        self.access_code = None
        self.access_code_hash = None
        self.connected_peers = set()
        
    def generate_id(self, length=8):
        """Generate a random alphanumeric ID"""
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))
    
    def set_access_code(self, code):
        """Set the access code and its hash"""
        self.access_code = code
        self.access_code_hash = hashlib.sha256(code.encode()).hexdigest()
        return self.access_code_hash
    
    def verify_access_code(self, code_hash):
        """Verify if the provided code hash matches our access code"""
        if not self.access_code_hash:
            return False
        return code_hash == self.access_code_hash
    
    def start_listening(self):
        """Start listening for incoming connections"""
        if self.is_listening:
            return False
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.is_listening = True
            
            self.listen_thread = threading.Thread(target=self.listen_for_connections)
            self.listen_thread.daemon = True
            self.listen_thread.start()
            
            return True
        except Exception as e:
            print(f"\033[91mError starting listener: {e}\033[0m")
            if self.server_socket:
                self.server_socket.close()
            return False
    
    def listen_for_connections(self):
        """Listen for incoming peer connections"""
        while self.is_listening:
            try:
                client_socket, address = self.server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_peer_connection,
                    args=(client_socket, address)
                )
                client_handler.daemon = True
                client_handler.start()
            except Exception as e:
                if self.is_listening:  # Only show error if we're supposed to be listening
                    print(f"\033[91mError accepting connection: {e}\033[0m")
    
    def handle_peer_connection(self, client_socket, address):
        """Handle an incoming peer connection"""
        peer_id = None
        peer_nickname = "Unknown"
        
        try:
            # First message should be authentication
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                client_socket.close()
                return
            
            try:
                auth_data = json.loads(data)
                if auth_data.get('type') != 'auth':
                    client_socket.close()
                    return
                
                # Verify the access code
                peer_code_hash = auth_data.get('code_hash')
                if not self.verify_access_code(peer_code_hash):
                    # Send auth failed message
                    response = json.dumps({
                        'type': 'auth_response',
                        'status': 'failed',
                        'message': 'Invalid access code'
                    })
                    client_socket.send(response.encode('utf-8'))
                    client_socket.close()
                    return
                
                # Authentication successful
                peer_id = auth_data.get('peer_id')
                peer_nickname = auth_data.get('nickname', 'Anonymous')
                
                # Send auth success response
                response = json.dumps({
                    'type': 'auth_response',
                    'status': 'success',
                    'peer_id': self.peer_id,
                    'nickname': self.nickname
                })
                client_socket.send(response.encode('utf-8'))
                
                # Add to connected peers
                self.peers[peer_id] = (address[0], auth_data.get('port', address[1]))
                self.connected_peers.add(peer_id)
                
                # Send connection notification
                self.add_system_message(f"{peer_nickname} has joined the chat")
                
                # Handle messages from this peer
                while True:
                    data = client_socket.recv(4096).decode('utf-8')
                    if not data:
                        break
                    
                    message = json.loads(data)
                    if message.get('type') == 'message':
                        content = message.get('content', '')
                        timestamp = message.get('timestamp', datetime.now().strftime("%H:%M:%S"))
                        
                        self.add_message(peer_nickname, content, timestamp)
            
            except json.JSONDecodeError:
                client_socket.close()
                return
        
        except Exception as e:
            print(f"\033[91mError handling peer connection: {e}\033[0m")
        
        finally:
            # Clean up when connection ends
            if peer_id in self.connected_peers:
                self.connected_peers.remove(peer_id)
            if peer_id in self.peers:
                del self.peers[peer_id]
            
            if peer_nickname != "Unknown":
                self.add_system_message(f"{peer_nickname} has left the chat")
            client_socket.close()
    
    def connect_to_peer(self, ip, port):
        """Connect to a peer using the access code"""
        if not self.access_code_hash:
            return False, "No access code set"
        
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((ip, port))
            
            # Send authentication
            auth_data = {
                'type': 'auth',
                'peer_id': self.peer_id,
                'nickname': self.nickname,
                'port': self.port,
                'code_hash': self.access_code_hash
            }
            peer_socket.send(json.dumps(auth_data).encode('utf-8'))
            
            # Wait for auth response
            response_data = peer_socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            
            if response.get('type') == 'auth_response' and response.get('status') == 'success':
                peer_id = response.get('peer_id')
                peer_nickname = response.get('nickname', 'Anonymous')
                
                # Add to peers
                self.peers[peer_id] = (ip, port)
                self.connected_peers.add(peer_id)
                
                # Start a thread to receive messages
                receive_thread = threading.Thread(
                    target=self.receive_from_peer,
                    args=(peer_socket, peer_id, peer_nickname)
                )
                receive_thread.daemon = True
                receive_thread.start()
                
                # Send connection notification
                self.add_system_message(f"Connected to {peer_nickname}")
                
                return True, f"Connected to {peer_nickname}"
            else:
                error_msg = response.get('message', 'Authentication failed')
                peer_socket.close()
                return False, error_msg
        
        except Exception as e:
            return False, str(e)
    
    def receive_from_peer(self, peer_socket, peer_id, peer_nickname):
        """Receive messages from a connected peer"""
        try:
            while peer_id in self.connected_peers:
                data = peer_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    if message.get('type') == 'message':
                        content = message.get('content', '')
                        timestamp = message.get('timestamp', datetime.now().strftime("%H:%M:%S"))
                        
                        self.add_message(peer_nickname, content, timestamp)
                except json.JSONDecodeError:
                    continue
        
        except Exception as e:
            print(f"\033[91mError receiving from peer: {e}\033[0m")
        
        finally:
            # Clean up when connection ends
            if peer_id in self.connected_peers:
                self.connected_peers.remove(peer_id)
            if peer_id in self.peers:
                del self.peers[peer_id]
            
            self.add_system_message(f"Disconnected from {peer_nickname}")
            peer_socket.close()
    
    def send_message_to_peers(self, content):
        """Send a message to all connected peers"""
        if not content:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        message = {
            'type': 'message',
            'content': content,
            'timestamp': timestamp
        }
        
        # Add to our own messages
        self.add_message(self.nickname, content, timestamp, is_self=True)
        
        # Send to all peers
        message_data = json.dumps(message).encode('utf-8')
        for peer_id in list(self.connected_peers):
            try:
                if peer_id in self.peers:
                    ip, port = self.peers[peer_id]
                    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    peer_socket.connect((ip, port))
                    peer_socket.send(message_data)
                    peer_socket.close()
            except Exception as e:
                print(f"\033[91mError sending to peer {peer_id}: {e}\033[0m")
                if peer_id in self.connected_peers:
                    self.connected_peers.remove(peer_id)
                if peer_id in self.peers:
                    del self.peers[peer_id]
    
    def add_message(self, sender, content, timestamp, is_self=False):
        """Add a message to the message history"""
        message = {
            'type': 'message',
            'sender': sender,
            'content': content,
            'timestamp': timestamp,
            'is_self': is_self
        }
        
        self.messages.append(message)
        self.on_message_received(message)
    
    def add_system_message(self, content):
        """Add a system message to the message history"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        message = {
            'type': 'system',
            'content': content,
            'timestamp': timestamp
        }
        
        self.messages.append(message)
        self.on_message_received(message)
    
    def on_message_received(self, message):
        """Callback for when a message is received (to be overridden)"""
        pass
    
    def stop(self):
        """Stop the node and close all connections"""
        self.is_listening = False
        if self.server_socket:
            self.server_socket.close()
        
        # Close all peer connections
        for peer_id in list(self.connected_peers):
            self.connected_peers.remove(peer_id)
        
        self.peers = {}


class TerminalChat:
    def __init__(self):
        self.chat_node = P2PChatNode()
        self.chat_node.on_message_received = self.on_message_received
        self.running = True
        self.input_thread = None
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        """Print a cool hacker-style banner"""
        self.clear_screen()
        
        banner = """
\033[92m╔══════════════════════════════════════════════════════════╗
║                                                          ║
║              P 2 P   S E C U R E   C H A T               ║
║                  C O D E   A C C E S S                   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝\033[0m

\033[93m[*] Direct peer-to-peer chat with code-based access
[*] No central server - your messages stay private
[*] Type /help for available commands\033[0m

"""
        print(banner)
    
    def print_help(self):
        """Print available commands"""
        help_text = """
\033[95mAvailable commands:
  /connect <ip:port>   - Connect to a peer
  /code <access_code>  - Set or change the access code
  /nick <nickname>     - Change your display name
  /info                - Show your connection information
  /peers               - List connected peers
  /help                - Show this help message
  /clear               - Clear the screen
  /exit                - Exit the chat
\033[0m
"""
        print(help_text)
    
    def start(self):
        """Start the chat client"""
        self.print_banner()
        
        # Start the chat node
        if self.chat_node.start_listening():
            print(f"\033[92m[+] Listening on port {self.chat_node.port}\033[0m")
        else:
            print(f"\033[91m[!] Failed to start listener\033[0m")
            return
        
        # Start input thread
        self.input_thread = threading.Thread(target=self.input_loop)
        self.input_thread.daemon = True
        self.input_thread.start()
        
        # Wait for exit
        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.running = False
        
        # Clean up
        self.chat_node.stop()
        print("\n\033[93m[*] Exiting...\033[0m")
    
    def input_loop(self):
        """Handle user input"""
        while self.running:
            try:
                user_input = input("\033[92m>\033[0m ")
                
                if not user_input:
                    continue
                
                if user_input.startswith('/'):
                    self.handle_command(user_input)
                else:
                    if not self.chat_node.access_code:
                        print("\033[91m[!] You must set an access code first with /code <access_code>\033[0m")
                    elif not self.chat_node.connected_peers:
                        print("\033[91m[!] You are not connected to any peers\033[0m")
                    else:
                        self.chat_node.send_message_to_peers(user_input)
            
            except EOFError:
                self.running = False
                break
            except KeyboardInterrupt:
                self.running = False
                break
    
    def handle_command(self, command):
        """Handle chat commands"""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        if cmd == '/help':
            self.print_help()
        
        elif cmd == '/clear':
            self.print_banner()
        
        elif cmd == '/exit':
            self.running = False
        
        elif cmd == '/code':
            if not arg:
                print("\033[91m[!] Usage: /code <access_code>\033[0m")
            else:
                self.chat_node.set_access_code(arg)
                print(f"\033[92m[+] Access code set: {arg[:2]}...{arg[-2:]}\033[0m")
        
        elif cmd == '/nick':
            if not arg:
                print("\033[91m[!] Usage: /nick <nickname>\033[0m")
            else:
                old_nickname = self.chat_node.nickname
                self.chat_node.nickname = arg
                print(f"\033[92m[+] Nickname changed from {old_nickname} to {arg}\033[0m")
        
        elif cmd == '/connect':
            if not arg:
                print("\033[91m[!] Usage: /connect <ip:port>\033[0m")
            else:
                if not self.chat_node.access_code:
                    print("\033[91m[!] You must set an access code first with /code <access_code>\033[0m")
                    return
                
                try:
                    # Parse IP and port
                    if ":" in arg:
                        ip, port_str = arg.split(":")
                        port = int(port_str)
                    else:
                        ip = arg
                        port = 10000  # Default port
                    
                    # Connect to peer
                    print(f"\033[93m[*] Connecting to {ip}:{port}...\033[0m")
                    success, message = self.chat_node.connect_to_peer(ip, port)
                    
                    if success:
                        print(f"\033[92m[+] {message}\033[0m")
                    else:
                        print(f"\033[91m[!] {message}\033[0m")
                
                except Exception as e:
                    print(f"\033[91m[!] Error connecting to peer: {e}\033[0m")
        
        elif cmd == '/info':
            # Get local IP addresses
            hostname = socket.gethostname()
            ip_addresses = []
            
            try:
                # Try to get all IP addresses
                for info in socket.getaddrinfo(hostname, None):
                    ip = info[4][0]
                    if not ip.startswith('127.') and ':' not in ip:  # Skip localhost and IPv6
                        ip_addresses.append(ip)
            except:
                pass
            
            # If we couldn't get IP addresses, try another method
            if not ip_addresses:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(('8.8.8.8', 80))
                    ip_addresses.append(s.getsockname()[0])
                    s.close()
                except:
                    ip_addresses.append('Could not determine IP')
            
            # Show connection info
            print("\n\033[96mYour connection info:\033[0m")
            for ip in ip_addresses:
                print(f"\033[96mIP: {ip}, Port: {self.chat_node.port}\033[0m")
            
            if self.chat_node.access_code:
                print(f"\033[96mAccess code: {self.chat_node.access_code}\033[0m")
            else:
                print("\033[96mNo access code set\033[0m")
            
            print(f"\033[96mConnected peers: {len(self.chat_node.connected_peers)}\033[0m\n")
        
        elif cmd == '/peers':
            if not self.chat_node.connected_peers:
                print("\033[93m[*] No connected peers\033[0m")
            else:
                print("\n\033[96mConnected peers:\033[0m")
                for peer_id in self.chat_node.connected_peers:
                    if peer_id in self.chat_node.peers:
                        ip, port = self.chat_node.peers[peer_id]
                        print(f"\033[96m- {peer_id} at {ip}:{port}\033[0m")
                print()
        
        else:
            print(f"\033[91m[!] Unknown command: {cmd}\033[0m")
    
    def on_message_received(self, message):
        """Handle received messages"""
        if message['type'] == 'message':
            timestamp = message.get('timestamp', datetime.now().strftime("%H:%M:%S"))
            sender = message.get('sender', 'Unknown')
            content = message.get('content', '')
            
            if message.get('is_self'):
                print(f"\033[90m[{timestamp}]\033[0m \033[92m[{sender}]\033[0m {content}")
            else:
                print(f"\033[90m[{timestamp}]\033[0m \033[96m[{sender}]\033[0m {content}")
        
        elif message['type'] == 'system':
            timestamp = message.get('timestamp', datetime.now().strftime("%H:%M:%S"))
            content = message.get('content', '')
            
            print(f"\033[90m[{timestamp}]\033[0m \033[93m[System]\033[0m {content}")

def main():
    parser = argparse.ArgumentParser(description="P2P Chat with Code Authentication")
    parser.add_argument("-p", "--port", type=int, help="Port to listen on (default: random)")
    parser.add_argument("-c", "--code", help="Access code")
    parser.add_argument("-n", "--nickname", default="Anonymous", help="Your nickname")
    args = parser.parse_args()
    
    chat = TerminalChat()
    
    # Set command line arguments
    if args.port:
        chat.chat_node.port = args.port
    
    if args.code:
        chat.chat_node.set_access_code(args.code)
    
    if args.nickname:
        chat.chat_node.nickname = args.nickname
    
    # Start the chat
    chat.start()

if __name__ == "__main__":
    main()
