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
import tkinter as tk
from tkinter import scrolledtext, simpledialog
import tkinter.ttk as ttk

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
            print(f"Error starting listener: {e}")
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
                    print(f"Error accepting connection: {e}")
    
    def handle_peer_connection(self, client_socket, address):
        """Handle an incoming peer connection"""
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
            print(f"Error handling peer connection: {e}")
        
        finally:
            # Clean up when connection ends
            if peer_id in self.connected_peers:
                self.connected_peers.remove(peer_id)
            if peer_id in self.peers:
                del self.peers[peer_id]
            
            self.add_system_message(f"{peer_nickname} has left the chat")
            client_socket.close()
    
    def connect_to_peer(self, ip, port, on_connect=None):
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
                
                if on_connect:
                    on_connect(True, f"Connected to {peer_nickname}")
                
                return True, f"Connected to {peer_nickname}"
            else:
                error_msg = response.get('message', 'Authentication failed')
                peer_socket.close()
                
                if on_connect:
                    on_connect(False, error_msg)
                
                return False, error_msg
        
        except Exception as e:
            if on_connect:
                on_connect(False, str(e))
            
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
            print(f"Error receiving from peer: {e}")
        
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
                print(f"Error sending to peer {peer_id}: {e}")
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


class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure P2P Chat - Code Access")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Set up the chat node
        self.chat_node = P2PChatNode()
        self.chat_node.on_message_received = self.on_message_received
        
        # Configure style
        self.configure_style()
        
        # Create frames
        self.create_frames()
        
        # Create menu
        self.create_menu()
        
        # Create widgets
        self.create_widgets()
        
        # Start the chat node
        self.chat_node.start_listening()
        self.status_var.set(f"Listening on port {self.chat_node.port}")
    
    def configure_style(self):
        """Configure the application style"""
        style = ttk.Style()
        style.configure("TFrame", background="#0a0e14")
        style.configure("TLabel", background="#0a0e14", foreground="#00ff00")
        style.configure("TButton", background="#0a0e14", foreground="#00ff00")
        style.configure("TEntry", background="#000000", foreground="#00ff00", fieldbackground="#000000")
        
        self.root.configure(bg="#0a0e14")
    
    def create_frames(self):
        """Create the application frames"""
        # Main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top frame for status and controls
        self.top_frame = ttk.Frame(self.main_frame)
        self.top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Chat frame
        self.chat_frame = ttk.Frame(self.main_frame)
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input frame
        self.input_frame = ttk.Frame(self.main_frame)
        self.input_frame.pack(fill=tk.X, pady=(10, 0))
    
    def create_menu(self):
        """Create the application menu"""
        self.menu_bar = tk.Menu(self.root)
        
        # File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Set Access Code", command=self.set_access_code)
        self.file_menu.add_command(label="Change Nickname", command=self.change_nickname)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        
        # Connection menu
        self.connection_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.connection_menu.add_command(label="Connect to Peer", command=self.connect_to_peer)
        self.connection_menu.add_command(label="View Connection Info", command=self.view_connection_info)
        self.menu_bar.add_cascade(label="Connection", menu=self.connection_menu)
        
        # Help menu
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        
        self.root.config(menu=self.menu_bar)
    
    def create_widgets(self):
        """Create the application widgets"""
        # Status label
        self.status_var = tk.StringVar()
        self.status_var.set("Not connected")
        self.status_label = ttk.Label(self.top_frame, textvariable=self.status_var, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Connection status
        self.connection_var = tk.StringVar()
        self.connection_var.set("No access code set")
        self.connection_label = ttk.Label(self.top_frame, textvariable=self.connection_var, anchor=tk.E)
        self.connection_label.pack(side=tk.RIGHT)
        
        # Chat text area
        self.chat_text = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, bg="#000000", fg="#00ff00", insertbackground="#00ff00")
        self.chat_text.pack(fill=tk.BOTH, expand=True)
        self.chat_text.config(state=tk.DISABLED)
        
        # Input field
        self.input_var = tk.StringVar()
        self.input_entry = ttk.Entry(self.input_frame, textvariable=self.input_var)
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.input_entry.bind("<Return>", self.send_message)
        
        # Send button
        self.send_button = ttk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)
    
    def set_access_code(self):
        """Set the access code for the chat"""
        code = simpledialog.askstring("Access Code", "Enter the access code:", parent=self.root)
        if code:
            self.chat_node.set_access_code(code)
            self.connection_var.set(f"Access code set: {code[:2]}...{code[-2:]}")
            self.add_to_chat("System", f"Access code set: {code[:2]}...{code[-2:]}", "system")
    
    def change_nickname(self):
        """Change the user's nickname"""
        nickname = simpledialog.askstring("Nickname", "Enter your nickname:", parent=self.root)
        if nickname:
            old_nickname = self.chat_node.nickname
            self.chat_node.nickname = nickname
            self.add_to_chat("System", f"You changed your nickname from {old_nickname} to {nickname}", "system")
    
    def connect_to_peer(self):
        """Connect to a peer"""
        if not self.chat_node.access_code_hash:
            self.add_to_chat("System", "You must set an access code first", "system")
            return
        
        # Ask for peer IP and port
        peer_address = simpledialog.askstring("Connect to Peer", "Enter peer IP:port:", parent=self.root)
        if not peer_address:
            return
        
        try:
            # Parse IP and port
            if ":" in peer_address:
                ip, port_str = peer_address.split(":")
                port = int(port_str)
            else:
                ip = peer_address
                port = 10000  # Default port
            
            # Connect to peer
            self.add_to_chat("System", f"Connecting to {ip}:{port}...", "system")
            
            def on_connect_result(success, message):
                self.add_to_chat("System", message, "system")
            
            threading.Thread(
                target=self.chat_node.connect_to_peer,
                args=(ip, port, on_connect_result)
            ).start()
        
        except Exception as e:
            self.add_to_chat("System", f"Error connecting to peer: {e}", "system")
    
    def view_connection_info(self):
        """View connection information"""
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
        info = f"Your connection info:\n"
        for ip in ip_addresses:
            info += f"IP: {ip}, Port: {self.chat_node.port}\n"
        
        if self.chat_node.access_code:
            info += f"\nAccess code: {self.chat_node.access_code}\n"
        else:
            info += "\nNo access code set\n"
        
        info += f"\nConnected peers: {len(self.chat_node.connected_peers)}\n"
        
        tk.messagebox.showinfo("Connection Info", info)
    
    def show_about(self):
        """Show about information"""
        about_text = """Secure P2P Chat with Code Access

A peer-to-peer chat application that uses 
access codes for secure communication.

Features:
- Direct peer-to-peer communication
- No central server required
- Access code authentication
- End-to-end messaging
"""
        tk.messagebox.showinfo("About", about_text)
    
    def send_message(self, event=None):
        """Send a message to all connected peers"""
        message = self.input_var.get().strip()
        if message:
            self.chat_node.send_message_to_peers(message)
            self.input_var.set("")
    
    def on_message_received(self, message):
        """Handle received messages"""
        if message['type'] == 'message':
            self.add_to_chat(message['sender'], message['content'], 'self' if message.get('is_self') else 'other', message['timestamp'])
        elif message['type'] == 'system':
            self.add_to_chat("System", message['content'], 'system', message['timestamp'])
    
    def add_to_chat(self, sender, content, message_type, timestamp=None):
        """Add a message to the chat display"""
        if not timestamp:
            timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.chat_text.config(state=tk.NORMAL)
        
        # Add timestamp
        self.chat_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        
        # Add sender and content based on message type
        if message_type == 'system':
            self.chat_text.insert(tk.END, f"{sender}: ", "system_sender")
            self.chat_text.insert(tk.END, f"{content}\n", "system_content")
        elif message_type == 'self':
            self.chat_text.insert(tk.END, f"{sender}: ", "self_sender")
            self.chat_text.insert(tk.END, f"{content}\n", "self_content")
        else:
            self.chat_text.insert(tk.END, f"{sender}: ", "other_sender")
            self.chat_text.insert(tk.END, f"{content}\n", "other_content")
        
        # Configure tags
        self.chat_text.tag_config("timestamp", foreground="#888888")
        self.chat_text.tag_config("system_sender", foreground="#ffcc00", font=("TkDefaultFont", 10, "bold"))
        self.chat_text.tag_config("system_content", foreground="#ffcc00")
        self.chat_text.tag_config("self_sender", foreground="#00ff00", font=("TkDefaultFont", 10, "bold"))
        self.chat_text.tag_config("self_content", foreground="#00ff00")
        self.chat_text.tag_config("other_sender", foreground="#00ccff", font=("TkDefaultFont", 10, "bold"))
        self.chat_text.tag_config("other_content", foreground="#ffffff")
        
        # Scroll to the end
        self.chat_text.see(tk.END)
        self.chat_text.config(state=tk.DISABLED)

def main():
    parser = argparse.ArgumentParser(description="P2P Chat with Code Authentication")
    parser.add_argument("-p", "--port", type=int, help="Port to listen on (default: random)")
    parser.add_argument("-c", "--code", help="Access code")
    parser.add_argument("-n", "--nickname", default="Anonymous", help="Your nickname")
    args = parser.parse_args()
    
    root = tk.Tk()
    app = ChatGUI(root)
    
    # Set command line arguments
    if args.port:
        app.chat_node.port = args.port
        app.chat_node.stop()
        app.chat_node.start_listening()
        app.status_var.set(f"Listening on port {app.chat_node.port}")
    
    if args.code:
        app.chat_node.set_access_code(args.code)
        app.connection_var.set(f"Access code set: {args.code[:2]}...{args.code[-2:]}")
    
    if args.nickname:
        app.chat_node.nickname = args.nickname
    
    # Set up cleanup on exit
    def on_closing():
        app.chat_node.stop()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Start the GUI
    root.mainloop()

if __name__ == "__main__":
    main()
