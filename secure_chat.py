import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import json
import base64
import os
import sys
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class SecureChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Application")
        self.master.geometry("800x600")
        self.master.minsize(600, 400)
        self.master.configure(bg="#2c3e50")
        
        # Set app icon and styling
        self.master.option_add("*Font", "Arial 10")
        
        # Variables
        self.username = ""
        self.connected = False
        self.server_mode = False
        self.client_mode = False
        self.socket = None
        self.client_socket = None
        self.client_address = None
        self.server_thread = None
        self.receive_thread = None
        self.encryption_ready = False
        
        # Encryption keys
        self.private_key = None
        self.public_key = None
        self.partner_public_key = None
        self.session_key = None
        
        # Chat history
        self.chat_history = []
        
        # Create widgets
        self.create_widgets()
        
        # Generate encryption keys
        self.generate_keys()
        
        # Ask for username
        self.get_username()
    
    def create_widgets(self):
        # Main frame
        main_frame = tk.Frame(self.master, bg="#34495e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top frame for connection controls
        top_frame = tk.Frame(main_frame, bg="#34495e")
        top_frame.pack(fill=tk.X, pady=5)
        
        # Connection type selection
        self.connection_var = tk.StringVar(value="server")
        tk.Radiobutton(top_frame, text="Host Chat (Server)", variable=self.connection_var, 
                      value="server", bg="#34495e", fg="white", selectcolor="#2c3e50").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(top_frame, text="Join Chat (Client)", variable=self.connection_var, 
                      value="client", bg="#34495e", fg="white", selectcolor="#2c3e50").pack(side=tk.LEFT, padx=5)
        
        # IP and Port entry
        ip_frame = tk.Frame(main_frame, bg="#34495e")
        ip_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(ip_frame, text="IP Address:", bg="#34495e", fg="white").pack(side=tk.LEFT, padx=5)
        self.ip_entry = tk.Entry(ip_frame, width=15)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.ip_entry.insert(0, "127.0.0.1")
        
        tk.Label(ip_frame, text="Port:", bg="#34495e", fg="white").pack(side=tk.LEFT, padx=5)
        self.port_entry = tk.Entry(ip_frame, width=6)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "5555")
        
        # Connect button
        self.connect_button = tk.Button(ip_frame, text="Connect", command=self.connect, 
                                     bg="#2ecc71", fg="white", relief=tk.FLAT)
        self.connect_button.pack(side=tk.LEFT, padx=10)
        
        # Disconnect button
        self.disconnect_button = tk.Button(ip_frame, text="Disconnect", command=self.disconnect, 
                                        bg="#e74c3c", fg="white", relief=tk.FLAT, state=tk.DISABLED)
        self.disconnect_button.pack(side=tk.LEFT, padx=5)
        
        # Status indicator
        status_frame = tk.Frame(main_frame, bg="#34495e")
        status_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(status_frame, text="Status:", bg="#34495e", fg="white").pack(side=tk.LEFT, padx=5)
        self.status_label = tk.Label(status_frame, text="Disconnected", bg="#e74c3c", fg="white", 
                                   width=15, relief=tk.RIDGE)
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        tk.Label(status_frame, text="Username:", bg="#34495e", fg="white").pack(side=tk.LEFT, padx=5)
        self.username_label = tk.Label(status_frame, text="Not set", bg="#34495e", fg="white", 
                                     width=15, relief=tk.RIDGE)
        self.username_label.pack(side=tk.LEFT, padx=5)
        
        tk.Label(status_frame, text="Encryption:", bg="#34495e", fg="white").pack(side=tk.LEFT, padx=5)
        self.encryption_label = tk.Label(status_frame, text="Initializing", bg="#f39c12", fg="white", 
                                       width=15, relief=tk.RIDGE)
        self.encryption_label.pack(side=tk.LEFT, padx=5)
        
        # Chat display area
        chat_frame = tk.Frame(main_frame, bg="#34495e")
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.chat_display = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, bg="#ecf0f1", 
                                                    font=("Arial", 11))
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        self.chat_display.config(state=tk.DISABLED)
        
        # Message entry area
        message_frame = tk.Frame(main_frame, bg="#34495e")
        message_frame.pack(fill=tk.X, pady=5)
        
        self.message_entry = tk.Entry(message_frame, font=("Arial", 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        self.message_entry.config(state=tk.DISABLED)
        
        self.send_button = tk.Button(message_frame, text="Send", command=self.send_message, 
                                   bg="#3498db", fg="white", relief=tk.FLAT, width=10)
        self.send_button.pack(side=tk.RIGHT, padx=5)
        self.send_button.config(state=tk.DISABLED)
        
        # Menu bar
        menu_bar = tk.Menu(self.master)
        self.master.config(menu=menu_bar)
        
        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Chat History", command=self.save_chat_history)
        file_menu.add_command(label="Clear Chat", command=self.clear_chat)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_app)
        
        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Security Info", command=self.show_security_info)
    
    def get_username(self):
        username = simpledialog.askstring("Username", "Enter your username:", parent=self.master)
        if username:
            self.username = username
            self.username_label.config(text=username)
        else:
            self.username = f"User_{os.urandom(2).hex()}"
            self.username_label.config(text=self.username)
    
    def generate_keys(self):
        try:
            # Generate RSA key pair
            key = RSA.generate(2048)
            self.private_key = key
            self.public_key = key.publickey()
            
            # Update encryption status
            self.encryption_label.config(text="Keys Generated", bg="#f39c12")
            self.update_chat_display("System", "Encryption keys generated successfully.")
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to generate encryption keys: {str(e)}")
    
    def connect(self):
        # Get connection details
        ip = self.ip_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Port", "Port must be a number")
            return
        
        # Disable connection controls
        self.connect_button.config(state=tk.DISABLED)
        self.ip_entry.config(state=tk.DISABLED)
        self.port_entry.config(state=tk.DISABLED)
        
        # Check connection type
        if self.connection_var.get() == "server":
            self.start_server(ip, port)
        else:
            self.start_client(ip, port)
    
    def start_server(self, ip, port):
        try:
            # Create server socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((ip, port))
            self.socket.listen(1)
            
            # Update status
            self.status_label.config(text="Listening", bg="#f39c12")
            self.update_chat_display("System", f"Server started on {ip}:{port}. Waiting for connection...")
            
            # Start server thread
            self.server_mode = True
            self.server_thread = threading.Thread(target=self.accept_connections)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            # Enable disconnect button
            self.disconnect_button.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to start server: {str(e)}")
            self.reset_connection_controls()
    
    def accept_connections(self):
        try:
            # Accept client connection
            self.client_socket, self.client_address = self.socket.accept()
            
            # Update status
            self.master.after(0, lambda: self.status_label.config(text="Connected", bg="#2ecc71"))
            self.master.after(0, lambda: self.update_chat_display("System", 
                                                               f"Client connected from {self.client_address[0]}:{self.client_address[1]}"))
            
            # Enable chat controls
            self.master.after(0, lambda: self.enable_chat_controls())
            
            # Start key exchange
            self.master.after(0, lambda: self.exchange_keys())
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
        except Exception as e:
            if not self.connected:
                self.master.after(0, lambda: self.update_chat_display("System", f"Connection error: {str(e)}"))
                self.master.after(0, lambda: self.reset_connection_controls())
    
    def start_client(self, ip, port):
        try:
            # Create client socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((ip, port))
            
            # Update status
            self.status_label.config(text="Connected", bg="#2ecc71")
            self.update_chat_display("System", f"Connected to server at {ip}:{port}")
            
            # Set client mode
            self.client_mode = True
            self.connected = True
            
            # Enable chat controls
            self.enable_chat_controls()
            
            # Enable disconnect button
            self.disconnect_button.config(state=tk.NORMAL)
            
            # Start key exchange
            self.exchange_keys()
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            self.reset_connection_controls()
    
    def exchange_keys(self):
        try:
            # Send public key
            public_key_bytes = self.public_key.export_key()
            self.send_data({
                "type": "key_exchange",
                "public_key": base64.b64encode(public_key_bytes).decode("utf-8"),
                "username": self.username
            })
            
            self.update_chat_display("System", "Exchanging encryption keys...")
        except Exception as e:
            self.update_chat_display("System", f"Key exchange error: {str(e)}")
    
    def complete_key_exchange(self, partner_key_data, partner_username):
        try:
            # Import partner's public key
            partner_key_bytes = base64.b64decode(partner_key_data)
            self.partner_public_key = RSA.import_key(partner_key_bytes)
            
            # Generate session key (AES-256)
            self.session_key = get_random_bytes(32)  # 256 bits
            
            # Encrypt session key with partner's public key
            cipher_rsa = PKCS1_OAEP.new(self.partner_public_key)
            encrypted_session_key = cipher_rsa.encrypt(self.session_key)
            
            # Send encrypted session key
            self.send_data({
                "type": "session_key",
                "session_key": base64.b64encode(encrypted_session_key).decode("utf-8")
            })
            
            # Update encryption status
            self.encryption_ready = True
            self.encryption_label.config(text="Secure", bg="#2ecc71")
            self.update_chat_display("System", f"Secure connection established with {partner_username}")
        except Exception as e:
            self.update_chat_display("System", f"Key exchange completion error: {str(e)}")
    
    def receive_session_key(self, encrypted_session_key_data):
        try:
            # Decrypt session key with private key
            encrypted_session_key = base64.b64decode(encrypted_session_key_data)
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            self.session_key = cipher_rsa.decrypt(encrypted_session_key)
            
            # Update encryption status
            self.encryption_ready = True
            self.encryption_label.config(text="Secure", bg="#2ecc71")
            self.update_chat_display("System", "Secure connection established")
        except Exception as e:
            self.update_chat_display("System", f"Session key reception error: {str(e)}")
    
    def enable_chat_controls(self):
        self.message_entry.config(state=tk.NORMAL)
        self.send_button.config(state=tk.NORMAL)
        self.connected = True
    
    def disable_chat_controls(self):
        self.message_entry.config(state=tk.DISABLED)
        self.send_button.config(state=tk.DISABLED)
        self.connected = False
    
    def reset_connection_controls(self):
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)
        self.ip_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        self.status_label.config(text="Disconnected", bg="#e74c3c")
        self.encryption_label.config(text="Keys Generated", bg="#f39c12")
        self.server_mode = False
        self.client_mode = False
        self.connected = False
        self.encryption_ready = False
        self.partner_public_key = None
        self.session_key = None
    
    def disconnect(self):
        try:
            # Send disconnect message
            if self.connected and self.encryption_ready:
                self.send_data({"type": "disconnect", "username": self.username})
            
            # Close socket
            if self.socket:
                self.socket.close()
            
            if self.client_socket:
                self.client_socket.close()
            
            # Update status
            self.status_label.config(text="Disconnected", bg="#e74c3c")
            self.update_chat_display("System", "Disconnected from chat")
            
            # Reset controls
            self.disable_chat_controls()
            self.reset_connection_controls()
        except Exception as e:
            self.update_chat_display("System", f"Disconnect error: {str(e)}")
            self.reset_connection_controls()
    
    def send_message(self):
        message = self.message_entry.get().strip()
        if not message or not self.connected:
            return
        
        if not self.encryption_ready:
            self.update_chat_display("System", "Cannot send message: Secure connection not established yet")
            return
        
        try:
            # Send encrypted message
            self.send_data({
                "type": "message",
                "username": self.username,
                "content": message
            })
            
            # Update chat display
            self.update_chat_display(self.username, message, is_self=True)
            
            # Clear message entry
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.update_chat_display("System", f"Failed to send message: {str(e)}")
    
    def send_data(self, data):
        try:
            # Convert data to JSON
            json_data = json.dumps(data)
            
            # Encrypt data if session key is available and it's not a key exchange message
            if self.encryption_ready and data.get("type") not in ["key_exchange", "session_key"]:
                # Encrypt with AES
                cipher_aes = AES.new(self.session_key, AES.MODE_CBC)
                padded_data = pad(json_data.encode("utf-8"), AES.block_size)
                encrypted_data = cipher_aes.encrypt(padded_data)
                
                # Prepare message with IV
                message = {
                    "encrypted": True,
                    "iv": base64.b64encode(cipher_aes.iv).decode("utf-8"),
                    "data": base64.b64encode(encrypted_data).decode("utf-8")
                }
                json_data = json.dumps(message)
            
            # Add message length prefix
            message_bytes = json_data.encode("utf-8")
            length_prefix = len(message_bytes).to_bytes(4, byteorder="big")
            
            # Send message
            if self.server_mode and self.client_socket:
                self.client_socket.sendall(length_prefix + message_bytes)
            elif self.client_mode and self.socket:
                self.socket.sendall(length_prefix + message_bytes)
        except Exception as e:
            raise Exception(f"Failed to send data: {str(e)}")
    
    def receive_messages(self):
        current_socket = self.client_socket if self.server_mode else self.socket
        
        while self.connected:
            try:
                # Receive message length
                length_bytes = current_socket.recv(4)
                if not length_bytes:
                    break
                
                message_length = int.from_bytes(length_bytes, byteorder="big")
                
                # Receive message data
                chunks = []
                bytes_received = 0
                while bytes_received < message_length:
                    chunk = current_socket.recv(min(message_length - bytes_received, 4096))
                    if not chunk:
                        raise Exception("Connection closed while receiving message")
                    chunks.append(chunk)
                    bytes_received += len(chunk)
                
                message_data = b"".join(chunks)
                message_json = message_data.decode("utf-8")
                message = json.loads(message_json)
                
                # Handle encrypted messages
                if isinstance(message, dict) and message.get("encrypted", False):
                    # Decrypt message
                    iv = base64.b64decode(message["iv"])
                    encrypted_data = base64.b64decode(message["data"])
                    
                    cipher_aes = AES.new(self.session_key, AES.MODE_CBC, iv)
                    decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)
                    message = json.loads(decrypted_data.decode("utf-8"))
                
                # Process message based on type
                self.process_message(message)
            except Exception as e:
                if self.connected:  # Only show error if still connected
                    self.master.after(0, lambda e=e: self.update_chat_display("System", f"Receive error: {str(e)}"))
                    self.master.after(0, self.disconnect)
                break
    
    def process_message(self, message):
        message_type = message.get("type")
        
        if message_type == "key_exchange":
            # Handle key exchange
            partner_key = message.get("public_key")
            partner_username = message.get("username")
            self.master.after(0, lambda: self.complete_key_exchange(partner_key, partner_username))
        
        elif message_type == "session_key":
            # Handle session key reception
            encrypted_session_key = message.get("session_key")
            self.master.after(0, lambda: self.receive_session_key(encrypted_session_key))
        
        elif message_type == "message":
            # Handle chat message
            username = message.get("username")
            content = message.get("content")
            self.master.after(0, lambda: self.update_chat_display(username, content))
        
        elif message_type == "disconnect":
            # Handle disconnect
            username = message.get("username")
            self.master.after(0, lambda: self.update_chat_display("System", f"{username} has disconnected"))
            self.master.after(0, self.disconnect)
    
    def update_chat_display(self, username, message, is_self=False):
        # Enable text widget for editing
        self.chat_display.config(state=tk.NORMAL)
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Format message
        if username == "System":
            formatted_message = f"[{timestamp}] [System] {message}\n"
            self.chat_display.insert(tk.END, formatted_message, "system")
        else:
            if is_self:
                formatted_message = f"[{timestamp}] [You] {message}\n"
                self.chat_display.insert(tk.END, formatted_message, "self")
            else:
                formatted_message = f"[{timestamp}] [{username}] {message}\n"
                self.chat_display.insert(tk.END, formatted_message, "other")
        
        # Add to chat history
        self.chat_history.append({
            "timestamp": timestamp,
            "username": username,
            "message": message,
            "is_self": is_self
        })
        
        # Configure tags
        self.chat_display.tag_configure("system", foreground="#7f8c8d")
        self.chat_display.tag_configure("self", foreground="#2980b9")
        self.chat_display.tag_configure("other", foreground="#16a085")
        
        # Disable text widget and scroll to bottom
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def save_chat_history(self):
        if not self.chat_history:
            messagebox.showinfo("Info", "No chat history to save")
            return
        
        try:
            # Create logs directory if it doesn't exist
            logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
            os.makedirs(logs_dir, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(logs_dir, f"chat_history_{timestamp}.txt")
            
            # Write chat history to file
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=== Secure Chat History ===\n\n")
                for entry in self.chat_history:
                    if entry["username"] == "System":
                        f.write(f"[{entry['timestamp']}] [System] {entry['message']}\n")
                    elif entry["is_self"]:
                        f.write(f"[{entry['timestamp']}] [{self.username}] {entry['message']}\n")
                    else:
                        f.write(f"[{entry['timestamp']}] [{entry['username']}] {entry['message']}\n")
            
            messagebox.showinfo("Success", f"Chat history saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save chat history: {str(e)}")
    
    def clear_chat(self):
        # Clear chat display
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state=tk.DISABLED)
        
        # Keep system messages about connection and encryption in chat history
        self.chat_history = [entry for entry in self.chat_history if entry["username"] == "System" and 
                           ("connection" in entry["message"].lower() or 
                            "encryption" in entry["message"].lower() or
                            "secure" in entry["message"].lower())]
        
        # Re-display system messages
        for entry in self.chat_history:
            self.update_chat_display(entry["username"], entry["message"], entry["is_self"])
    
    def show_about(self):
        about_text = """Secure Chat Application

A demonstration of end-to-end encrypted messaging using:
- RSA for key exchange
- AES-256 for message encryption
- Socket programming for communication

This application is for educational purposes only.

Created as Project 6 for the portfolio."""
        
        messagebox.showinfo("About", about_text)
    
    def show_security_info(self):
        security_text = """Security Information

This application implements end-to-end encryption:

1. Key Exchange:
   - RSA-2048 asymmetric encryption
   - Unique key pair generated for each session

2. Message Encryption:
   - AES-256 symmetric encryption in CBC mode
   - Unique session key for each conversation
   - Messages are padded according to PKCS#7

3. Security Features:
   - Messages cannot be read without the private key
   - New encryption keys for each session
   - No plaintext data transmitted after key exchange

Note: While this implementation demonstrates encryption principles,
it is not intended for sensitive communications."""
        
        messagebox.showinfo("Security Information", security_text)
    
    def exit_app(self):
        # Disconnect if connected
        if self.connected:
            self.disconnect()
        
        # Close application
        self.master.destroy()

def main():
    # Check if required modules are installed
    try:
        import Crypto
    except ImportError:
        print("The PyCryptodome module is required. Please install it using:")
        print("pip install pycryptodome")
        return
    
    root = tk.Tk()
    app = SecureChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.exit_app)
    root.mainloop()

if __name__ == "__main__":
    main()