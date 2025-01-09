import json
import socket
import threading
import time
import hashlib
import uuid

class StratumServer:
    def __init__(self, host="0.0.0.0", port=3333):
        self.host = host
        self.port = port
        print(f"Initializing NiceHash Stratum Server on {host}:{port}")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = []
        self.job_id = 0
        self.minimum_difficulty = 500000
        self.verify_connection_timeout = 10
        self.current_prevhash = "0000000000000000000000000000000000000000000000000000000000000000"
        self.current_merkle = "a0602cf9e43106d1b4f9c5076b23cb91ccafd45a5e7ea35c8d0452b9d69bd062"
        self.current_blob = "0707d5efbc1a89f3d03cd13b3c2540b3f7dd7dc40e4b7c7779e9c4ae2c37597b0dd6021cbf6f3c8"
        self.current_height = 0
        self.current_coinbase = "0000000000000000000000000000000000000000000000000000000000000000"
        self.xmrig_algorithms = {
            "scrypt": "scrypt",
            "sha256": "sha256",
            "randomx": "randomx"
        }
        self.xmrig_variants = {
            "0": "standard",
            "1": "lite"
        }
        print("StratumServer initialized successfully")

    def handle_login(self, client_socket, message):
        """Handle login requests from mining clients"""
        try:
            print(f"Raw login message received: {message}")
            
            # Handle standard Stratum mining.authorize
            if message.get('method') == 'mining.authorize':
                response = {
                    "id": message.get('id'),
                    "result": True,
                    "error": None
                }
                self.send_response(client_socket, response)
                return

            # Handle XMRig-style login
            params = message.get('params', {})
            if isinstance(params, dict):
                # First send login response
                login_response = {
                    "id": message.get('id'),
                    "jsonrpc": "2.0",
                    "error": None,
                    "result": {
                        "id": str(uuid.uuid4()),
                        "status": "OK",
                        "extensions": ["algo"],
                        "algo": "scrypt"  # Explicitly tell XMRig we're using Scrypt
                    }
                }
                self.send_response(client_socket, login_response)

                # Then send the first job
                job_response = {
                    "jsonrpc": "2.0",
                    "method": "job",
                    "params": {
                        "blob": self.current_blob,
                        "job_id": str(self.next_job_id()),
                        "target": format(int(0xFFFFFFFFFFFFFFFF / self.minimum_difficulty), '016x'),
                        "height": self.current_height,
                        "seed_hash": self.current_prevhash,
                        "algo": "scrypt"  # Use Scrypt algorithm
                    }
                }
                self.send_response(client_socket, job_response)
                print(f"Sent login response and initial job with difficulty {self.minimum_difficulty}")

        except Exception as e:
            print(f"Login error: {str(e)}")
            error_response = {
                "id": message.get('id'),
                "jsonrpc": "2.0",
                "error": {
                    "code": -1,
                    "message": f"Login failed: {str(e)}"
                }
            }
            self.send_response(client_socket, error_response)

    def create_mining_job(self):
        """Create a NiceHash-compatible Scrypt mining job"""
        job_id = format(self.next_job_id(), '08x')
        
        # Create proper Scrypt mining job parameters
        params = [
            job_id,                                                           # Job ID
            self.current_prevhash,                                           # Previous hash
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff", # Coinbase1
            "ffffffff01ffffff0000000000",                                    # Coinbase2 
            [],                                                              # Merkle branches
            "00000002",                                                      # Version
            "1e0ffff0",                                                      # nBits (difficulty target)
            format(int(time.time()), '08x'),                                # nTime (current timestamp)
            True                                                            # Clean jobs
        ]
        
        print(f"Created Scrypt mining job with params: {params}")
        return params

    def send_mining_job(self, client_socket):
        """Send a new mining job to the client"""
        try:
            params = self.create_mining_job()
            
            # Send proper NiceHash mining.notify
            job = {
                "id": None,
                "method": "mining.notify",
                "params": params
            }
            self.send_response(client_socket, job)
            print(f"Sent Scrypt mining job: {job}")
            
        except Exception as e:
            print(f"Error sending mining job: {str(e)}")

    def send_difficulty(self, client_socket):
        """Send difficulty setting to client"""
        try:
            # Use difficulty that matches our chain parameters
            difficulty_message = {
                "id": None,
                "method": "mining.set_difficulty", 
                "params": [5000000]  # Matches 1e0ffff0 nbits
            }
            self.send_response(client_socket, difficulty_message)
            print(f"Sent difficulty: {difficulty_message}")
            
        except Exception as e:
            print(f"Error sending difficulty: {str(e)}")

    def create_block_header(self, share_data):
        """Create block header from share data for verification"""
        try:
            # Format the block header fields in little-endian
            version = bytes.fromhex("00000002")[::-1]  # Version 2 in little-endian
            prev_hash = bytes.fromhex(self.current_prevhash)[::-1]
            merkle_root = bytes.fromhex(self.current_merkle)[::-1]
            timestamp = int(share_data['timestamp'], 16).to_bytes(4, 'little')
            bits = bytes.fromhex("1e0ffff0")[::-1]  # Standard Scrypt difficulty bits
            nonce = int(share_data['nonce'], 16).to_bytes(4, 'little')

            # Concatenate all fields to create the header
            header = (
                version +
                prev_hash +
                merkle_root +
                timestamp +
                bits +
                nonce
            )
            return header
        except Exception as e:
            print(f"Error creating block header: {str(e)}")
            return None

    def verify_scrypt_share(self, share_data):
        """Verify a submitted Scrypt share"""
        try:
            # Reconstruct block header from share data
            header = self.create_block_header(share_data)
            if not header:
                return False
            
            # For testing, accept all shares while we implement proper verification
            print(f"Share accepted (testing): {share_data}")
            return True
            
            # TODO: Implement actual Scrypt verification
            # import scrypt
            # hash_result = scrypt.hash(header)
            # target = int('0x' + format(int(0xFFFFFFFFFFFFFFFF / self.minimum_difficulty), '016x'), 16)
            # hash_int = int.from_bytes(hash_result, byteorder='little')
            # return hash_int <= target
            
        except Exception as e:
            print(f"Share verification error: {str(e)}")
            return False

    def handle_submit(self, client_socket, message):
        """Handle share submission with Scrypt verification"""
        try:
            # Parse share submission
            params = message.get('params', [])
            if len(params) >= 5:
                worker_name, job_id, nonce, timestamp, nonce2 = params
                
                share_data = {
                    'worker': worker_name,
                    'job_id': job_id,
                    'nonce': nonce,
                    'timestamp': timestamp,
                    'nonce2': nonce2
                }
                
                # Verify the share
                if self.verify_scrypt_share(share_data):
                    response = {
                        "id": message.get('id'),
                        "result": True,
                        "error": None
                    }
                else:
                    response = {
                        "id": message.get('id'),
                        "result": False,
                        "error": [21, "Share rejected", None]
                    }
                self.send_response(client_socket, response)
                
        except Exception as e:
            print(f"Error processing share: {str(e)}")
            error_response = {
                "id": message.get('id'),
                "result": False,
                "error": [20, f"Error processing share: {str(e)}", None]
            }
            self.send_response(client_socket, error_response)

    def send_response(self, client_socket, response):
        """Send JSON response to client"""
        try:
            message = json.dumps(response) + "\n"
            client_socket.send(message.encode())
            print(f"Sent: {message.strip()}")
        except Exception as e:
            print(f"Error sending response: {str(e)}")

    def handle_client(self, client_socket):
        """Handle client connection"""
        client_address = client_socket.getpeername()
        print(f"New client connection from {client_address}")
        
        try:
            buffer = ""
            
            while True:
                data = client_socket.recv(4096)
                if not data:
                    print(f"Client disconnected: {client_address}")
                    break
                
                buffer += data.decode()
                
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    try:
                        message = json.loads(line)
                        print(f"Received message from {client_address}: {message}")
                        
                        method = message.get('method')
                        if not method:
                            print(f"Warning: Message has no method: {message}")
                            continue
                        
                        # Handle NiceHash mining.subscribe
                        if method == 'mining.subscribe':
                            response = {
                                "id": message.get('id'),
                                "result": [
                                    [
                                        ["mining.set_difficulty", ""],
                                        ["mining.notify", ""]
                                    ],
                                    "",  # Subscription ID
                                    4    # Extranonce2 size
                                ],
                                "error": None
                            }
                            self.send_response(client_socket, response)
                            
                            # Send initial difficulty
                            diff_response = {
                                "id": None,
                                "method": "mining.set_difficulty",
                                "params": [self.minimum_difficulty]
                            }
                            self.send_response(client_socket, diff_response)
                            
                            # Send first job
                            self.send_mining_job(client_socket)
                            
                        # Handle NiceHash mining.authorize
                        elif method == 'mining.authorize':
                            response = {
                                "id": message.get('id'),
                                "result": True,
                                "error": None
                            }
                            self.send_response(client_socket, response)
                            
                        # Handle NiceHash mining.submit
                        elif method == 'mining.submit':
                            self.handle_submit(client_socket, message)
                            
                    except json.JSONDecodeError as e:
                        print(f"Failed to decode message: {line}, Error: {e}")
                    except Exception as e:
                        print(f"Error processing message: {str(e)}")
                    
        except Exception as e:
            print(f"Error handling client {client_address}: {str(e)}")
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            client_socket.close()

    def start(self):
        """Start the stratum server"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
        
        # Start job broadcast thread
        broadcast_thread = threading.Thread(target=self.broadcast_jobs)
        broadcast_thread.daemon = True
        broadcast_thread.start()
        
        while True:
            client_socket, addr = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.daemon = True
            client_thread.start()
            self.clients.append(client_socket)
            print(f"Active clients: {len(self.clients)}")

    def broadcast_jobs(self):
        """Periodically broadcast new jobs to all clients"""
        while True:
            time.sleep(30)  # Send new job every 30 seconds
            for client in self.clients[:]:  # Copy list to avoid modification during iteration
                try:
                    self.send_mining_job(client)
                except Exception as e:
                    print(f"Error broadcasting job: {str(e)}")

    def next_job_id(self):
        """Get next unique job ID"""
        self.job_id += 1
        return self.job_id

    def handle_subscribe(self, client_socket, message):
        """Handle subscription request"""
        try:
            # Send subscription response
            response = {
                "id": message.get('id'),
                "result": [
                    [
                        ["mining.set_difficulty", "b4b6693b72a50c7116db18d6497cac52"],
                        ["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"]
                    ],
                    "08000002",
                    4
                ],
                "error": None
            }
            self.send_response(client_socket, response)
            
            # Send initial difficulty
            self.send_difficulty(client_socket)
            
            # Send first job
            self.send_mining_job(client_socket)
            
        except Exception as e:
            print(f"Error in subscribe: {str(e)}")

    def handle_message(self, client_socket, message):
        """Handle incoming stratum messages"""
        try:
            method = message.get("method")
            
            if method == "login":
                params = message["params"]
                # Send XMRig-style response
                response = {
                    "id": message["id"],
                    "jsonrpc": "2.0", 
                    "result": {
                        "id": str(self.next_job_id()),
                        "job": {
                            "blob": "0" * 64,
                            "job_id": str(self.next_job_id()),
                            "target": "b88d0600",
                            "algo": params["algo"][0]  # Use first algo from list
                        },
                        "status": "OK"
                    },
                    "error": None
                }
                self.send_response(client_socket, response)
                
                # Keep connection alive
                self.clients[client_socket] = {
                    "address": params["login"],
                    "worker": params.get("pass", "x"),
                    "difficulty": 500000
                }
                
            elif method == "mining.subscribe":
                self.handle_subscribe(client_socket, message)
            elif method == "mining.authorize":
                self.handle_authorize(client_socket, message)
            elif method == "mining.submit":
                self.handle_submit(client_socket, message)
            elif method == "submit":
                self.handle_submit(client_socket, message)
            else:
                print(f"Unknown method: {method}")
                error_response = {
                    "id": message.get("id"),
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -1,
                        "message": f"Unknown method {method}"
                    },
                    "result": None
                }
                self.send_response(client_socket, error_response)
            
        except Exception as e:
            print(f"Error handling message: {str(e)}")

    def send_xmrig_job(self, client_socket):
        """Send a new mining job in XMRig format"""
        try:
            # Calculate target based on difficulty
            target_hex = format(int(0xFFFFFFFFFFFFFFFF / self.minimum_difficulty), '016x')
            
            job = {
                "jsonrpc": "2.0",
                "method": "job",
                "params": {
                    "blob": self.current_blob,
                    "job_id": str(uuid.uuid4()),
                    "target": target_hex,
                    "height": self.current_height,
                    "seed_hash": self.current_prevhash,
                    "algo": "scrypt"  # Changed from cn/1 to scrypt
                }
            }
            self.send_response(client_socket, job)
            print(f"Sent XMRig job with difficulty {self.minimum_difficulty}")
            
        except Exception as e:
            print(f"Error sending XMRig job: {str(e)}")

if __name__ == "__main__":
    server = StratumServer()
    try:
        print("Starting NiceHash Stratum server...")
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")