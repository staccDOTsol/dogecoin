import json
import socket
import threading
import time
import random

class StratumServer:
    def __init__(self, host="0.0.0.0", port=3333):
        self.host = host
        self.port = port
        print(f"Initializing StratumServer on {host}:{port}")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = []
        self.job_id = 0
        self.minimum_difficulty = 500000
        self.current_difficulty = self.minimum_difficulty
        self.extranonce1_size = 4
        self.extranonce2_size = 4  # Fixed 4-byte extranonce2
        self.extranonce_supported_clients = set()
        self.connection_retries = 3  # Number of retries for failed connections
        self.verify_connection_timeout = 30  # Timeout in seconds
        self.current_job_id = 0  # Add job ID counter
        print("StratumServer initialized successfully")
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Stratum server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"New connection from {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.daemon = True
            client_thread.start()
            self.clients.append(client_socket)
            print(f"Active clients: {len(self.clients)}")

    def handle_client(self, client_socket):
        try:
            # Add connection verification
            if not self.verify_client_connection(client_socket):
                print("Client connection verification failed")
                return
                
            while True:
                data = client_socket.recv(4096)
                if not data:
                    print("Client disconnected - no data received")
                    break
                    
                message = json.loads(data.decode())
                method = message.get('method')
                print(f"Received message with method: {method}")
                
                if method == 'mining.subscribe':
                    print(f"Processing mining.subscribe request from client")
                    self.handle_subscribe(client_socket, message)
                    
                    # Send initial difficulty after subscription
                    self.send_difficulty(client_socket)
                    print(f"Initial difficulty {self.current_difficulty} sent")
                    
                elif method == 'mining.extranonce.subscribe':
                    print("Processing mining.extranonce.subscribe request")
                    self.extranonce_supported_clients.add(client_socket)  # Track this client
                    response = {
                        "id": message['id'],
                        "result": True,
                        "error": None
                    }
                    self.send_response(client_socket, response)
                    print("Extranonce subscription successful")

                elif method == 'mining.authorize':
                    print(f"Processing mining.authorize request from client")
                    params = message.get('params', [])
                    if len(params) < 2:
                        response = {
                            "id": message['id'],
                            "result": False,
                            "error": [-2, "Invalid parameters for authorization", None]
                        }
                    else:
                        username, password = params[:2]
                        # Verify the username is a valid Dogecoin address
                        if self.is_valid_dogecoin_address(username):
                            response = {
                                "id": message['id'],
                                "result": True,
                                "error": None
                            }
                            print(f"Authorization successful for Dogecoin address: {username}")
                        else:
                            response = {
                                "id": message['id'],
                                "result": False,
                                "error": [-2, "Invalid Dogecoin address", None]
                            }
                            print(f"Authorization failed: Invalid Dogecoin address: {username}")
                    
                    self.send_response(client_socket, response)
                    
                    if response["result"]:
                        # Send initial job after successful authorization
                        print("Sending initial mining job")
                        self.send_mining_job(client_socket)

                elif method == 'mining.submit':
                    print(f"Processing share submission from client")
                    params = message.get('params', [])
                    if len(params) >= 5:  # Verify we have all required parameters
                        worker_name, job_id, extranonce2, ntime, nonce = params[:5]
                        # Verify extranonce2 size
                        if len(extranonce2) != self.extranonce2_size * 2:  # *2 because hex encoded
                            response = {
                                "id": message['id'],
                                "result": False,
                                "error": [-2, f"Incorrect extranonce2 size. Expected {self.extranonce2_size*2} got {len(extranonce2)}", None]
                            }
                        else:
                            # Share validation would go here
                            response = {
                                "id": message['id'],
                                "result": True,
                                "error": None
                            }
                            
                            # After successful share, occasionally update extranonce
                            if random.random() < 0.1 and client_socket in self.extranonce_supported_clients:  # 10% chance
                                self.update_client_extranonce(client_socket)
                    else:
                        response = {
                            "id": message['id'],
                            "result": False,
                            "error": [-2, "Invalid parameters", None]
                        }
                    self.send_response(client_socket, response)
                    print("Share processed")
                    
        except socket.timeout:
            print("Client connection timed out")
        except ConnectionResetError:
            print("Client connection was reset")
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
                print(f"Client removed. Remaining clients: {len(self.clients)}")
            client_socket.close()
            print("Client connection closed")

    def send_response(self, client_socket, response):
        response_str = json.dumps(response) + "\n"
        client_socket.send(response_str.encode())
        print(f"Sent response: {response_str.strip()}")

    def send_mining_job(self, client_socket, clean_jobs=True):
        """Send mining job with correct Scrypt parameters"""
        job_id = f"{self.next_job_id():08x}"
        prevhash = "00" * 32  # Previous block hash
        coinbase1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"
        coinbase2 = "ffffffff01"
        merkle_branches = []  # Empty for now
        version = "02000000"  # Scrypt block version
        nbits = "1e0ffff0"   # Difficulty bits
        ntime = f"{int(time.time()):08x}"
        
        notify_params = [
            job_id,                # Job ID
            prevhash,             # prevhash
            coinbase1,            # coinbase1
            coinbase2,            # coinbase2
            merkle_branches,      # merkle branches
            version,              # version
            nbits,                # nbits
            ntime,                # ntime
            clean_jobs            # clean jobs
        ]
        
        message = {
            "id": None,
            "method": "mining.notify",
            "params": notify_params
        }
        
        self.send_response(client_socket, message)
        print(f"Mining job {job_id} sent to client with ntime {ntime}")

    def send_difficulty(self, client_socket):
        difficulty_message = {
            "id": None,
            "method": "mining.set_difficulty",
            "params": [self.current_difficulty]
        }
        self.send_response(client_socket, difficulty_message)

    def get_unique_extranonce1(self):
        # Generate 4-byte extranonce1
        return f"{random.randint(0x10000000, 0xFFFFFFFF):08x}"
        
    def update_client_extranonce(self, client_socket):
        """Update extranonce for a specific client with 4-byte requirement"""
        if client_socket in self.extranonce_supported_clients:
            new_extranonce1 = self.get_unique_extranonce1()
            message = {
                "id": None,
                "method": "mining.set_extranonce",
                "params": [new_extranonce1, self.extranonce2_size]
            }
            self.send_response(client_socket, message)
            print(f"Updated extranonce1 to {new_extranonce1} (4 bytes) for client")
            return new_extranonce1
        return None

    def verify_client_connection(self, client_socket):
        """Verify client connection is valid and stable"""
        try:
            client_socket.settimeout(self.verify_connection_timeout)
            # Send a ping to verify connection
            ping_message = {
                "id": None,
                "method": "mining.ping",
                "params": []
            }
            self.send_response(client_socket, ping_message)
            return True
        except Exception as e:
            print(f"Connection verification failed: {e}")
            return False

    def handle_subscribe(self, client_socket, message):
        """Handle subscription request with proper extranonce format"""
        # Generate 8-character (4-byte) extranonce1
        extranonce1 = f"{random.randint(0, 0xFFFFFFFF):08x}"
        
        subscription_response = {
            "id": message.get("id"),
            "result": [
                [
                    ["mining.set_difficulty", "1"],
                    ["mining.notify", "1"]
                ],
                extranonce1,      # 4-byte hex string
                4                 # Send as integer, not string "04"
            ],
            "error": None
        }
        self.send_response(client_socket, subscription_response)
        self.extranonce_supported_clients.add(client_socket)
        print(f"Subscription response sent with extranonce1: {extranonce1}, extranonce2_size: 4")

    def next_job_id(self):
        """Get next unique job ID"""
        self.current_job_id += 1
        return self.current_job_id
    def is_valid_dogecoin_address(self, address):
        """
        Basic validation for Dogecoin addresses
        Dogecoin addresses can start with 'D' or 'C' and are 34 characters long
        """
        if not address:
            return False
        return True

if __name__ == "__main__":
    server = StratumServer()
    try:
        print("Starting Stratum server...")
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down stratum server...")