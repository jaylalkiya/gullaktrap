"""
FTP Honeypot Module for Freak-Pot
Fully functional FTP server - allows login, viewing, and downloading files
Enhanced with verbose logging
"""

import socket
from netutil import bind_listener
from threading import Thread
import os
import time

class FTPHoneypot:
    # Vulnerable FTP banner suggestions
    BANNER_SUGGESTIONS = [
        "220 Welcome to FreakPot FTP Server (vsFTPd 3.0.3)",
        "220 ProFTPD 1.3.3c Server (Debian)",
        "220 Microsoft FTP Service",
        "220 (vsFTPD 2.3.4)",
        "220 FileZilla Server 0.9.41 beta",
        "220 Pure-FTPd 1.0.36",
        "220 ProFTPD 1.2.10 Server (ProFTPD Default Installation)",
        "220 wu-ftpd 2.6.0",
        "220 WarFTPd 1.65 Ready",
        "220 Serv-U FTP Server v6.4",
        "220 Gene6 FTP Server v3.10.0",
        "220 GlobalSCAPE Secure FTP Server (v3.2)",
    ]
    
    def __init__(self, port=2121, log_callback=None, server_banner=None,
                 files_dir=None, session_hooks=None):
        self.port = port
        self.log_callback = log_callback
        self.hooks = session_hooks or {}
        self.server_socket = None
        self.running = False
        self.thread = None
        
        # Custom banner
        self.server_banner = server_banner or self.BANNER_SUGGESTIONS[0]
        
        # Files directory for fake files
        self.files_dir = files_dir or 'ftp_files'
        self._ensure_files_directory()
        
        # Statistics
        self.total_connections = 0
        self.failed_logins = 0
        self.successful_logins = 0
        self.commands_received = 0
        
        # Data connection tracking
        self.data_connections = {}
    
    def _hook(self, name, *args, **kwargs):
        """Call an optional recorder without letting it break capture."""
        fn = self.hooks.get(name)
        if fn:
            try:
                return fn(*args, **kwargs)
            except Exception:
                return None
        return None

    def _ensure_files_directory(self):
        """Ensure files directory exists with some default files"""
        if not os.path.exists(self.files_dir):
            os.makedirs(self.files_dir)
            # Create some default files
            with open(os.path.join(self.files_dir, 'readme.txt'), 'w') as f:
                f.write('Welcome to the FTP server!\nThis is a honeypot for security research.\n')
            with open(os.path.join(self.files_dir, 'info.txt'), 'w') as f:
                f.write('Server Information\nVersion: 1.0\nLast Updated: 2024\n')
    
    def _get_file_list(self):
        """Get list of files from directory"""
        try:
            files = []
            for filename in os.listdir(self.files_dir):
                filepath = os.path.join(self.files_dir, filename)
                if os.path.isfile(filepath):
                    size = os.path.getsize(filepath)
                    files.append((filename, size))
            return files
        except:
            return [('readme.txt', 1024)]
    
    def log_attack(self, attack_type, details):
        """Verbose logging with detailed information"""
        if self.log_callback:
            self.log_callback('ftp', attack_type, details)
    
    def start(self):
        """Start the FTP honeypot server"""
        try:
            self.server_socket = bind_listener(self.port, backlog=5,
                                               protocol='ftp')
            
            self.running = True
            self.thread = Thread(target=self._run_server)
            self.thread.daemon = True
            self.thread.start()
            
            # Verbose startup log
            files = self._get_file_list()
            startup_info = (
                f"FTP Honeypot initialized on port {self.port} | "
                f"Banner: '{self.server_banner}' | "
                f"Files directory: '{self.files_dir}' | "
                f"Total files available: {len(files)} | "
                f"Files: [{', '.join([f[0] for f in files[:5]])}{'...' if len(files) > 5 else ''}]"
            )
            self.log_attack('Server Started', startup_info)
            self.log_attack('Configuration', f"Listening on 0.0.0.0:{self.port} (all interfaces)")
            self.log_attack('Security Mode', "Honeypot mode active - Full FTP functionality enabled for monitoring")
        except Exception as e:
            self.log_attack('Startup Error', f"Failed to start FTP honeypot: {str(e)} | Port: {self.port}")
            raise
    
    def _run_server(self):
        """Run the server and accept connections"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client_socket, address = self.server_socket.accept()
                    self.total_connections += 1
                    
                    # Verbose connection log
                    conn_info = (
                        f"New connection #{self.total_connections} from {address[0]}:{address[1]} | "
                        f"Socket: {client_socket.fileno()} | "
                        f"Time: {time.strftime('%H:%M:%S')} | "
                        f"Total connections so far: {self.total_connections}"
                    )
                    self.log_attack('Connection Established', conn_info)
                    
                    # Handle client in separate thread
                    client_thread = Thread(target=self._handle_client, args=(client_socket, address))
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
            except Exception as e:
                if self.running:
                    self.log_attack('Server Error', f"Error in main loop: {str(e)}")
    
    def _handle_client(self, client_socket, address):
        """Handle individual FTP client connection with full functionality"""
        client_ip = address[0]
        client_port = address[1]
        session_id = f"{client_ip}:{client_port}"
        username = None
        password = None
        authenticated = False
        commands_in_session = 0
        session_start = time.time()
        current_dir = '/'
        transfer_type = 'A'
        
        # Data connection info
        data_socket = None
        data_mode = None  # 'active' or 'passive'
        pasv_server = None
        
        session_db_id = self._hook('open_session', session_id, 'ftp',
                                   client_ip, client_port)

        try:
            # Send custom welcome banner
            self._send_response(client_socket, self.server_banner)
            self.log_attack('Banner Sent', f"Session {session_id} | Sent banner: '{self.server_banner}'")
            
            while self.running:
                # Receive command
                try:
                    data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    break
                    
                if not data:
                    break
                
                commands_in_session += 1
                self.commands_received += 1
                command = data.upper()
                
                # Verbose command logging
                cmd_log = (
                    f"Session {session_id} | "
                    f"Command #{commands_in_session} | "
                    f"Raw: '{data}' | "
                    f"Auth: {'Yes' if authenticated else 'No'} | "
                    f"User: {username or 'None'}"
                )
                self.log_attack('Command Received', cmd_log)
                
                # Parse FTP commands
                if command.startswith('USER'):
                    username = data.split(' ', 1)[1] if ' ' in data else 'anonymous'
                    user_log = (
                        f"Session {session_id} | "
                        f"Username: '{username}' | "
                        f"IP: {client_ip}"
                    )
                    self.log_attack('Username Provided', user_log)
                    self._send_response(client_socket, '331 Please specify the password.')
                
                elif command.startswith('PASS'):
                    password = data.split(' ', 1)[1] if ' ' in data else ''
                    pass_log = (
                        f"Session {session_id} | "
                        f"User: '{username}' | "
                        f"Password: '{password}' | "
                        f"Length: {len(password)} chars | "
                        f"IP: {client_ip}"
                    )
                    self.log_attack('Password Attempt', pass_log)
                    
                    # Log credentials
                    if username and password:
                        self.successful_logins += 1
                        cred_log = (
                            f"CREDENTIAL CAPTURED | "
                            f"Session {session_id} | "
                            f"Username: '{username}' | "
                            f"Password: '{password}' | "
                            f"IP: {client_ip} | "
                            f"Login #: {self.successful_logins}"
                        )
                        self.log_attack('Credential Capture', cred_log)
                    
                    self._hook('credential', 'ftp', client_ip, username,
                               password, session_db_id)

                    # Allow login (honeypot accepts all credentials)
                    authenticated = True
                    self._send_response(client_socket, '230 Login successful.')
                    self.log_attack('Login Success', f"Session {session_id} | User '{username}' logged in successfully")
                
                elif command == 'SYST':
                    self._send_response(client_socket, '215 UNIX Type: L8')
                    self.log_attack('System Info', f"Session {session_id} | Sent system type")
                
                elif command == 'PWD':
                    self._send_response(client_socket, f'257 "{current_dir}" is the current directory')
                    self.log_attack('Directory Query', f"Session {session_id} | Current dir: {current_dir}")
                
                elif command.startswith('CWD'):
                    directory = data.split(' ', 1)[1] if ' ' in data else '/'
                    # Just acknowledge, we always stay in root
                    current_dir = directory
                    cwd_log = f"Session {session_id} | Changed to: {directory} | IP: {client_ip}"
                    self.log_attack('Directory Change', cwd_log)
                    self._send_response(client_socket, '250 Directory successfully changed.')
                
                elif command.startswith('TYPE'):
                    transfer_type = data.split(' ', 1)[1] if ' ' in data else 'A'
                    self._send_response(client_socket, f'200 Switching to {transfer_type} mode.')
                    self.log_attack('Transfer Type', f"Session {session_id} | Type: {transfer_type}")
                
                elif command == 'PASV':
                    # Enter passive mode - create data socket
                    try:
                        pasv_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        pasv_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        
                        # Bind to the same IP the client connected to
                        server_ip = client_socket.getsockname()[0]
                        pasv_server.bind((server_ip, 0))
                        pasv_server.listen(1)
                        
                        pasv_port = pasv_server.getsockname()[1]
                        p1 = pasv_port // 256
                        p2 = pasv_port % 256
                        
                        # Format IP address correctly for PASV response
                        # Must be exactly: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
                        ip_octets = server_ip.split('.')
                        if len(ip_octets) == 4:
                            pasv_response = f'227 Entering Passive Mode ({ip_octets[0]},{ip_octets[1]},{ip_octets[2]},{ip_octets[3]},{p1},{p2}).'
                        else:
                            # Fallback to localhost
                            pasv_response = f'227 Entering Passive Mode (127,0,0,1,{p1},{p2}).'
                        
                        self._send_response(client_socket, pasv_response)
                        
                        data_mode = 'passive'
                        
                        pasv_log = (
                            f"Session {session_id} | "
                            f"Passive mode enabled | "
                            f"Server IP: {server_ip} | "
                            f"Data port: {pasv_port} | "
                            f"Response: {pasv_response}"
                        )
                        self.log_attack('Passive Mode', pasv_log)
                    except Exception as e:
                        self._send_response(client_socket, '425 Cannot open passive connection.')
                        self.log_attack('Passive Error', f"Session {session_id} | Error: {str(e)}")
                
                elif command == 'LIST' or command.startswith('LIST'):
                    list_log = f"Session {session_id} | Directory listing requested | IP: {client_ip}"
                    self.log_attack('List Request', list_log)
                    
                    # Get file list
                    files = self._get_file_list()
                    
                    # Send over data connection
                    if data_mode == 'passive' and pasv_server:
                        self._send_response(client_socket, '150 Here comes the directory listing.')
                        
                        try:
                            # Accept data connection with timeout
                            pasv_server.settimeout(10.0)
                            data_socket, data_addr = pasv_server.accept()
                            self.log_attack('Data Connection', f"Session {session_id} | Data connection from {data_addr}")
                            
                            # Send file list
                            file_list = '\r\n'.join([
                                f'-rw-r--r-- 1 ftp ftp {size} Jan 01 12:00 {name}' 
                                for name, size in files
                            ]) + '\r\n'
                            
                            data_socket.sendall(file_list.encode())
                            data_socket.close()
                            
                            self._send_response(client_socket, '226 Directory send OK.')
                            self.log_attack('List Sent', f"Session {session_id} | Sent {len(files)} files")
                            
                            pasv_server.close()
                            pasv_server = None
                            data_mode = None
                        except socket.timeout:
                            self._send_response(client_socket, '426 Data connection timed out.')
                            self.log_attack('List Timeout', f"Session {session_id} | Data connection timeout")
                            if pasv_server:
                                pasv_server.close()
                                pasv_server = None
                                data_mode = None
                        except Exception as e:
                            self._send_response(client_socket, '426 Connection closed; transfer aborted.')
                            self.log_attack('List Error', f"Session {session_id} | Error: {str(e)}")
                            if pasv_server:
                                pasv_server.close()
                                pasv_server = None
                                data_mode = None
                    else:
                        self._send_response(client_socket, '425 Use PASV first.')
                        self.log_attack('List No PASV', f"Session {session_id} | LIST without PASV")
                
                elif command.startswith('RETR'):
                    filename = data.split(' ', 1)[1] if ' ' in data else ''
                    retr_log = (
                        f"Session {session_id} | "
                        f"FILE DOWNLOAD | "
                        f"File: '{filename}' | "
                        f"IP: {client_ip}"
                    )
                    self.log_attack('Download Request', retr_log)
                    
                    # Try to read actual file
                    filepath = os.path.join(self.files_dir, os.path.basename(filename))  # Security: prevent path traversal
                    
                    if os.path.exists(filepath) and os.path.isfile(filepath):
                        if data_mode == 'passive' and pasv_server:
                            self._send_response(client_socket, f'150 Opening BINARY mode data connection for {filename}.')
                            
                            try:
                                # Accept data connection with timeout
                                pasv_server.settimeout(10.0)
                                data_socket, data_addr = pasv_server.accept()
                                self.log_attack('Data Connection', f"Session {session_id} | Data connection from {data_addr} for download")
                                
                                # Send file content
                                with open(filepath, 'rb') as f:
                                    file_content = f.read()
                                    data_socket.sendall(file_content)
                                
                                data_socket.close()
                                
                                self._send_response(client_socket, '226 Transfer complete.')
                                self.log_attack('Download Success', f"Session {session_id} | File '{filename}' sent | Size: {len(file_content)} bytes")
                                
                                pasv_server.close()
                                pasv_server = None
                                data_mode = None
                            except socket.timeout:
                                self._send_response(client_socket, '426 Data connection timed out.')
                                self.log_attack('Download Timeout', f"Session {session_id} | Data connection timeout")
                                if pasv_server:
                                    pasv_server.close()
                                    pasv_server = None
                                    data_mode = None
                            except Exception as e:
                                self._send_response(client_socket, '426 Connection closed; transfer aborted.')
                                self.log_attack('Download Error', f"Session {session_id} | Error: {str(e)}")
                                if pasv_server:
                                    pasv_server.close()
                                    pasv_server = None
                                    data_mode = None
                        else:
                            self._send_response(client_socket, '425 Use PASV first.')
                            self.log_attack('Download No PASV', f"Session {session_id} | RETR without PASV")
                    else:
                        self._send_response(client_socket, '550 Failed to open file.')
                        self.log_attack('Download Failed', f"Session {session_id} | File not found: {filename}")
                
                elif command.startswith('STOR'):
                    filename = data.split(' ', 1)[1] if ' ' in data else 'unknown'
                    stor_log = (
                        f"Session {session_id} | "
                        f"FILE UPLOAD ATTEMPT | "
                        f"File: '{filename}' | "
                        f"IP: {client_ip}"
                    )
                    self.log_attack('Upload Attempt', stor_log)
                    self._send_response(client_socket, '553 Could not create file.')
                
                elif command.startswith('DELE'):
                    filename = data.split(' ', 1)[1] if ' ' in data else 'unknown'
                    dele_log = f"Session {session_id} | DELETE ATTEMPT | File: '{filename}' | IP: {client_ip}"
                    self.log_attack('Delete Attempt', dele_log)
                    self._send_response(client_socket, '550 Delete operation failed.')
                
                elif command == 'QUIT':
                    session_duration = int(time.time() - session_start)
                    quit_log = (
                        f"Session {session_id} | "
                        f"Client disconnecting | "
                        f"Duration: {session_duration}s | "
                        f"Commands: {commands_in_session}"
                    )
                    self.log_attack('Graceful Disconnect', quit_log)
                    self._send_response(client_socket, '221 Goodbye.')
                    break
                
                elif command == 'NOOP':
                    self._send_response(client_socket, '200 NOOP ok.')
                    self.log_attack('NOOP', f"Session {session_id} | Keep-alive")
                
                elif command == 'FEAT':
                    # Multi-line response for FEAT
                    self._send_response(client_socket, '211-Features:')
                    self._send_response(client_socket, ' PASV')
                    self._send_response(client_socket, ' SIZE')
                    self._send_response(client_socket, ' MDTM')
                    self._send_response(client_socket, '211 End')
                    self.log_attack('Features', f"Session {session_id} | Sent feature list")
                
                elif command.startswith('SIZE'):
                    filename = data.split(' ', 1)[1] if ' ' in data else ''
                    filepath = os.path.join(self.files_dir, os.path.basename(filename))
                    if os.path.exists(filepath) and os.path.isfile(filepath):
                        size = os.path.getsize(filepath)
                        self._send_response(client_socket, f'213 {size}')
                        self.log_attack('Size Query', f"Session {session_id} | File: {filename} | Size: {size}")
                    else:
                        self._send_response(client_socket, '550 Could not get file size.')
                
                elif command == 'OPTS':
                    # Options command (UTF8 usually)
                    self._send_response(client_socket, '200 OK.')
                    self.log_attack('Options', f"Session {session_id} | Command: {data}")
                
                elif command.startswith('PORT'):
                    # Active mode (we don't support, but acknowledge)
                    self._send_response(client_socket, '200 PORT command successful.')
                    self.log_attack('Active Mode', f"Session {session_id} | Active mode requested (not supported)")
                
                elif command in ['EPSV', 'EPRT']:
                    # Extended passive/active mode
                    self._send_response(client_socket, '500 Command not supported.')
                    self.log_attack('Extended Mode', f"Session {session_id} | {command} requested")
                
                else:
                    unknown_log = f"Session {session_id} | Unknown command: '{data}'"
                    self.log_attack('Unknown Command', unknown_log)
                    self._send_response(client_socket, '500 Unknown command.')
        
        except Exception as e:
            session_duration = int(time.time() - session_start)
            error_log = f"Session {session_id} | Error: {str(e)} | Duration: {session_duration}s"
            self.log_attack('Connection Error', error_log)
        finally:
            # Clean up passive server if still open
            if pasv_server:
                try:
                    pasv_server.close()
                    self.log_attack('Cleanup', f"Session {session_id} | Closed passive server")
                except:
                    pass
            
            # Close client socket
            try:
                client_socket.close()
            except:
                pass
            
            session_duration = int(time.time() - session_start)
            summary = (
                f"SESSION CLOSED | {session_id} | "
                f"Duration: {session_duration}s | "
                f"Commands: {commands_in_session} | "
                f"User: {username or 'None'} | "
                f"Auth: {authenticated}"
            )
            self.log_attack('Session Summary', summary)
            self._hook('close_session', session_db_id, username,
                       authenticated, commands_in_session)

    def _send_response(self, client_socket, message):
        """Send FTP response to client"""
        try:
            # Ensure message ends with CRLF
            if not message.endswith('\r\n'):
                message += '\r\n'
            client_socket.send(message.encode('utf-8'))
        except Exception:
            pass
    
    def stop(self):
        """Stop the FTP honeypot server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            
            shutdown_info = (
                f"FTP Honeypot stopped on port {self.port} | "
                f"Total connections: {self.total_connections} | "
                f"Successful logins: {self.successful_logins} | "
                f"Total commands: {self.commands_received}"
            )
            self.log_attack('Server Stopped', shutdown_info)


if __name__ == '__main__':
    def test_log(protocol, event_type, details):
        print(f"[{protocol.upper()}] {event_type}: {details}")
    
    honeypot = FTPHoneypot(
        port=2121, 
        log_callback=test_log,
        server_banner="220 (vsFTPD 2.3.4)",
        files_dir="ftp_files"
    )
    honeypot.start()
    
    print("FTP Honeypot running on port 2121")
    print("Try: ftp localhost 2121")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        honeypot.stop()
        print("\nStopped")