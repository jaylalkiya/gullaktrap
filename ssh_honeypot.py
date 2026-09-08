"""
SSH Honeypot Module for Freak-Pot
Fully functional SSH server - allows login, command execution, file viewing
Enhanced with verbose logging
Uses Paramiko for real SSH protocol implementation
"""

import socket
from netutil import bind_listener
from threading import Thread
import os
import time

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("WARNING: paramiko not installed. SSH honeypot will have limited functionality.")
    print("Install with: pip install paramiko")

class SSHHoneypot:
    # Vulnerable SSH banner suggestions
    BANNER_SUGGESTIONS = [
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "SSH-2.0-OpenSSH_7.4",
        "SSH-2.0-OpenSSH_5.3",
        "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2",
        "SSH-1.99-OpenSSH_3.9p1",
        "SSH-2.0-libssh-0.7.0",
        "SSH-2.0-dropbear_2014.63",
        "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2",
        "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3",
        "SSH-2.0-Cisco-1.25",
        "SSH-2.0-ROSSSH",
        "SSH-1.5-Cisco-1.25",
    ]
    
    def __init__(self, port=2222, log_callback=None, ssh_banner=None,
                 files_dir=None, session_hooks=None):
        self.port = port
        self.log_callback = log_callback
        self.hooks = session_hooks or {}
        self.server_socket = None
        self.running = False
        self.thread = None
        
        # Custom SSH version banner
        self.ssh_version = ssh_banner or self.BANNER_SUGGESTIONS[0]
        
        # Files directory for fake filesystem
        self.files_dir = files_dir or 'ssh_files'
        self._ensure_files_directory()
        
        # Statistics
        self.total_connections = 0
        self.auth_attempts = 0
        self.successful_auths = 0
        
        # SSH server key
        self.host_key = None
        if PARAMIKO_AVAILABLE:
            self._setup_host_key()
    
    def _ensure_files_directory(self):
        """Ensure files directory exists with some default files"""
        if not os.path.exists(self.files_dir):
            os.makedirs(self.files_dir)
            # Create some default files
            with open(os.path.join(self.files_dir, 'readme.txt'), 'w') as f:
                f.write('SSH Server Files\nWelcome to the honeypot!\n')
            with open(os.path.join(self.files_dir, '.bash_history'), 'w') as f:
                f.write('ls\ncd /var/www\npwd\ncat config.php\n')
    
    def _hook(self, name, *args, **kwargs):
        """Call an optional recorder without letting it break capture."""
        fn = self.hooks.get(name)
        if fn:
            try:
                return fn(*args, **kwargs)
            except Exception:
                return None
        return None

    def _safe_path(self, filename):
        """Resolve filename inside files_dir, or None if it escapes.

        The filename comes from the attacker's shell input, so a bare
        os.path.join would let 'cat ../main.py' read the honeypot's own
        source. realpath also collapses symlinks and absolute paths.
        """
        base = os.path.realpath(self.files_dir)
        target = os.path.realpath(os.path.join(base, filename))
        if target != base and not target.startswith(base + os.sep):
            return None
        return target

    def _setup_host_key(self):
        """Generate or load SSH host key"""
        key_file = 'ssh_host_key.rsa'
        if os.path.exists(key_file):
            self.host_key = paramiko.RSAKey(filename=key_file)
        else:
            # Generate new key
            self.host_key = paramiko.RSAKey.generate(2048)
            self.host_key.write_private_key_file(key_file)
    
    def log_attack(self, attack_type, details):
        """Verbose logging with detailed information"""
        if self.log_callback:
            self.log_callback('ssh', attack_type, details)
    
    def start(self):
        """Start the SSH honeypot server"""
        if not PARAMIKO_AVAILABLE:
            self.log_attack('Startup Error', "Paramiko not installed. SSH honeypot cannot start.")
            raise ImportError("Paramiko required for SSH honeypot. Install with: pip install paramiko")
        
        try:
            self.server_socket = bind_listener(self.port, backlog=5,
                                               protocol='ssh')
            
            self.running = True
            self.thread = Thread(target=self._run_server)
            self.thread.daemon = True
            self.thread.start()
            
            # Verbose startup log
            file_count = len([f for f in os.listdir(self.files_dir) if os.path.isfile(os.path.join(self.files_dir, f))])
            startup_info = (
                f"SSH Honeypot initialized on port {self.port} | "
                f"Banner: '{self.ssh_version}' | "
                f"Protocol: SSH-2.0 | "
                f"Files directory: '{self.files_dir}' | "
                f"Total files in filesystem: {file_count}"
            )
            self.log_attack('Server Started', startup_info)
            self.log_attack('Configuration', f"Listening on 0.0.0.0:{self.port} | Full SSH functionality enabled")
        except Exception as e:
            self.log_attack('Startup Error', f"Failed to start SSH honeypot: {str(e)}")
            raise
    
    def _run_server(self):
        """Run the server and accept connections"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client_socket, address = self.server_socket.accept()
                    self.total_connections += 1
                    
                    conn_info = (
                        f"New SSH connection #{self.total_connections} from {address[0]}:{address[1]} | "
                        f"Time: {time.strftime('%H:%M:%S')}"
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
                    self.log_attack('Server Error', f"Error in main server loop: {str(e)}")
    
    def _handle_client(self, client_socket, address):
        """Handle individual SSH client connection"""
        client_ip = address[0]
        client_port = address[1]
        session_id = f"{client_ip}:{client_port}"
        session_start = time.time()
        # Bound before the try so the finally block can always reference it,
        # even if the transport handshake fails immediately.
        session_db_id = None
        shell_commands = 0

        try:
            # Create SSH transport
            transport = paramiko.Transport(client_socket)
            transport.local_version = self.ssh_version
            transport.add_server_key(self.host_key)
            
            # Create server interface
            session_db_id = self._hook('open_session', session_id, 'ssh',
                                       client_ip, client_port)
            server = SSHServer(session_id, self.log_attack,
                               hook=self._hook, session_db_id=session_db_id,
                               client_ip=client_ip)
            
            try:
                transport.start_server(server=server)
            except Exception as e:
                self.log_attack('Transport Error', f"Session {session_id} | {str(e)}")
                return
            
            # Wait for authentication
            channel = transport.accept(20)
            if channel is None:
                self.log_attack('Auth Timeout', f"Session {session_id} | No channel opened")
                return
            
            self.auth_attempts += server.auth_attempts
            if server.authenticated:
                self.successful_auths += 1
            
            # Handle shell session
            if channel and server.authenticated:
                shell_commands = self._handle_shell(
                    channel, session_id, server.username,
                    session_db_id, client_ip)
            
        except Exception as e:
            self.log_attack('Session Error', f"Session {session_id} | {str(e)}")
        finally:
            try:
                transport.close()
            except:
                pass
            
            session_duration = int(time.time() - session_start)
            summary = (
                f"SSH SESSION CLOSED | {session_id} | "
                f"Duration: {session_duration}s | "
                f"User: {server.username if 'server' in locals() else 'Unknown'} | "
                f"Auth: {server.authenticated if 'server' in locals() else False}"
            )
            self.log_attack('Session Summary', summary)
            if 'server' in locals():
                self._hook('close_session', session_db_id, server.username,
                           server.authenticated, shell_commands)

    def _handle_shell(self, channel, session_id, username,
                      session_db_id=None, client_ip=None):
        """Handle shell commands"""
        channel.send(f"Welcome to Ubuntu 20.04 LTS\r\nLast login: {time.strftime('%a %b %d %H:%M:%S %Y')}\r\n")
        channel.send(f"{username}@honeypot:~$ ")
        
        command_buffer = ""
        commands_executed = 0
        shell_start = time.time()
        last_char = ''
        terminate = False

        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break

                # A real terminal delivers one keystroke per packet, but
                # automated clients -- the attack simulator, worms, and any
                # tool that pastes a whole command -- send the entire line
                # (or several lines) in one recv. Walk the chunk character by
                # character so interactive and scripted input are captured
                # identically.
                for char in data.decode('utf-8', errors='ignore'):
                    # Each keypress is a replay frame; the offset is what lets
                    # playback reproduce the attacker's original typing rhythm.
                    self._hook('keystroke', session_db_id,
                               time.time() - shell_start, char)

                    # Swallow the LF half of a CRLF so one line runs once.
                    if char == '\n' and last_char == '\r':
                        last_char = char
                        continue
                    last_char = char

                    # Handle backspace
                    if char in ('\x7f', '\b'):
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            channel.send('\b \b')
                        continue

                    # Handle enter -> run the accumulated command
                    if char == '\r' or char == '\n':
                        channel.send('\r\n')

                        if command_buffer.strip():
                            commands_executed += 1
                            cmd_log = (
                                f"Session {session_id} | "
                                f"COMMAND EXECUTED | "
                                f"User: {username} | "
                                f"Command #{commands_executed}: '{command_buffer.strip()}'"
                            )
                            self.log_attack('Shell Command', cmd_log)
                            self._hook('command', 'ssh', client_ip,
                                       command_buffer.strip(), session_db_id)

                            # Execute command
                            output = self._execute_command(
                                command_buffer.strip(), session_id,
                                session_db_id=session_db_id,
                                client_ip=client_ip)
                            # `exit` returns None -- honour it instead of
                            # redrawing the prompt forever.
                            if output is None:
                                channel.send('logout\r\n')
                                terminate = True
                                command_buffer = ""
                                break
                            if output:
                                channel.send(output + '\r\n')

                        command_buffer = ""
                        channel.send(f"{username}@honeypot:~$ ")
                        continue

                    # Ignore remaining control characters (Ctrl-C, arrows,
                    # escape sequences) but keep them out of the command.
                    if ord(char) < 32:
                        continue

                    # Printable: echo and buffer.
                    command_buffer += char
                    channel.send(char)

                if terminate:
                    break

            except Exception:
                break
        
        cmd_summary = f"Session {session_id} | Shell closed | Commands executed: {commands_executed}"
        self.log_attack('Shell Closed', cmd_summary)
        return commands_executed
    
    def _execute_command(self, command, session_id,
                         session_db_id=None, client_ip=None):
        """Execute fake shell commands"""
        cmd = command.strip().lower()
        
        # ls command
        if cmd in ['ls', 'ls -la', 'ls -l', 'dir']:
            files = []
            try:
                for filename in os.listdir(self.files_dir):
                    filepath = os.path.join(self.files_dir, filename)
                    if os.path.isfile(filepath):
                        size = os.path.getsize(filepath)
                        files.append(f"-rw-r--r-- 1 root root {size:>8} Jan 01 12:00 {filename}")
            except:
                pass
            return '\r\n'.join(files) if files else "readme.txt\ninfo.txt"
        
        # pwd command
        elif cmd == 'pwd':
            return "/home/" + session_id.split(':')[0]
        
        # whoami command
        elif cmd == 'whoami':
            return "root"
        
        # id command
        elif cmd == 'id':
            return "uid=0(root) gid=0(root) groups=0(root)"
        
        # uname command
        elif cmd.startswith('uname'):
            if '-a' in cmd:
                return "Linux honeypot 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux"
            return "Linux"
        
        # cat command
        elif cmd.startswith('cat '):
            # Slice the original command, not the lowercased copy, so the
            # filename keeps its case on case-sensitive filesystems.
            filename = command.strip()[4:].strip()
            
            file_log = f"Session {session_id} | FILE READ ATTEMPT | File: '{filename}'"
            self.log_attack('File Access', file_log)
            
            filepath = self._safe_path(filename)
            if filepath is None:
                traversal_log = (
                    f"Session {session_id} | "
                    f"PATH TRAVERSAL ATTEMPT | "
                    f"File: '{filename}' | "
                    f"Command: '{command}'"
                )
                self.log_attack('Path Traversal', traversal_log)
                return f"cat: {filename}: No such file or directory"
            
            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                    success_log = f"Session {session_id} | FILE READ SUCCESS | File: '{filename}' | Size: {len(content)} bytes"
                    self.log_attack('File Read', success_log)
                    return content
                except:
                    return f"cat: {filename}: Permission denied"
            return f"cat: {filename}: No such file or directory"
        
        # wget/curl command (malware download attempt)
        elif cmd.startswith('wget ') or cmd.startswith('curl '):
            url = cmd.split()[1] if len(cmd.split()) > 1 else 'unknown'
            malware_log = (
                f"Session {session_id} | "
                f"MALWARE DOWNLOAD ATTEMPT | "
                f"Command: '{command}' | "
                f"URL: '{url}'"
            )
            self.log_attack('Malware Download', malware_log)
            self._hook('payload', url, client_ip, session_db_id,
                       cmd.split()[0])
            return f"Connecting to {url}... failed: Connection refused"
        
        # cd command
        elif cmd.startswith('cd '):
            directory = cmd[3:].strip()
            dir_log = f"Session {session_id} | Directory change to: '{directory}'"
            self.log_attack('Directory Change', dir_log)
            return ""
        
        # rm command (destruction attempt)
        elif cmd.startswith('rm '):
            target = cmd[3:].strip()
            rm_log = (
                f"Session {session_id} | "
                f"DELETE ATTEMPT | "
                f"Target: '{target}' | "
                f"Command: '{command}'"
            )
            self.log_attack('Delete Attempt', rm_log)
            return f"rm: cannot remove '{target}': Permission denied"
        
        # chmod command
        elif cmd.startswith('chmod '):
            chmod_log = f"Session {session_id} | Permission change attempt: '{command}'"
            self.log_attack('Permission Change', chmod_log)
            return ""

        # SSH-key persistence -- dropping a public key into authorized_keys is
        # the classic way to keep access after the password is rotated.
        elif 'authorized_keys' in cmd or cmd.startswith('ssh-keygen'):
            self.log_attack(
                'SSH Key Persistence',
                f"Session {session_id} | PERSISTENCE (ssh authorized_keys) | Command: '{command}'")
            return ""

        # Scheduled-task persistence via cron / systemd.
        elif 'crontab' in cmd or '/etc/cron' in cmd or 'systemctl enable' in cmd:
            self.log_attack(
                'Cron Persistence',
                f"Session {session_id} | PERSISTENCE (scheduled task) | Command: '{command}'")
            return ""

        # Defense evasion -- wiping shell history / disabling logging.
        elif (('history' in cmd and ('-c' in cmd or '-w' in cmd))
              or 'histfile' in cmd or cmd.startswith('unset hist')):
            self.log_attack(
                'History Cleared',
                f"Session {session_id} | DEFENSE EVASION (history cleared) | Command: '{command}'")
            return ""

        # exit/logout
        elif cmd in ['exit', 'logout', 'quit']:
            return None
        
        # Unknown command
        else:
            unknown_log = f"Session {session_id} | Unknown command: '{command}'"
            self.log_attack('Unknown Command', unknown_log)
            return f"bash: {command.split()[0]}: command not found"
    
    def stop(self):
        """Stop the SSH honeypot server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            
            shutdown_info = (
                f"SSH Honeypot stopped on port {self.port} | "
                f"Total connections: {self.total_connections} | "
                f"Auth attempts: {self.auth_attempts} | "
                f"Successful logins: {self.successful_auths}"
            )
            self.log_attack('Server Stopped', shutdown_info)


class SSHServer(paramiko.ServerInterface):
    """SSH Server Interface for handling authentication"""
    
    def __init__(self, session_id, log_callback, hook=None,
                 session_db_id=None, client_ip=None):
        self.session_id = session_id
        self.log_callback = log_callback
        self.hook = hook
        self.session_db_id = session_db_id
        self.client_ip = client_ip
        self.event = None
        self.username = None
        self.password = None
        self.authenticated = False
        self.auth_attempts = 0
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self.auth_attempts += 1
        
        # Log credential attempt
        cred_log = (
            f"Session {self.session_id} | "
            f"AUTH ATTEMPT #{self.auth_attempts} | "
            f"Username: '{username}' | "
            f"Password: '{password}' | "
            f"Password length: {len(password)}"
        )
        self._log('Password Authentication', cred_log)
        
        # Log captured credentials
        capture_log = (
            f"CREDENTIAL CAPTURED | "
            f"Session {self.session_id} | "
            f"Username: '{username}' | "
            f"Password: '{password}'"
        )
        self._log('Credential Capture', capture_log)
        if self.hook:
            self.hook('credential', 'ssh', self.client_ip, username,
                      password, self.session_db_id)
        
        # Always allow login (honeypot accepts all)
        self.authenticated = True
        success_log = f"Session {self.session_id} | Login successful | User: '{username}'"
        self._log('Login Success', success_log)
        
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_publickey(self, username, key):
        self.username = username
        self.auth_attempts += 1
        
        key_log = (
            f"Session {self.session_id} | "
            f"PUBLIC KEY AUTH | "
            f"Username: '{username}' | "
            f"Key type: {key.get_name()} | "
            f"Key fingerprint: {key.get_fingerprint().hex()}"
        )
        self._log('Public Key Auth', key_log)
        
        # Accept key auth too
        self.authenticated = True
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username):
        return 'password,publickey'
    
    def check_channel_shell_request(self, channel):
        self._log('Shell Request', f"Session {self.session_id} | Shell requested by {self.username}")
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self._log('PTY Request', f"Session {self.session_id} | Terminal: {term} | Size: {width}x{height}")
        return True
    
    def _log(self, event_type, details):
        if self.log_callback:
            self.log_callback(event_type, details)


if __name__ == '__main__':
    def test_log(protocol, event_type, details):
        print(f"[{protocol.upper()}] {event_type}: {details}")
    
    honeypot = SSHHoneypot(
        port=2222, 
        log_callback=test_log,
        ssh_banner="SSH-2.0-OpenSSH_5.3",
        files_dir="ssh_files"
    )
    honeypot.start()
    
    print("SSH Honeypot running on port 2222")
    print("Try: ssh -p 2222 root@localhost")
    print("Password: anything")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        honeypot.stop()
        print("\nStopped")