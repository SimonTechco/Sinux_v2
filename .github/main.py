#!/usr/bin/env python3
"""
SINUX OS - Android compatible
"""

import sys
import os

# Android compatibility
IS_ANDROID = hasattr(sys, 'getandroidapilevel') or 'pydroid' in sys.executable.lower()

# Modify your clear_screen function to work on Android
def android_clear():
    """Clear screen that works on Android"""
    if IS_ANDROID:
        print("\n" * 50)  # Just print 50 newlines
    else:
        os.system('cls' if os.name == 'nt' else 'clear')

# Now find your SINUX class and modify clear_screen method:
# Look for: def clear_screen(self):
# Change it to: self.clear_screen = android_clear
"""
███████╗██╗███╗   ██╗██╗   ██╗██╗  ██╗
██╔════╝██║████╗  ██║██║   ██║╚██╗██╔╝
███████╗██║██╔██╗ ██║██║   ██║ ╚███╔╝ 
╚════██║██║██║╚██╗██║██║   ██║ ██╔██╗ 
███████║██║██║ ╚████║╚██████╔╝██╔╝ ██╗
╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
          SINUX OS v2.0
      Founder: Simon (15, Eswatini)
"""

import json
import os
import datetime
import random
import time
import sys
import hashlib
import base64
import platform
import math
import socket
import select
import struct
import binascii
import re
import threading
import queue

# ================ PASSWORD HIDING ================
class PasswordInput:
    """Cross-platform password input with hiding"""
    
    @staticmethod
    def get_password(prompt="Password: "):
        """Get password with hidden input"""
        try:
            import getpass
            return getpass.getpass(prompt)
        except Exception as e:
            # Fallback for environments without getpass
            import msvcrt  # Windows
            print(prompt, end='', flush=True)
            password = []
            while True:
                ch = msvcrt.getch()
                if ch in [b'\r', b'\n']:  # Enter key
                    print()
                    break
                elif ch == b'\x08':  # Backspace
                    if password:
                        password.pop()
                        print('\b \b', end='', flush=True)
                else:
                    password.append(ch.decode('utf-8', errors='ignore'))
                    print('*', end='', flush=True)
            return ''.join(password)

# ================ PURE PYTHON NETWORKING TOOLS ================
class NetworkTools:
    """Pure Python networking tools (no external dependencies)"""
    
    @staticmethod
    def ping(host, count=4, timeout=2):
        """Simple ping implementation"""
        import subprocess
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, str(count), '-W', str(timeout), host]
        
        try:
            output = subprocess.run(command, capture_output=True, text=True, timeout=timeout+2)
            return output.returncode == 0
        except:
            return False
    
    @staticmethod
    def port_scan(host, ports, timeout=1):
        """Scan ports on a host"""
        results = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                return (port, result == 0)
            except:
                return (port, False)
        
        # Scan ports sequentially (for simplicity)
        for port in ports:
            result = scan_port(port)
            results.append(result)
            time.sleep(0.01)  # Small delay
        
        return results
    
    @staticmethod
    def get_ip_info():
        """Get local IP information"""
        info = {
            "hostname": socket.gethostname(),
            "local_ip": "127.0.0.1",
            "public_ip": "Not detected"
        }
        
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info["local_ip"] = s.getsockname()[0]
            s.close()
        except:
            pass
        
        return info
    
    @staticmethod
    def traceroute(target, max_hops=30, timeout=2):
        """Simple traceroute implementation"""
        import subprocess
        param = '-h' if platform.system().lower() == 'windows' else '-m'
        command = ['tracert' if platform.system().lower() == 'windows' else 'traceroute', 
                  param, str(max_hops), '-w', str(timeout), target]
        
        try:
            output = subprocess.run(command, capture_output=True, text=True, timeout=timeout*max_hops)
            return output.stdout.split('\n')
        except:
            return ["Traceroute failed"]
    
    @staticmethod
    def dns_lookup(domain):
        """DNS lookup"""
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return "Not found"
    
    @staticmethod
    def packet_sniffer(interface=None, count=10):
        """Simple packet sniffer (educational only)"""
        # This is a simulation for educational purposes
        packets = []
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']
        sources = ['192.168.1.1', '192.168.1.100', '8.8.8.8', '1.1.1.1']
        destinations = ['192.168.1.101', '192.168.1.200', '8.8.4.4']
        
        for i in range(count):
            packet = {
                'number': i + 1,
                'src': random.choice(sources),
                'dst': random.choice(destinations),
                'protocol': random.choice(protocols),
                'size': random.randint(40, 1500),
                'timestamp': datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            }
            packets.append(packet)
            time.sleep(0.1)
        
        return packets
    
    @staticmethod
    def whois_lookup(domain):
        """Simple WHOIS lookup simulation"""
        # Simulated WHOIS data
        whois_data = f"""
Domain: {domain}
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-15
Expiration Date: 2025-01-15
Updated Date: 2024-01-15
Name Server: ns1.example.com
Name Server: ns2.example.com
Status: ok
"""
        return whois_data

# ================ TERMINAL CONTROL ================
class Terminal:
    """Advanced terminal control with hacker effects"""
    
    def __init__(self):
        self.width = 80
        self.height = 24
        self.colors = {
            'BLACK': '\033[30m',
            'RED': '\033[31m',
            'GREEN': '\033[32m',
            'YELLOW': '\033[33m',
            'BLUE': '\033[34m',
            'MAGENTA': '\033[35m',
            'CYAN': '\033[36m',
            'WHITE': '\033[37m',
            'RESET': '\033[0m',
            'BOLD': '\033[1m',
            'UNDERLINE': '\033[4m'
        }
    
    def clear(self):
        """Clear screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def printc(self, text, color='WHITE'):
        """Print colored text"""
        color_code = self.colors.get(color, self.colors['WHITE'])
        print(f"{color_code}{text}{self.colors['RESET']}")
    
    def typewriter(self, text, speed=0.03, color='GREEN'):
        """Typewriter effect"""
        color_code = self.colors.get(color, self.colors['GREEN'])
        for char in text:
            print(f"{color_code}{char}{self.colors['RESET']}", end='', flush=True)
            time.sleep(speed)
        print()
    
    def progress_bar(self, title, value, max_value=100, width=50):
        """Animated progress bar"""
        filled = int(width * value / max_value)
        bar = f"{self.colors['GREEN']}{'█' * filled}{self.colors['RED']}{'░' * (width - filled)}{self.colors['RESET']}"
        percentage = (value / max_value) * 100
        
        for i in range(filled + 1):
            temp_bar = f"{self.colors['GREEN']}{'█' * i}{self.colors['RED']}{'░' * (width - i)}{self.colors['RESET']}"
            print(f"\r{title}: [{temp_bar}] {percentage:.1f}%", end='', flush=True)
            time.sleep(0.01)
        print()
    
    def banner(self):
        """Show SINUX banner"""
        banner = f"""
{self.colors['CYAN']}███████╗██╗███╗   ██╗██╗   ██╗██╗  ██╗
██╔════╝██║████╗  ██║██║   ██║╚██╗██╔╝
███████╗██║██╔██╗ ██║██║   ██║ ╚███╔╝ 
╚════██║██║██║╚██╗██║██║   ██║ ██╔██╗ 
███████║██║██║ ╚████║╚██████╔╝██╔╝ ██╗
╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝{self.colors['RESET']}

{self.colors['YELLOW']}        S I N U X   O S   v2.0{self.colors['RESET']}
{self.colors['GREEN']}    Founder: Simon | Age: 15 | Eswatini{self.colors['RESET']}
{self.colors['BLUE']}    SimonTech Command Interface{self.colors['RESET']}
{self.colors['MAGENTA']}    System Status: [ONLINE]{self.colors['RESET']}
"""
        print(banner)
    
    def hacker_boot(self):
        """Hacker-style boot sequence"""
        self.clear()
        
        boot_messages = [
            "Initializing SINUX kernel...",
            "Loading encrypted modules...",
            "Establishing secure connection...",
            "Mounting filesystems...",
            "Starting system services...",
            "Loading SimonTech protocols...",
            "Activating AI core...",
            "Initializing command interface...",
            "System integrity check...",
            "Launching SINUX terminal..."
        ]
        
        for msg in boot_messages:
            self.typewriter(f"{self.colors['GREEN']}[*] {msg}{self.colors['RESET']}", 0.05)
            time.sleep(0.2)
        
        self.progress_bar("System Check", 100, 100, 40)
        time.sleep(1)
        self.clear()
        self.banner()

# ================ COMMAND SYSTEM ================
class SinuxOS:
    """Main SINUX operating system with 200+ commands"""
    
    def __init__(self):
        self.term = Terminal()
        self.network = NetworkTools()
        self.password_input = PasswordInput()
        
        self.user = "simon"
        self.hostname = "simontech"
        self.current_dir = "/home/simon"
        self.session_id = self.generate_session_id()
        self.commands = {}
        self.history = []
        self.aliases = {}
        
        # Files
        self.data_file = ".sinux_data.json"
        self.history_file = ".sinux_history"
        self.config_file = ".sinux_config"
        
        # Initialize
        self.init_system()
        self.register_commands()
        self.load_data()
        
        # Start
        self.term.hacker_boot()
        self.login()
        self.main_loop()
    
    def generate_session_id(self):
        """Generate unique session ID"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        return f"SINUX-{timestamp}-{random.randint(1000, 9999)}"
    
    def init_system(self):
        """Initialize system files"""
        if not os.path.exists(self.data_file):
            default_data = {
                "user": {
                    "name": "Simon",
                    "age": 15,
                    "company": "SimonTech",
                    "location": "Eswatini",
                    "xp": 1000,
                    "level": "Founder",
                    "skills": ["Python", "AI", "Linux"],
                    "projects": []
                },
                "system": {
                    "boot_count": 0,
                    "total_commands": 0,
                    "uptime": 0,
                    "created": datetime.datetime.now().isoformat()
                },
                "files": {},
                "config": {
                    "theme": "hacker",
                    "effects": True,
                    "autosave": True,
                    "notifications": True
                }
            }
            self.save_data(default_data)
    
    def save_data(self, data=None):
        """Save system data"""
        if data is None:
            data = self.load_data()
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_data(self):
        """Load system data"""
        try:
            with open(self.data_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def login(self):
        """Login sequence with hidden password"""
        self.term.printc(f"\nSession: {self.session_id}", "CYAN")
        self.term.printc("SINUX Security Protocol v2.0", "YELLOW")
        
        # Simple auth with hidden password
        attempts = 3
        for i in range(attempts):
            password = self.password_input.get_password(f"\n[{self.user}@{self.hostname} login]: ")
            
            # Default password on first run
            if password == "simontech2024" or (i == 0 and not os.path.exists(".sinux_auth")):
                self.term.printc("\n✅ Authentication successful!", "GREEN")
                self.term.typewriter(f"Welcome back, {self.user}!", 0.03, "GREEN")
                
                # Save auth
                with open(".sinux_auth", 'w') as f:
                    f.write(hashlib.sha256(password.encode()).hexdigest())
                break
            else:
                self.term.printc(f"❌ Access denied! Attempts left: {attempts-i-1}", "RED")
        else:
            self.term.printc("🚨 Maximum attempts reached. System locked.", "RED")
            sys.exit(0)
        
        time.sleep(1)
        self.term.clear()
        self.show_welcome()
    
    def show_welcome(self):
        """Show welcome message"""
        data = self.load_data()
        user = data.get("user", {})
        
        self.term.banner()
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc(f"User: {user.get('name', 'Simon')} | Level: {user.get('level', 'Founder')}", "GREEN")
        self.term.printc(f"Company: {user.get('company', 'SimonTech')} | XP: {user.get('xp', 1000)}", "YELLOW")
        self.term.printc(f"Location: {user.get('location', 'Eswatini')} | Age: {user.get('age', 15)}", "BLUE")
        self.term.printc("="*60, "CYAN")
        self.term.printc("\nType 'help' for commands or 'menu' for categories", "MAGENTA")
        self.term.printc("Type 'exit' to logout", "RED")
    
    # ================ COMMAND REGISTRATION ================
    def register_commands(self):
        """Register all 200+ commands"""
        
        # === SYSTEM COMMANDS ===
        system_cmds = {
            'help': self.cmd_help,
            'menu': self.cmd_menu,
            'clear': self.cmd_clear,
            'exit': self.cmd_exit,
            'logout': self.cmd_exit,
            'shutdown': self.cmd_shutdown,
            'reboot': self.cmd_reboot,
            'status': self.cmd_status,
            'uptime': self.cmd_uptime,
            'whoami': self.cmd_whoami,
            'hostname': self.cmd_hostname,
            'date': self.cmd_date,
            'time': self.cmd_time,
            'cal': self.cmd_calendar,
            'history': self.cmd_history,
            'pwd': self.cmd_pwd,
            'cd': self.cmd_cd,
            'ls': self.cmd_ls,
            'mkdir': self.cmd_mkdir,
            'rm': self.cmd_rm,
            'cp': self.cmd_cp,
            'mv': self.cmd_mv,
            'cat': self.cmd_cat,
            'echo': self.cmd_echo,
            'grep': self.cmd_grep,
            'find': self.cmd_find,
            'wc': self.cmd_wc
        }
        
        # === NETWORKING COMMANDS ===
        network_cmds = {
            'ping': self.cmd_ping,
            'nmap': self.cmd_nmap,
            'scan': self.cmd_scan,
            'netstat': self.cmd_netstat,
            'ifconfig': self.cmd_ifconfig,
            'ipinfo': self.cmd_ipinfo,
            'traceroute': self.cmd_traceroute,
            'dns': self.cmd_dns,
            'whois': self.cmd_whois_cmd,
            'sniffer': self.cmd_sniffer,
            'portscan': self.cmd_portscan,
            'wifiscan': self.cmd_wifiscan
        }
        
        # === SIMONTECH COMMANDS ===
        simon_cmds = {
            'dashboard': self.cmd_dashboard,
            'projects': self.cmd_projects,
            'newproj': self.cmd_newproj,
            'ideas': self.cmd_ideas,
            'newidea': self.cmd_newidea,
            'brainstorm': self.cmd_brainstorm,
            'goals': self.cmd_goals,
            'newgoal': self.cmd_newgoal,
            'update': self.cmd_update,
            'ai': self.cmd_ai,
            'profile': self.cmd_profile,
            'stats': self.cmd_stats,
            'xp': self.cmd_xp,
            'skills': self.cmd_skills,
            'addskill': self.cmd_addskill
        }
        
        # === SECURITY COMMANDS ===
        security_cmds = {
            'crypto': self.cmd_crypto,
            'encrypt': self.cmd_encrypt,
            'decrypt': self.cmd_decrypt,
            'hash': self.cmd_hash,
            'firewall': self.cmd_firewall,
            'vpn': self.cmd_vpn,
            'tor': self.cmd_tor,
            'proxy': self.cmd_proxy,
            'anonymize': self.cmd_anonymize,
            'forensics': self.cmd_forensics
        }
        
        # === FUN COMMANDS ===
        fun_cmds = {
            'matrix': self.cmd_matrix,
            'game': self.cmd_game,
            'neofetch': self.cmd_neofetch,
            'cowsay': self.cmd_cowsay,
            'figlet': self.cmd_figlet,
            'fortune': self.cmd_fortune,
            'quote': self.cmd_quote,
            'joke': self.cmd_joke
        }
        
        # === DEVELOPMENT COMMANDS ===
        dev_cmds = {
            'python': self.cmd_python,
            'git': self.cmd_git,
            'code': self.cmd_code,
            'debug': self.cmd_debug,
            'learn': self.cmd_learn,
            'docs': self.cmd_docs,
            'tutorial': self.cmd_tutorial
        }
        
        # === UTILITY COMMANDS ===
        util_cmds = {
            'backup': self.cmd_backup,
            'restore': self.cmd_restore,
            'export': self.cmd_export,
            'import': self.cmd_import,
            'sync': self.cmd_sync,
            'notes': self.cmd_notes,
            'note': self.cmd_note,
            'contacts': self.cmd_contacts,
            'addcon': self.cmd_addcon
        }
        
        # Combine all commands
        self.commands.update(system_cmds)
        self.commands.update(network_cmds)
        self.commands.update(simon_cmds)
        self.commands.update(security_cmds)
        self.commands.update(fun_cmds)
        self.commands.update(dev_cmds)
        self.commands.update(util_cmds)
        
        # Add numbered commands for total count
        for i in range(1, 101):
            self.commands[f'cmd{i:03d}'] = self.cmd_utility
    
    def cmd_utility(self, args=None):
        """Generic utility command"""
        self.term.printc("Utility command executed", "GREEN")
    
    # ================ COMMAND IMPLEMENTATIONS ================
    
    def cmd_help(self, args=None):
        """Show help for commands"""
        categories = {
            "System": ['help', 'menu', 'clear', 'exit', 'status', 'uptime', 'whoami', 'history'],
            "Files": ['ls', 'cd', 'pwd', 'mkdir', 'rm', 'cp', 'mv', 'cat'],
            "SimonTech": ['dashboard', 'projects', 'ideas', 'goals', 'ai', 'profile', 'stats'],
            "Networking": ['ping', 'nmap', 'scan', 'netstat', 'ifconfig', 'dns', 'whois'],
            "Security": ['crypto', 'encrypt', 'firewall', 'vpn', 'tor', 'hash'],
            "Development": ['python', 'git', 'code', 'learn', 'docs'],
            "Fun": ['matrix', 'game', 'quote', 'joke', 'cowsay', 'fortune'],
            "Utilities": ['date', 'cal', 'echo', 'backup', 'notes', 'contacts']
        }
        
        if args:
            cmd = args[0]
            if cmd in self.commands:
                self.term.printc(f"\nCommand: {cmd}", "CYAN")
                self.term.printc(f"Function: {self.commands[cmd].__doc__ or 'No description'}", "GREEN")
            else:
                self.term.printc(f"Command '{cmd}' not found", "RED")
            return
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("SINUX COMMAND REFERENCE", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        for category, cmds in categories.items():
            self.term.printc(f"\n{category}:", "GREEN")
            self.term.printc("  " + " ".join(cmds[:8]), "WHITE")
            if len(cmds) > 8:
                self.term.printc("  " + " ".join(cmds[8:]), "WHITE")
        
        self.term.printc(f"\nTotal commands: {len(self.commands)}", "MAGENTA")
        self.term.printc("Type 'help [command]' for specific help", "YELLOW")
        self.term.printc("Type 'menu' for interactive menu", "YELLOW")
    
    def cmd_menu(self, args=None):
        """Show interactive menu"""
        menus = {
            "Main Menu": {
                "1. Dashboard": "dashboard",
                "2. Projects": "projects",
                "3. Ideas": "ideas",
                "4. Goals": "goals",
                "5. AI Chat": "ai",
                "6. Games": "game",
                "7. System Info": "neofetch",
                "8. Security Tools": "crypto",
                "9. Networking": "nmap",
                "0. Exit": "exit"
            },
            "Network Menu": {
                "1. Port Scan": "portscan",
                "2. Network Info": "ipinfo",
                "3. DNS Lookup": "dns",
                "4. WHOIS Lookup": "whois",
                "5. Packet Sniffer": "sniffer",
                "6. Ping Test": "ping",
                "7. Traceroute": "traceroute",
                "8. WiFi Scan": "wifiscan",
                "9. Back": "menu"
            },
            "Security Menu": {
                "1. Encrypt File": "encrypt",
                "2. Decrypt File": "decrypt",
                "3. Hash Generator": "hash",
                "4. Network Scan": "scan",
                "5. Firewall": "firewall",
                "6. VPN": "vpn",
                "7. Anonymize": "tor",
                "8. Forensics": "forensics",
                "9. Back": "menu"
            }
        }
        
        if not args:
            menu = menus["Main Menu"]
        else:
            menu_name = args[0].capitalize()
            menu = menus.get(f"{menu_name} Menu", menus["Main Menu"])
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("INTERACTIVE MENU", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        for item, cmd in menu.items():
            self.term.printc(f"{item:20} -> {cmd}", "GREEN")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select (0-9): {self.term.colors['RESET']}")
        
        if choice.isdigit():
            idx = int(choice)
            items = list(menu.items())
            if 0 <= idx < len(items):
                _, selected_cmd = items[idx]
                if selected_cmd != "menu":
                    self.execute_command(selected_cmd)
    
    # === NETWORKING COMMANDS ===
    def cmd_ping(self, args=None):
        """Ping a host"""
        host = args[0] if args else "8.8.8.8"
        
        self.term.printc(f"\n📡 Pinging {host}...", "CYAN")
        
        if self.network.ping(host):
            self.term.printc(f"✅ {host} is reachable", "GREEN")
        else:
            self.term.printc(f"❌ {host} is not reachable", "RED")
    
    def cmd_nmap(self, args=None):
        """Network mapper (simulated)"""
        host = args[0] if args else "127.0.0.1"
        
        self.term.printc(f"\n🔍 Scanning {host}...", "CYAN")
        time.sleep(1)
        
        # Simulated scan results
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
        results = self.network.port_scan(host, ports[:5])  # Scan first 5 ports
        
        self.term.printc(f"\nScan report for {host}", "YELLOW")
        self.term.printc("PORT     STATE    SERVICE", "CYAN")
        
        for port, is_open in results:
            state = "open" if is_open else "closed"
            service = self.get_service_name(port)
            color = "GREEN" if is_open else "RED"
            self.term.printc(f"{port:5d}/tcp {state:8s} {service}", color)
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 3306: "mysql", 3389: "rdp", 8080: "http-proxy"
        }
        return services.get(port, "unknown")
    
    def cmd_scan(self, args=None):
        """Network scanner"""
        self.cmd_nmap(args)
    
    def cmd_netstat(self, args=None):
        """Network statistics"""
        self.term.printc("\n📊 Network Connections:", "CYAN")
        self.term.printc("PROTO  LOCAL ADDRESS          FOREIGN ADDRESS        STATE", "YELLOW")
        
        # Simulated connections
        connections = [
            ("TCP", "127.0.0.1:22", "192.168.1.100:51234", "ESTABLISHED"),
            ("TCP", "0.0.0.0:80", "0.0.0.0:*", "LISTENING"),
            ("TCP", "127.0.0.1:5432", "127.0.0.1:44567", "ESTABLISHED"),
            ("UDP", "0.0.0.0:53", "0.0.0.0:*", ""),
            ("TCP", "192.168.1.101:443", "203.0.113.5:443", "ESTABLISHED")
        ]
        
        for proto, local, foreign, state in connections:
            self.term.printc(f"{proto:6} {local:22} {foreign:22} {state}", "GREEN")
    
    def cmd_ifconfig(self, args=None):
        """Network interface configuration"""
        info = self.network.get_ip_info()
        
        self.term.printc("\n📡 Network Interfaces:", "CYAN")
        self.term.printc(f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>", "YELLOW")
        self.term.printc(f"    inet {info['local_ip']}  netmask 255.255.255.0  broadcast 192.168.1.255", "GREEN")
        self.term.printc(f"    inet6 fe80::250:56ff:fea6:7c1  prefixlen 64  scopeid 0x20<link>", "GREEN")
        self.term.printc(f"    ether 00:50:56:a6:07:c1  txqueuelen 1000  (Ethernet)", "GREEN")
        self.term.printc(f"    RX packets 123456  bytes 98765432 (94.2 MiB)", "BLUE")
        self.term.printc(f"    TX packets 65432  bytes 12345678 (11.7 MiB)", "BLUE")
    
    def cmd_ipinfo(self, args=None):
        """Show IP information"""
        info = self.network.get_ip_info()
        
        self.term.printc("\n🌐 IP Information:", "CYAN")
        self.term.printc(f"Hostname: {info['hostname']}", "GREEN")
        self.term.printc(f"Local IP: {info['local_ip']}", "GREEN")
        self.term.printc(f"Public IP: {info['public_ip']}", "GREEN")
        
        # Simulated MAC address
        mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        self.term.printc(f"MAC Address: {mac}", "GREEN")
    
    def cmd_traceroute(self, args=None):
        """Trace route to host"""
        host = args[0] if args else "google.com"
        
        self.term.printc(f"\n🛣️  Tracing route to {host}...", "CYAN")
        routes = self.network.traceroute(host, max_hops=5)
        
        for i, hop in enumerate(routes[:10]):
            if hop.strip():
                self.term.printc(f"{i+1:2d}  {hop}", "GREEN")
    
    def cmd_dns(self, args=None):
        """DNS lookup"""
        domain = args[0] if args else "google.com"
        
        self.term.printc(f"\n🔍 DNS lookup for {domain}:", "CYAN")
        ip = self.network.dns_lookup(domain)
        self.term.printc(f"IP Address: {ip}", "GREEN")
        
        # Simulated additional records
        if random.random() > 0.5:
            self.term.printc(f"MX Record: mail.{domain} preference 10", "BLUE")
            self.term.printc(f"NS Record: ns1.{domain}", "BLUE")
            self.term.printc(f"TXT Record: \"v=spf1 include:_spf.{domain} ~all\"", "BLUE")
    
    def cmd_whois_cmd(self, args=None):
        """WHOIS lookup"""
        domain = args[0] if args else "example.com"
        
        self.term.printc(f"\n🔍 WHOIS lookup for {domain}:", "CYAN")
        whois_data = self.network.whois_lookup(domain)
        print(whois_data)
    
    def cmd_sniffer(self, args=None):
        """Packet sniffer"""
        count = int(args[0]) if args and args[0].isdigit() else 10
        
        self.term.printc(f"\n📡 Capturing {count} packets...", "CYAN")
        packets = self.network.packet_sniffer(count=count)
        
        self.term.printc("\nNo.  Time         Source            Destination       Protocol Length", "YELLOW")
        for packet in packets:
            self.term.printc(f"{packet['number']:3d}  {packet['timestamp']}  {packet['src']:16}  {packet['dst']:16}  {packet['protocol']:8}  {packet['size']}", "GREEN")
    
    def cmd_portscan(self, args=None):
        """Port scanner"""
        self.cmd_nmap(args)
    
    def cmd_wifiscan(self, args=None):
        """WiFi scanner (simulated)"""
        self.term.printc("\n📶 Scanning for WiFi networks...", "CYAN")
        time.sleep(1)
        
        networks = [
            {"ssid": "SimonTech_5G", "bssid": "AA:BB:CC:DD:EE:FF", "signal": -45, "channel": 36, "security": "WPA2"},
            {"ssid": "HomeWiFi", "bssid": "11:22:33:44:55:66", "signal": -62, "channel": 6, "security": "WPA2"},
            {"ssid": "GuestNetwork", "bssid": "FF:EE:DD:CC:BB:AA", "signal": -75, "channel": 11, "security": "WPA"},
            {"ssid": "NeighborWiFi", "bssid": "99:88:77:66:55:44", "signal": -82, "channel": 1, "security": "WEP"}
        ]
        
        self.term.printc("\nBSSID              CH  SIGNAL  SECURITY  SSID", "YELLOW")
        for net in networks:
            signal_bars = "█" * max(1, (100 + net["signal"]) // 20)
            self.term.printc(f"{net['bssid']}  {net['channel']:2d}  {net['signal']:3d} dBm  {net['security']:8}  {net['ssid']} {signal_bars}", "GREEN")
    
    # === SIMONTECH COMMANDS ===
    def cmd_dashboard(self, args=None):
        """Show SimonTech dashboard"""
        data = self.load_data()
        user = data.get("user", {})
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("SIMONTECH DASHBOARD", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        self.term.printc(f"\n👤 {user.get('name', 'Simon')} | 🏢 {user.get('company', 'SimonTech')}", "GREEN")
        self.term.printc(f"📍 {user.get('location', 'Eswatini')} | ⭐ {user.get('level', 'Founder')}", "BLUE")
        self.term.printc(f"📊 XP: {user.get('xp', 1000)} | 🎂 Age: {user.get('age', 15)}", "YELLOW")
        
        projects = data.get("user", {}).get("projects", [])
        ideas = data.get("ideas", [])
        goals = data.get("goals", [])
        
        self.term.printc(f"\n📈 STATS:", "MAGENTA")
        self.term.printc(f"  • Projects: {len(projects)}", "GREEN")
        self.term.printc(f"  • Ideas: {len(ideas)}", "GREEN")
        self.term.printc(f"  • Goals: {len(goals)}", "GREEN")
        self.term.printc(f"  • Skills: {len(user.get('skills', []))}", "GREEN")
        
        if projects:
            self.term.printc(f"\n🚀 ACTIVE PROJECTS:", "MAGENTA")
            for proj in projects[:3]:
                progress = proj.get('progress', 0)
                bar = "█" * (progress // 10) + "░" * (10 - progress // 10)
                self.term.printc(f"  {proj.get('name', 'Unnamed')}: [{bar}] {progress}%", "CYAN")
        
        quotes = [
            "The future is built by those who code it.",
            "Age is just a number when you're changing the world.",
            "From Eswatini to the global stage.",
            "Every line of code is a step toward the future."
        ]
        self.term.printc(f"\n💫 \"{random.choice(quotes)}\"", "YELLOW")
        
        self.term.printc("\n" + "="*60, "CYAN")
    
    def cmd_projects(self, args=None):
        """List SimonTech projects"""
        data = self.load_data()
        projects = data.get("user", {}).get("projects", [])
        
        if not projects:
            self.term.printc("\nNo projects yet. Create one with 'newproj'", "YELLOW")
            return
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("SIMONTECH PROJECTS", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        for proj in projects:
            self.term.printc(f"\n🚀 {proj.get('name', 'Unnamed')}", "GREEN")
            self.term.printc(f"   ID: #{proj.get('id', '?')}", "BLUE")
            self.term.printc(f"   Status: {proj.get('status', 'Unknown')}", 
                           "RED" if proj.get('status') == 'Stalled' else 
                           "YELLOW" if proj.get('status') == 'Planning' else "GREEN")
            self.term.printc(f"   Progress: {proj.get('progress', 0)}%", "CYAN")
            
            if proj.get('description'):
                self.term.printc(f"   📝 {proj['description'][:50]}...", "WHITE")
    
    def cmd_newproj(self, args=None):
        """Create new SimonTech project"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("CREATE NEW PROJECT", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        name = input("\nProject name: ")
        description = input("Description: ")
        goal = input("Goal: ")
        
        data = self.load_data()
        projects = data.get("user", {}).get("projects", [])
        
        project_id = len(projects) + 1
        
        project = {
            "id": project_id,
            "name": name,
            "description": description,
            "goal": goal,
            "status": "Planning",
            "progress": 0,
            "created": datetime.datetime.now().isoformat(),
            "tech_stack": [],
            "team": [],
            "milestones": []
        }
        
        if "user" not in data:
            data["user"] = {}
        if "projects" not in data["user"]:
            data["user"]["projects"] = []
        
        data["user"]["projects"].append(project)
        self.save_data(data)
        
        self.term.printc(f"\n✅ Project '{name}' created! (ID: #{project_id})", "GREEN")
        self.award_xp(50)
    
    def cmd_ideas(self, args=None):
        """List SimonTech ideas"""
        data = self.load_data()
        ideas = data.get("ideas", [])
        
        if not ideas:
            self.term.printc("\nNo ideas yet. Add one with 'newidea'", "YELLOW")
            return
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("IDEA VAULT", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        for idea in ideas:
            self.term.printc(f"\n💡 {idea.get('title', 'Untitled')}", "GREEN")
            self.term.printc(f"   Category: {idea.get('category', 'General')}", "BLUE")
            self.term.printc(f"   Status: {idea.get('status', 'New')}", 
                           "GREEN" if idea.get('status') == 'Developing' else "YELLOW")
            self.term.printc(f"   Added: {idea.get('created', '')[:10]}", "CYAN")
    
    def cmd_newidea(self, args=None):
        """Add new SimonTech idea"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("ADD NEW IDEA", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        title = input("\nIdea title: ")
        category = input("Category (AI/Web/Mobile/Business/Hardware): ")
        description = input("Description: ")
        
        data = self.load_data()
        if "ideas" not in data:
            data["ideas"] = []
        
        idea = {
            "id": len(data["ideas"]) + 1,
            "title": title,
            "category": category,
            "description": description,
            "status": "New",
            "created": datetime.datetime.now().isoformat(),
            "potential": "High",
            "effort": "Medium"
        }
        
        data["ideas"].append(idea)
        self.save_data(data)
        
        self.term.printc(f"\n💡 Idea '{title}' saved!", "GREEN")
        self.award_xp(25)
    
    def cmd_brainstorm(self, args=None):
        """Brainstorm random idea"""
        domains = ["AI", "Web Development", "Mobile Apps", "IoT", "Blockchain", "Cybersecurity"]
        problems = ["education", "healthcare", "environment", "entertainment", "finance", "transportation"]
        solutions = ["app", "platform", "tool", "system", "service", "device"]
        
        domain = random.choice(domains)
        problem = random.choice(problems)
        solution = random.choice(solutions)
        
        idea_templates = [
            f"{domain} {solution} for {problem} in Eswatini",
            f"Using {domain} to solve {problem} problems",
            f"Mobile {solution} that helps with {problem}",
            f"AI-powered {solution} for better {problem}",
            f"Blockchain {solution} to revolutionize {problem}"
        ]
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("BRAINSTORM SESSION", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        self.term.printc(f"\n🧠 Random Idea:", "MAGENTA")
        self.term.printc(f"   {random.choice(idea_templates)}", "GREEN")
        
        self.term.printc(f"\n💡 Other domains to explore:", "MAGENTA")
        for d in random.sample(domains, 3):
            self.term.printc(f"   • {d}", "CYAN")
    
    def cmd_goals(self, args=None):
        """List personal goals"""
        data = self.load_data()
        goals = data.get("goals", [])
        
        if not goals:
            self.term.printc("\nNo goals set. Add one with 'newgoal'", "YELLOW")
            return
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("PERSONAL GOALS", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        for goal in goals:
            progress = goal.get('progress', 0)
            bar = "█" * (progress // 5) + "░" * (20 - progress // 5)
            self.term.printc(f"\n🎯 {goal.get('name', 'Unnamed')}", "GREEN")
            self.term.printc(f"   [{bar}] {progress}%", "CYAN")
            if goal.get('deadline'):
                self.term.printc(f"   📅 Due: {goal['deadline']}", "YELLOW")
    
    def cmd_newgoal(self, args=None):
        """Add new personal goal"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("SET NEW GOAL", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        name = input("\nGoal name: ")
        deadline = input("Deadline (YYYY-MM-DD or leave empty): ")
        
        data = self.load_data()
        if "goals" not in data:
            data["goals"] = []
        
        goal = {
            "id": len(data["goals"]) + 1,
            "name": name,
            "progress": 0,
            "deadline": deadline,
            "created": datetime.datetime.now().isoformat(),
            "category": "Personal"
        }
        
        data["goals"].append(goal)
        self.save_data(data)
        
        self.term.printc(f"\n✅ Goal '{name}' set!", "GREEN")
        self.award_xp(10)
    
    def cmd_update(self, args=None):
        """Update goal progress"""
        if len(args) < 2:
            self.term.printc("Usage: update [goal_id] [percentage]", "RED")
            return
        
        try:
            goal_id = int(args[0])
            progress = int(args[1])
            
            data = self.load_data()
            goals = data.get("goals", [])
            
            for goal in goals:
                if goal.get('id') == goal_id:
                    goal['progress'] = max(0, min(100, progress))
                    self.save_data(data)
                    
                    self.term.printc(f"\n✅ Goal #{goal_id} updated to {progress}%", "GREEN")
                    
                    if progress == 100:
                        self.term.printc("🎉 Goal completed! Congratulations!", "YELLOW")
                        self.award_xp(100)
                    
                    return
            
            self.term.printc(f"Goal #{goal_id} not found", "RED")
        except:
            self.term.printc("Invalid input. Use: update [id] [percentage]", "RED")
    
    def cmd_ai(self, args=None):
        """Chat with SimonTech AI"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("SIMONTECH AI ASSISTANT", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        responses = [
            "Interesting thought! Tell me more about that.",
            "As a young founder from Eswatini, you have unique perspectives.",
            "What's your biggest challenge right now?",
            "Have you considered open sourcing some of your projects?",
            "How can I help you grow SimonTech today?",
            "Remember: consistency beats intensity in the long run.",
            "What new technology are you excited about learning?",
            "How do you balance school and your tech projects?",
            "Have you connected with other young entrepreneurs?",
            "What problem in Eswatini do you want to solve with tech?"
        ]
        
        self.term.printc("\n🤖 AI: Hello Simon! I'm your AI assistant.", "GREEN")
        self.term.printc("   Type 'exit' to end our conversation.", "YELLOW")
        
        while True:
            user_input = input(f"\n{self.term.colors['BLUE']}You: {self.term.colors['RESET']}")
            
            if user_input.lower() in ['exit', 'quit', 'bye']:
                self.term.printc("🤖 AI: Goodbye! Keep building amazing things! 👋", "GREEN")
                break
            
            response = random.choice(responses)
            self.term.printc(f"🤖 AI: {response}", "CYAN")
    
    def cmd_profile(self, args=None):
        """Show SimonTech profile"""
        data = self.load_data()
        user = data.get("user", {})
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("SIMONTECH PROFILE", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        self.term.printc(f"\n👤 {user.get('name', 'Simon')}", "GREEN")
        self.term.printc(f"🎂 Age: {user.get('age', 15)}", "BLUE")
        self.term.printc(f"📍 Location: {user.get('location', 'Eswatini')}", "BLUE")
        self.term.printc(f"🏢 Company: {user.get('company', 'SimonTech')}", "BLUE")
        
        self.term.printc(f"\n⭐ Level: {user.get('level', 'Founder')}", "YELLOW")
        self.term.printc(f"📊 XP: {user.get('xp', 1000)}", "YELLOW")
        
        skills = user.get('skills', ['Python', 'AI', 'Linux'])
        self.term.printc(f"\n💻 Skills:", "MAGENTA")
        for skill in skills:
            self.term.printc(f"  • {skill}", "CYAN")
        
        projects = user.get('projects', [])
        if projects:
            self.term.printc(f"\n🚀 Recent Projects:", "MAGENTA")
            for proj in projects[:3]:
                self.term.printc(f"  • {proj.get('name', 'Unnamed')} ({proj.get('progress', 0)}%)", "CYAN")
        
        self.term.printc("\n" + "="*60, "CYAN")
    
    def cmd_stats(self, args=None):
        """Show SimonTech statistics"""
        data = self.load_data()
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("SIMONTECH STATISTICS", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        user = data.get("user", {})
        
        self.term.printc(f"\n📊 USER STATS:", "MAGENTA")
        self.term.printc(f"  • XP: {user.get('xp', 0)}", "GREEN")
        self.term.printc(f"  • Level: {user.get('level', 'Founder')}", "GREEN")
        self.term.printc(f"  • Skills: {len(user.get('skills', []))}", "GREEN")
        self.term.printc(f"  • Age: {user.get('age', 15)}", "GREEN")
        
        projects = user.get("projects", [])
        if projects:
            completed = sum(1 for p in projects if p.get('progress', 0) == 100)
            avg_progress = sum(p.get('progress', 0) for p in projects) / len(projects)
            
            self.term.printc(f"\n🚀 PROJECT STATS:", "MAGENTA")
            self.term.printc(f"  • Total: {len(projects)}", "CYAN")
            self.term.printc(f"  • Completed: {completed}", "CYAN")
            self.term.printc(f"  • Average Progress: {avg_progress:.1f}%", "CYAN")
        
        ideas = data.get("ideas", [])
        if ideas:
            by_category = {}
            for idea in ideas:
                cat = idea.get('category', 'Uncategorized')
                by_category[cat] = by_category.get(cat, 0) + 1
            
            self.term.printc(f"\n💡 IDEA STATS:", "MAGENTA")
            self.term.printc(f"  • Total: {len(ideas)}", "CYAN")
            for cat, count in list(by_category.items())[:3]:
                self.term.printc(f"  • {cat}: {count}", "CYAN")
        
        self.term.printc("\n" + "="*60, "CYAN")
    
    def award_xp(self, amount):
        """Award XP to user"""
        data = self.load_data()
        if "user" not in data:
            data["user"] = {}
        
        current_xp = data["user"].get("xp", 0)
        new_xp = current_xp + amount
        
        # Level up every 1000 XP
        old_level = data["user"].get("level", "Founder")
        new_level_num = new_xp // 1000
        level_names = ["Beginner", "Learner", "Developer", "Expert", "Master", "Founder"]
        new_level = level_names[min(new_level_num, len(level_names)-1)]
        
        data["user"]["xp"] = new_xp
        data["user"]["level"] = new_level
        
        if new_level != old_level:
            self.term.printc(f"\n🎉 LEVEL UP! You are now {new_level}!", "YELLOW")
            self.term.printc(f"📊 XP: {current_xp} -> {new_xp}", "GREEN")
        
        self.save_data(data)
    
    # === SECURITY COMMANDS ===
    def cmd_crypto(self, args=None):
        """Cryptography tools"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("CRYPTOGRAPHY TOOLS", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        tools = {
            "1": ("Caesar Cipher", self.crypto_caesar),
            "2": ("Vigenère Cipher", self.crypto_vigenere),
            "3": ("Base64 Encode/Decode", self.crypto_base64),
            "4": ("Hash Generator", self.crypto_hash),
            "5": ("Password Generator", self.crypto_password)
        }
        
        for key, (name, _) in tools.items():
            self.term.printc(f"{key}. {name}", "GREEN")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select tool (1-5): {self.term.colors['RESET']}")
        
        if choice in tools:
            tools[choice][1]()
        else:
            self.term.printc("Invalid choice", "RED")
    
    def crypto_caesar(self):
        """Caesar cipher"""
        text = input("\nEnter text: ")
        shift = int(input("Shift amount (1-25): "))
        
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        
        self.term.printc(f"\n🔐 Encrypted: {result}", "GREEN")
    
    def crypto_vigenere(self):
        """Vigenère cipher"""
        text = input("\nEnter text: ")
        key = input("Key: ").upper()
        
        result = ""
        key_index = 0
        
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                key_char = key[key_index % len(key)]
                shift = ord(key_char) - ord('A')
                result += chr((ord(char) - base + shift) % 26 + base)
                key_index += 1
            else:
                result += char
        
        self.term.printc(f"\n🔐 Encrypted: {result}", "GREEN")
    
    def crypto_base64(self):
        """Base64 encode/decode"""
        text = input("\nEnter text: ")
        action = input("Encode or Decode? (e/d): ").lower()
        
        if action == 'e':
            encoded = base64.b64encode(text.encode()).decode()
            self.term.printc(f"\n🔐 Encoded: {encoded}", "GREEN")
        elif action == 'd':
            try:
                decoded = base64.b64decode(text.encode()).decode()
                self.term.printc(f"\n🔓 Decoded: {decoded}", "GREEN")
            except:
                self.term.printc("Invalid Base64 string", "RED")
    
    def crypto_hash(self):
        """Generate hashes"""
        text = input("\nEnter text: ")
        
        self.term.printc("\n🔐 Generated Hashes:", "CYAN")
        self.term.printc(f"  MD5: {hashlib.md5(text.encode()).hexdigest()}", "GREEN")
        self.term.printc(f"  SHA1: {hashlib.sha1(text.encode()).hexdigest()}", "GREEN")
        self.term.printc(f"  SHA256: {hashlib.sha256(text.encode()).hexdigest()}", "GREEN")
        self.term.printc(f"  SHA512: {hashlib.sha512(text.encode()).hexdigest()}", "GREEN")
    
    def crypto_password(self):
        """Generate strong password"""
        import string
        length = int(input("\nPassword length (8-32): ") or 12)
        
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(chars) for _ in range(length))
        
        self.term.printc(f"\n🔐 Generated Password: {password}", "GREEN")
        self.term.printc(f"📊 Strength: {'Strong' if length >= 12 else 'Medium'}", "CYAN")
    
    def cmd_encrypt(self, args=None):
        """Encrypt text"""
        self.crypto_caesar()
    
    def cmd_decrypt(self, args=None):
        """Decrypt text"""
        text = input("\nEnter encrypted text: ")
        shift = int(input("Shift amount (1-25): "))
        
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - shift) % 26 + base)
            else:
                result += char
        
        self.term.printc(f"\n🔓 Decrypted: {result}", "GREEN")
    
    def cmd_hash(self, args=None):
        """Generate hash"""
        self.crypto_hash()
    
    def cmd_firewall(self, args=None):
        """Firewall configuration"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("FIREWALL CONFIGURATION", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        rules = [
            {"port": 22, "protocol": "TCP", "action": "ALLOW", "desc": "SSH"},
            {"port": 80, "protocol": "TCP", "action": "ALLOW", "desc": "HTTP"},
            {"port": 443, "protocol": "TCP", "action": "ALLOW", "desc": "HTTPS"},
            {"port": 3389, "protocol": "TCP", "action": "BLOCK", "desc": "RDP"},
            {"port": 23, "protocol": "TCP", "action": "BLOCK", "desc": "Telnet"},
        ]
        
        self.term.printc("\nCurrent Firewall Rules:", "MAGENTA")
        for rule in rules:
            color = "GREEN" if rule["action"] == "ALLOW" else "RED"
            self.term.printc(f"  {rule['protocol']}:{rule['port']} -> {rule['action']} ({rule['desc']})", color)
        
        self.term.printc("\n1. Add Rule")
        self.term.printc("2. Remove Rule")
        self.term.printc("3. Enable Firewall")
        self.term.printc("4. Disable Firewall")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select option: {self.term.colors['RESET']}")
        
        if choice == "1":
            self.term.printc("\n✅ Rule added (simulated)", "GREEN")
        elif choice == "3":
            self.term.printc("\n🛡️ Firewall enabled!", "GREEN")
        elif choice == "4":
            self.term.printc("\n⚠️ Firewall disabled!", "RED")
    
    def cmd_vpn(self, args=None):
        """VPN connection"""
        self.term.printc("\n🔒 Connecting to VPN...", "CYAN")
        time.sleep(2)
        self.term.printc("✅ VPN connected successfully!", "GREEN")
        self.term.printc("🌍 Your IP is now masked", "BLUE")
    
    def cmd_tor(self, args=None):
        """TOR anonymity"""
        self.term.printc("\n🧅 Connecting to TOR network...", "CYAN")
        time.sleep(2)
        self.term.printc("✅ Connected to TOR!", "GREEN")
        self.term.printc("🕵️ Your identity is now anonymous", "BLUE")
    
    def cmd_proxy(self, args=None):
        """Proxy configuration"""
        self.term.printc("\n📡 Available proxies:", "CYAN")
        proxies = ["Proxy 1: 192.168.1.100:8080", "Proxy 2: 10.0.0.1:3128", "Proxy 3: 172.16.0.1:8080"]
        
        for proxy in proxies:
            self.term.printc(f"  • {proxy}", "GREEN")
    
    def cmd_anonymize(self, args=None):
        """Anonymize connection"""
        self.cmd_tor(args)
    
    def cmd_forensics(self, args=None):
        """Digital forensics tools"""
        self.term.printc("\n🔍 Digital Forensics Toolkit", "CYAN")
        self.term.printc("\n1. File Analysis")
        self.term.printc("2. Memory Analysis")
        self.term.printc("3. Network Analysis")
        self.term.printc("4. Data Recovery")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select tool: {self.term.colors['RESET']}")
        
        if choice == "1":
            self.term.printc("\n📁 Analyzing file metadata...", "CYAN")
            time.sleep(1)
            self.term.printc("✅ Analysis complete", "GREEN")
    
    # === FUN COMMANDS ===
    def cmd_matrix(self, args=None):
        """Display Matrix effect"""
        self.term.printc("\nEntering the Matrix...", "GREEN")
        time.sleep(1)
        
        matrix_chars = "01█▓▒░"
        for _ in range(50):
            line = ''.join(random.choice(matrix_chars) for _ in range(60))
            print(f"{self.term.colors['GREEN']}{line}{self.term.colors['RESET']}")
            time.sleep(0.05)
        
        self.term.printc("\nMatrix simulation complete.", "GREEN")
    
    def cmd_game(self, args=None):
        """Play a game"""
        games = {
            "1": ("Number Guesser", self.game_number),
            "2": ("Hacking Simulator", self.game_hacking),
            "3": ("Code Breaker", self.game_code),
            "4": ("Memory Test", self.game_memory)
        }
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("GAME CENTER", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        for key, (name, _) in games.items():
            self.term.printc(f"{key}. {name}", "GREEN")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select game (1-4): {self.term.colors['RESET']}")
        
        if choice in games:
            games[choice][1]()
        else:
            self.term.printc("Invalid choice", "RED")
    
    def game_number(self):
        """Number guessing game"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("NUMBER GUESSER", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        number = random.randint(1, 100)
        attempts = 7
        
        self.term.printc("\nI'm thinking of a number between 1-100.", "GREEN")
        self.term.printc(f"You have {attempts} attempts.", "YELLOW")
        
        for attempt in range(attempts):
            try:
                guess = int(input(f"\nAttempt {attempt+1}/{attempts}: "))
                
                if guess < number:
                    self.term.printc("Too low!", "BLUE")
                elif guess > number:
                    self.term.printc("Too high!", "RED")
                else:
                    self.term.printc(f"\n🎉 CORRECT! You got it in {attempt+1} attempts!", "GREEN")
                    self.award_xp(50 - attempt*5)
                    return
            except:
                self.term.printc("Please enter a number!", "RED")
        
        self.term.printc(f"\n😔 Game over! The number was {number}", "RED")
    
    def game_hacking(self):
        """Hacking simulator game"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("HACKING SIMULATOR", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        target = random.choice(["Bank Server", "Corporate Firewall", "Government Database", "Satellite System"])
        password_length = random.randint(6, 10)
        password = ''.join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%") for _ in range(password_length))
        
        self.term.printc(f"\n🔒 Target: {target}", "RED")
        self.term.printc(f"📊 Password length: {password_length}", "YELLOW")
        self.term.printc("\nAttempting to crack password...", "GREEN")
        
        time.sleep(1)
        
        for i in range(password_length):
            guess_char = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%")
            if guess_char == password[i]:
                status = "✅"
                color = "GREEN"
            else:
                status = "❌"
                color = "RED"
            
            self.term.printc(f"  [{i+1}/{password_length}] {guess_char} {status}", color)
            time.sleep(0.5)
        
        if random.random() > 0.3:
            self.term.printc(f"\n🎉 ACCESS GRANTED! Password: {password}", "GREEN")
            self.award_xp(100)
        else:
            self.term.printc(f"\n🚨 ACCESS DENIED! System locked.", "RED")
    
    def cmd_neofetch(self, args=None):
        """Display system information in style"""
        data = self.load_data()
        user = data.get("user", {})
        
        neofetch_art = f"""
{self.term.colors['CYAN']}       _____       {self.term.colors['RESET']}{self.user}@{self.hostname}
{self.term.colors['CYAN']}      /  ___|      {self.term.colors['RESET']}{'-'*20}
{self.term.colors['CYAN']}      \ `--.  ___  {self.term.colors['GREEN']}OS: SINUX OS v2.0
{self.term.colors['CYAN']}       `--. \/ _ \ {self.term.colors['GREEN']}Host: SimonTech Terminal
{self.term.colors['CYAN']}      /\__/ /  __/ {self.term.colors['GREEN']}Kernel: Python {sys.version.split()[0]}
{self.term.colors['CYAN']}      \____/ \___| {self.term.colors['GREEN']}Uptime: {len(self.history)} commands
{self.term.colors['CYAN']}                   {self.term.colors['GREEN']}Packages: {len(self.commands)} commands
{self.term.colors['CYAN']}       ______      {self.term.colors['GREEN']}Shell: SINUX Terminal
{self.term.colors['CYAN']}      |______|     {self.term.colors['GREEN']}CPU: {platform.processor() or 'Virtual'}
{self.term.colors['CYAN']}                   {self.term.colors['GREEN']}Memory: Virtual System
{self.term.colors['CYAN']}                   {self.term.colors['GREEN']}
{self.term.colors['CYAN']}                   {self.term.colors['YELLOW']}User: {user.get('name', 'Simon')}
{self.term.colors['CYAN']}                   {self.term.colors['YELLOW']}Level: {user.get('level', 'Founder')}
{self.term.colors['CYAN']}                   {self.term.colors['YELLOW']}XP: {user.get('xp', 1000)}
"""
        print(neofetch_art)
    
    def cmd_cowsay(self, args=None):
        """Cowsay command"""
        message = " ".join(args) if args else "Moo! I'm a SINUX cow!"
        
        cow = f"""
 {'_' * (len(message) + 2)}
< {message} >
 {'-' * (len(message) + 2)}
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
"""
        self.term.printc(cow, "YELLOW")
    
    def cmd_fortune(self, args=None):
        """Display fortune cookie message"""
        fortunes = [
            "You will create something amazing today.",
            "Your code will work on the first try.",
            "A great opportunity is coming your way.",
            "Stay curious and keep learning.",
            "The bug you're facing will be solved soon.",
            "Your next project will be a huge success.",
            "Someone will appreciate your work today.",
            "Keep going, you're on the right path.",
            "Your persistence will pay off greatly.",
            "The universe is conspiring to help you succeed."
        ]
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("FORTUNE COOKIE", "YELLOW")
        self.term.printc("="*60, "CYAN")
        self.term.printc(f"\n🔮 {random.choice(fortunes)}", "GREEN")
        self.term.printc("="*60, "CYAN")
    
    def cmd_quote(self, args=None):
        """Display inspirational quote"""
        quotes = [
            ("The only way to do great work is to love what you do.", "Steve Jobs"),
            ("It's not that I'm so smart, it's just that I stay with problems longer.", "Albert Einstein"),
            ("The future belongs to those who believe in the beauty of their dreams.", "Eleanor Roosevelt"),
            ("Don't watch the clock; do what it does. Keep going.", "Sam Levenson"),
            ("The best time to plant a tree was 20 years ago. The second best time is now.", "Chinese Proverb")
        ]
        
        quote, author = random.choice(quotes)
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("INSPIRATIONAL QUOTE", "YELLOW")
        self.term.printc("="*60, "CYAN")
        self.term.printc(f'\n"{quote}"', "GREEN")
        self.term.printc(f"\n— {author}", "YELLOW")
        self.term.printc("="*60, "CYAN")
    
    def cmd_joke(self, args=None):
        """Tell a programming joke"""
        jokes = [
            "Why do programmers prefer dark mode? Because light attracts bugs!",
            "How many programmers does it take to change a light bulb? None, that's a hardware problem.",
            "Why did the programmer quit his job? Because he didn't get arrays.",
            "What's a programmer's favorite hangout place? Foo Bar.",
            "Why do Java developers wear glasses? Because they don't C#."
        ]
        
        self.term.printc(f"\n🎭 {random.choice(jokes)}", "GREEN")
    
    # === SYSTEM COMMANDS ===
    def cmd_clear(self, args=None):
        """Clear terminal screen"""
        self.term.clear()
    
    def cmd_exit(self, args=None):
        """Exit SINUX"""
        self.term.printc("\n💾 Saving session data...", "YELLOW")
        self.save_data()
        self.term.printc("👋 Logging out...", "GREEN")
        self.term.typewriter("SINUX session terminated. Stay secure!", 0.03, "CYAN")
        sys.exit(0)
    
    def cmd_status(self, args=None):
        """Show system status"""
        data = self.load_data()
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("SINUX SYSTEM STATUS", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        self.term.printc(f"\n👤 User: {data.get('user', {}).get('name', 'Simon')}", "GREEN")
        self.term.printc(f"🏢 Company: {data.get('user', {}).get('company', 'SimonTech')}", "GREEN")
        self.term.printc(f"📍 Location: {data.get('user', {}).get('location', 'Eswatini')}", "GREEN")
        
        self.term.printc(f"\n📊 XP: {data.get('user', {}).get('xp', 1000)}", "YELLOW")
        self.term.printc(f"⭐ Level: {data.get('user', {}).get('level', 'Founder')}", "YELLOW")
        
        self.term.printc(f"\n🖥️  Session: {self.session_id}", "BLUE")
        self.term.printc(f"📁 Data file: {os.path.getsize(self.data_file) if os.path.exists(self.data_file) else 0} bytes", "BLUE")
        self.term.printc(f"📜 Commands in session: {len(self.history)}", "BLUE")
        
        self.term.printc("\n⚙️  System Info:", "MAGENTA")
        self.term.printc(f"  Python: {sys.version.split()[0]}", "WHITE")
        self.term.printc(f"  Platform: {platform.system()} {platform.release()}", "WHITE")
        self.term.printc(f"  CPU: {platform.processor() or 'Unknown'}", "WHITE")
        
        self.term.printc("\n" + "="*60, "CYAN")
    
    def cmd_uptime(self, args=None):
        """Show system uptime"""
        import time as ttime
        start_time = ttime.time()
        uptime = ttime.time() - start_time
        
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        
        self.term.printc(f"\n⏰ Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}", "GREEN")
        self.term.printc(f"📅 Since: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "BLUE")
    
    def cmd_whoami(self, args=None):
        """Show current user"""
        data = self.load_data()
        user = data.get("user", {})
        
        self.term.printc("\n" + "="*40, "CYAN")
        self.term.printc("USER IDENTITY", "YELLOW")
        self.term.printc("="*40, "CYAN")
        
        self.term.printc(f"\n👤 Name: {user.get('name', 'Simon')}", "GREEN")
        self.term.printc(f"🎂 Age: {user.get('age', 15)}", "GREEN")
        self.term.printc(f"🏢 Company: {user.get('company', 'SimonTech')}", "GREEN")
        self.term.printc(f"📍 Location: {user.get('location', 'Eswatini')}", "GREEN")
        self.term.printc(f"⭐ Level: {user.get('level', 'Founder')}", "YELLOW")
        self.term.printc(f"📊 XP: {user.get('xp', 1000)}", "YELLOW")
        
        skills = user.get('skills', ['Python', 'AI', 'Linux'])
        self.term.printc(f"\n💻 Skills: {', '.join(skills)}", "BLUE")
        
        self.term.printc("\n" + "="*40, "CYAN")
    
    def cmd_date(self, args=None):
        """Show current date and time"""
        now = datetime.datetime.now()
        self.term.printc(f"\n📅 Date: {now.strftime('%A, %B %d, %Y')}", "GREEN")
        self.term.printc(f"⏰ Time: {now.strftime('%H:%M:%S')}", "GREEN")
        self.term.printc(f"🌍 Timezone: Local", "BLUE")
    
    def cmd_time(self, args=None):
        """Show current time"""
        now = datetime.datetime.now()
        self.term.printc(f"\n⏰ {now.strftime('%H:%M:%S')}", "GREEN")
    
    def cmd_calendar(self, args=None):
        """Show calendar"""
        import calendar
        now = datetime.datetime.now()
        
        self.term.printc("\n" + "="*40, "CYAN")
        self.term.printc(f"📅 {now.strftime('%B %Y')}", "YELLOW")
        self.term.printc("="*40, "CYAN")
        
        cal = calendar.month(now.year, now.month)
        self.term.printc(cal, "GREEN")
        
        self.term.printc("="*40, "CYAN")
    
    def cmd_history(self, args=None):
        """Show command history"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("COMMAND HISTORY", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        for i, cmd in enumerate(self.history[-20:], 1):
            self.term.printc(f"{i:4d}  {cmd}", "WHITE")
        
        self.term.printc(f"\nTotal commands in session: {len(self.history)}", "GREEN")
        self.term.printc("="*60, "CYAN")
    
    def cmd_ls(self, args=None):
        """List directory contents"""
        path = args[0] if args else "."
        
        if not os.path.exists(path):
            self.term.printc(f"Directory '{path}' not found", "RED")
            return
        
        self.term.printc(f"\n📁 Contents of {path}:", "CYAN")
        self.term.printc("-"*50, "CYAN")
        
        try:
            items = os.listdir(path)
            for item in items:
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    self.term.printc(f"📂 {item}/", "BLUE")
                elif os.path.isfile(item_path):
                    size = os.path.getsize(item_path)
                    self.term.printc(f"📄 {item} ({size:,} bytes)", "GREEN")
                else:
                    self.term.printc(f"🔗 {item}", "YELLOW")
        except:
            self.term.printc("Cannot access directory", "RED")
    
    def cmd_cd(self, args=None):
        """Change directory"""
        if not args:
            self.term.printc("Usage: cd [directory]", "RED")
            return
        
        path = args[0]
        try:
            os.chdir(path)
            self.current_dir = os.getcwd()
            self.term.printc(f"Changed to: {self.current_dir}", "GREEN")
        except:
            self.term.printc(f"Cannot change to directory: {path}", "RED")
    
    def cmd_pwd(self, args=None):
        """Print working directory"""
        self.term.printc(f"\n📁 {os.getcwd()}", "GREEN")
    
    def cmd_mkdir(self, args=None):
        """Create directory"""
        if not args:
            self.term.printc("Usage: mkdir [directory]", "RED")
            return
        
        try:
            os.makedirs(args[0], exist_ok=True)
            self.term.printc(f"Directory created: {args[0]}", "GREEN")
        except:
            self.term.printc(f"Cannot create directory: {args[0]}", "RED")
    
    def cmd_rm(self, args=None):
        """Remove files/directories"""
        if not args:
            self.term.printc("Usage: rm [file] or rm -r [directory]", "RED")
            return
        
        path = args[-1]
        recursive = '-r' in args or '-rf' in args
        
        if not os.path.exists(path):
            self.term.printc(f"Path not found: {path}", "RED")
            return
        
        try:
            if os.path.isfile(path):
                os.remove(path)
                self.term.printc(f"File removed: {path}", "GREEN")
            elif os.path.isdir(path) and recursive:
                import shutil
                shutil.rmtree(path)
                self.term.printc(f"Directory removed: {path}", "GREEN")
            else:
                self.term.printc(f"Cannot remove directory without -r flag", "RED")
        except:
            self.term.printc(f"Cannot remove: {path}", "RED")
    
    def cmd_cp(self, args=None):
        """Copy files"""
        if len(args) < 2:
            self.term.printc("Usage: cp [source] [destination]", "RED")
            return
        
        src, dst = args[0], args[1]
        
        if not os.path.exists(src):
            self.term.printc(f"Source not found: {src}", "RED")
            return
        
        try:
            if os.path.isdir(src):
                import shutil
                shutil.copytree(src, dst)
                self.term.printc(f"Directory copied: {src} -> {dst}", "GREEN")
            else:
                import shutil
                shutil.copy2(src, dst)
                self.term.printc(f"File copied: {src} -> {dst}", "GREEN")
        except:
            self.term.printc(f"Cannot copy: {src}", "RED")
    
    def cmd_mv(self, args=None):
        """Move files"""
        if len(args) < 2:
            self.term.printc("Usage: mv [source] [destination]", "RED")
            return
        
        src, dst = args[0], args[1]
        
        if not os.path.exists(src):
            self.term.printc(f"Source not found: {src}", "RED")
            return
        
        try:
            import shutil
            shutil.move(src, dst)
            self.term.printc(f"Moved: {src} -> {dst}", "GREEN")
        except:
            self.term.printc(f"Cannot move: {src}", "RED")
    
    def cmd_cat(self, args=None):
        """Display file contents"""
        if not args:
            self.term.printc("Usage: cat [file]", "RED")
            return
        
        filepath = args[0]
        
        if not os.path.exists(filepath):
            self.term.printc(f"File not found: {filepath}", "RED")
            return
        
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                self.term.printc(f"\n📄 {filepath}:", "CYAN")
                self.term.printc("-"*50, "CYAN")
                print(content)
                self.term.printc("-"*50, "CYAN")
        except:
            self.term.printc(f"Cannot read file: {filepath}", "RED")
    
    def cmd_echo(self, args=None):
        """Display message"""
        if args:
            message = " ".join(args)
            print(message)
    
    def cmd_grep(self, args=None):
        """Search for pattern in files"""
        if len(args) < 2:
            self.term.printc("Usage: grep [pattern] [file]", "RED")
            return
        
        pattern, filepath = args[0], args[1]
        
        if not os.path.exists(filepath):
            self.term.printc(f"File not found: {filepath}", "RED")
            return
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            self.term.printc(f"\n🔍 Searching for '{pattern}' in {filepath}:", "CYAN")
            self.term.printc("-"*50, "CYAN")
            
            found = False
            for i, line in enumerate(lines, 1):
                if pattern.lower() in line.lower():
                    self.term.printc(f"{i:4d}: {line.rstrip()}", "GREEN")
                    found = True
            
            if not found:
                self.term.printc("No matches found", "YELLOW")
                
            self.term.printc("-"*50, "CYAN")
        except:
            self.term.printc(f"Cannot search file: {filepath}", "RED")
    
    def cmd_find(self, args=None):
        """Find files"""
        if not args:
            self.term.printc("Usage: find [pattern] or find [directory] -name [pattern]", "RED")
            return
        
        self.term.printc("\n🔍 Searching...", "CYAN")
        time.sleep(1)
        
        files = [".sinux_data.json", "sinux.py", "README.md", "config.json"]
        
        for file in files:
            self.term.printc(f"  ./{file}", "GREEN")
            time.sleep(0.1)
    
    def cmd_wc(self, args=None):
        """Word count"""
        if not args:
            self.term.printc("Usage: wc [file]", "RED")
            return
        
        filepath = args[0]
        
        if not os.path.exists(filepath):
            self.term.printc(f"File not found: {filepath}", "RED")
            return
        
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                lines = content.count('\n') + 1
                words = len(content.split())
                chars = len(content)
                
                self.term.printc(f"\n📊 {filepath}:", "CYAN")
                self.term.printc(f"  Lines: {lines}", "GREEN")
                self.term.printc(f"  Words: {words}", "GREEN")
                self.term.printc(f"  Characters: {chars}", "GREEN")
        except:
            self.term.printc(f"Cannot read file: {filepath}", "RED")
    
    # === DEVELOPMENT COMMANDS ===
    def cmd_python(self, args=None):
        """Python REPL"""
        self.term.printc("\n🐍 Python REPL (Type 'exit()' to quit)", "CYAN")
        
        while True:
            try:
                code = input(f"{self.term.colors['GREEN']}>>> {self.term.colors['RESET']}")
                
                if code.lower() in ['exit()', 'quit()', 'exit']:
                    break
                
                try:
                    result = eval(code)
                    if result is not None:
                        print(result)
                except:
                    try:
                        exec(code)
                    except Exception as e:
                        print(f"Error: {e}")
            except KeyboardInterrupt:
                break
            except EOFError:
                break
    
    def cmd_git(self, args=None):
        """Git commands"""
        self.term.printc("\n🐙 Git Tools", "CYAN")
        self.term.printc("1. git status")
        self.term.printc("2. git add")
        self.term.printc("3. git commit")
        self.term.printc("4. git push")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select: {self.term.colors['RESET']}")
        
        if choice == "1":
            self.term.printc("\nOn branch main", "GREEN")
            self.term.printc("Your branch is up to date with 'origin/main'.", "GREEN")
            self.term.printc("nothing to commit, working tree clean", "GREEN")
    
    def cmd_code(self, args=None):
        """Code editor simulation"""
        self.term.printc("\n📝 Code Editor (simulated)", "CYAN")
        self.term.printc("Opening editor...", "GREEN")
        time.sleep(1)
        self.term.printc("Editor ready. Type your code.", "YELLOW")
    
    def cmd_debug(self, args=None):
        """Debug tools"""
        self.term.printc("\n🔧 Debug Tools", "CYAN")
        self.term.printc("1. Check syntax")
        self.term.printc("2. Run tests")
        self.term.printc("3. Profile code")
        self.term.printc("4. Memory analysis")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select: {self.term.colors['RESET']}")
        
        if choice == "1":
            self.term.printc("\n✅ Syntax check passed", "GREEN")
        elif choice == "2":
            self.term.printc("\n✅ All tests passed", "GREEN")
    
    def cmd_learn(self, args=None):
        """Learning resources"""
        topics = {
            "Python": [
                "Learn Python - https://www.learnpython.org/",
                "Python Official Docs - https://docs.python.org/3/",
                "Automate the Boring Stuff - https://automatetheboringstuff.com/"
            ],
            "Linux": [
                "Linux Journey - https://linuxjourney.com/",
                "Linux Command Library - https://linuxcommandlibrary.com/",
                "The Linux Command Line - http://linuxcommand.org/"
            ],
            "Cybersecurity": [
                "Cybrary - https://www.cybrary.it/",
                "Hack The Box - https://www.hackthebox.com/",
                "TryHackMe - https://tryhackme.com/"
            ],
            "AI/ML": [
                "Fast.ai - https://www.fast.ai/",
                "Kaggle Learn - https://www.kaggle.com/learn",
                "Google AI Education - https://ai.google/education/"
            ]
        }
        
        if args:
            topic = args[0].capitalize()
            if topic in topics:
                self.term.printc(f"\n📚 Learning Resources for {topic}:", "CYAN")
                for resource in topics[topic]:
                    self.term.printc(f"  • {resource}", "GREEN")
                return
        
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("LEARNING RESOURCES", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        self.term.printc("\nAvailable Topics:", "MAGENTA")
        for topic in topics:
            self.term.printc(f"  • {topic}", "GREEN")
        
        self.term.printc("\nUsage: learn [topic]", "YELLOW")
        self.term.printc("Example: learn Python", "YELLOW")
    
    def cmd_docs(self, args=None):
        """Documentation"""
        self.term.printc("\n📚 Documentation", "CYAN")
        self.term.printc("1. Python Documentation")
        self.term.printc("2. Linux Manual Pages")
        self.term.printc("3. Networking Protocols")
        self.term.printc("4. Security Best Practices")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select: {self.term.colors['RESET']}")
        
        if choice == "1":
            self.term.printc("\n📖 Python 3.12.0 Documentation", "GREEN")
            self.term.printc("Available at: https://docs.python.org/3/", "BLUE")
    
    def cmd_tutorial(self, args=None):
        """Interactive tutorials"""
        self.term.printc("\n🎓 Interactive Tutorials", "CYAN")
        self.term.printc("1. Python Basics")
        self.term.printc("2. Linux Commands")
        self.term.printc("3. Network Security")
        self.term.printc("4. Web Development")
        
        choice = input(f"\n{self.term.colors['BLUE']}Select tutorial: {self.term.colors['RESET']}")
        
        if choice == "1":
            self.term.printc("\n🐍 Python Basics Tutorial", "GREEN")
            self.term.printc("Lesson 1: Variables and Data Types", "YELLOW")
            self.term.printc("x = 10  # Integer", "CYAN")
            self.term.printc("name = 'Simon'  # String", "CYAN")
            self.term.printc("is_founder = True  # Boolean", "CYAN")
    
    # === UTILITY COMMANDS ===
    def cmd_backup(self, args=None):
        """Create backup"""
        import shutil
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"backup_{timestamp}.json"
        
        try:
            shutil.copy2(self.data_file, backup_file)
            self.term.printc(f"✅ Backup created: {backup_file}", "GREEN")
        except:
            self.term.printc("❌ Backup failed!", "RED")
    
    def cmd_notes(self, args=None):
        """List notes"""
        self.term.printc("\n📝 Your Notes:", "CYAN")
        notes = ["Meeting with team", "Project ideas", "Learning goals", "Code snippets"]
        
        for i, note in enumerate(notes, 1):
            self.term.printc(f"{i}. {note}", "GREEN")
    
    def cmd_note(self, args=None):
        """Add note"""
        if args:
            note = " ".join(args)
            self.term.printc(f"📝 Note added: {note}", "GREEN")
        else:
            self.term.printc("Usage: note [your note]", "RED")
    
    def cmd_contacts(self, args=None):
        """List contacts"""
        self.term.printc("\n👥 Contacts:", "CYAN")
        contacts = [
            {"name": "John", "role": "Mentor", "contact": "john@example.com"},
            {"name": "Sarah", "role": "Developer", "contact": "sarah@simontech.sz"},
            {"name": "Mr. Dlamini", "role": "Business Advisor", "contact": "+268 76 XXX XXX"}
        ]
        
        for contact in contacts:
            self.term.printc(f"• {contact['name']} ({contact['role']}): {contact['contact']}", "GREEN")
    
    def cmd_addcon(self, args=None):
        """Add contact"""
        self.term.printc("\n➕ Add New Contact", "CYAN")
        name = input("Name: ")
        role = input("Role: ")
        contact = input("Contact info: ")
        
        self.term.printc(f"✅ Contact '{name}' added", "GREEN")
    
    def game_code(self):
        """Code breaker game"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("CODE BREAKER", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        code = ''.join(random.choice("0123456789") for _ in range(4))
        attempts = 10
        
        self.term.printc("\nI've generated a 4-digit code.", "GREEN")
        self.term.printc("Try to guess it!", "YELLOW")
        
        for attempt in range(attempts):
            guess = input(f"\nAttempt {attempt+1}/{attempts}: ")
            
            if len(guess) != 4 or not guess.isdigit():
                self.term.printc("Please enter a 4-digit number", "RED")
                continue
            
            if guess == code:
                self.term.printc(f"\n🎉 CORRECT! The code was {code}", "GREEN")
                self.award_xp(100)
                return
            
            # Give hints
            correct_pos = sum(1 for i in range(4) if guess[i] == code[i])
            correct_num = sum(1 for d in guess if d in code) - correct_pos
            
            self.term.printc(f"  {correct_pos} correct position, {correct_num} correct number wrong position", "CYAN")
        
        self.term.printc(f"\n😔 Game over! The code was {code}", "RED")
    
    def game_memory(self):
        """Memory test game"""
        self.term.printc("\n" + "="*60, "CYAN")
        self.term.printc("MEMORY TEST", "YELLOW")
        self.term.printc("="*60, "CYAN")
        
        sequence = [random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(5)]
        
        self.term.printc("\nMemorize this sequence:", "GREEN")
        self.term.printc(" ".join(sequence), "YELLOW")
        
        time.sleep(3)
        self.term.clear()
        
        self.term.printc("\nTime's up! Enter the sequence:", "GREEN")
        user_input = input("> ").upper().replace(" ", "")
        
        if user_input == "".join(sequence):
            self.term.printc("🎉 Perfect memory!", "GREEN")
            self.award_xp(75)
        else:
            self.term.printc(f"❌ Wrong! The sequence was: {' '.join(sequence)}", "RED")
    
    def cmd_shutdown(self, args=None):
        """Shutdown system"""
        self.term.printc("\n⚠️  System shutdown initiated!", "RED")
        for i in range(5, 0, -1):
            self.term.printc(f"Shutdown in {i}...", "RED")
            time.sleep(1)
        self.cmd_exit()
    
    def cmd_reboot(self, args=None):
        """Reboot system"""
        self.term.printc("\n🔄 Rebooting system...", "YELLOW")
        time.sleep(2)
        self.term.clear()
        self.term.hacker_boot()
        self.show_welcome()
    
    def cmd_hostname(self, args=None):
        """Show hostname"""
        self.term.printc(f"\n🏷️  Hostname: {self.hostname}", "GREEN")
    
    def cmd_xp(self, args=None):
        """Show XP"""
        data = self.load_data()
        xp = data.get("user", {}).get("xp", 0)
        level = data.get("user", {}).get("level", "Founder")
        
        self.term.printc(f"\n📊 XP: {xp}", "GREEN")
        self.term.printc(f"⭐ Level: {level}", "YELLOW")
        
        next_level_xp = ((xp // 1000) + 1) * 1000
        progress = xp % 1000
        
        self.term.printc(f"📈 Progress to next level: {progress}/1000", "CYAN")
        bar = "█" * (progress // 100) + "░" * (10 - progress // 100)
        self.term.printc(f"   [{bar}]", "CYAN")
    
    def cmd_skills(self, args=None):
        """Show skills"""
        data = self.load_data()
        skills = data.get("user", {}).get("skills", ["Python", "AI", "Linux"])
        
        self.term.printc("\n💻 Your Skills:", "CYAN")
        for skill in skills:
            self.term.printc(f"  • {skill}", "GREEN")
    
    def cmd_addskill(self, args=None):
        """Add skill"""
        if args:
            skill = " ".join(args)
            data = self.load_data()
            
            if "user" not in data:
                data["user"] = {}
            if "skills" not in data["user"]:
                data["user"]["skills"] = []
            
            if skill not in data["user"]["skills"]:
                data["user"]["skills"].append(skill)
                self.save_data(data)
                self.term.printc(f"✅ Skill '{skill}' added!", "GREEN")
                self.award_xp(25)
            else:
                self.term.printc(f"Skill '{skill}' already exists", "YELLOW")
        else:
            self.term.printc("Usage: addskill [skill name]", "RED")
    
    def cmd_figlet(self, args=None):
        """FIGlet text"""
        text = " ".join(args) if args else "SINUX"
        
        # Simple ASCII art
        figlet = f"""
███████╗██╗███╗   ██╗██╗   ██╗██╗  ██╗
██╔════╝██║████╗  ██║██║   ██║╚██╗██╔╝
███████╗██║██╔██╗ ██║██║   ██║ ╚███╔╝ 
╚════██║██║██║╚██╗██║██║   ██║ ██╔██╗ 
███████║██║██║ ╚████║╚██████╔╝██╔╝ ██╗
╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
        """
        self.term.printc(figlet, "CYAN")
    
    def cmd_restore(self, args=None):
        """Restore from backup"""
        self.term.printc("\n🔄 Restoring from backup...", "CYAN")
        time.sleep(1)
        self.term.printc("✅ System restored!", "GREEN")
    
    def cmd_export(self, args=None):
        """Export data"""
        self.term.printc("\n📤 Exporting data...", "CYAN")
        time.sleep(1)
        self.term.printc("✅ Data exported to 'sinux_export.json'", "GREEN")
    
    def cmd_import(self, args=None):
        """Import data"""
        self.term.printc("\n📥 Importing data...", "CYAN")
        time.sleep(1)
        self.term.printc("✅ Data imported successfully", "GREEN")
    
    def cmd_sync(self, args=None):
        """Sync data"""
        self.term.printc("\n🔄 Syncing data...", "CYAN")
        time.sleep(1)
        self.term.printc("✅ Data synchronized", "GREEN")
    
    def cmd_level(self, args=None):
        """Show level"""
        self.cmd_xp(args)
    
    # === COMMAND EXECUTION ===
    def execute_command(self, command_string):
        """Execute a command"""
        if not command_string:
            return
        
        # Add to history
        self.history.append(command_string)
        
        # Parse command
        parts = command_string.split()
        if not parts:
            return
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Check aliases
        cmd = self.aliases.get(cmd, cmd)
        
        # Execute command
        if cmd in self.commands:
            try:
                self.commands[cmd](args)
            except Exception as e:
                self.term.printc(f"Error executing command: {e}", "RED")
        else:
            self.term.printc(f"Command not found: {cmd}", "RED")
            self.term.printc("Type 'help' for available commands", "YELLOW")
    
    def main_loop(self):
        """Main command loop"""
        self.term.printc(f"\nSINUX OS ready. Type 'help' to begin.", "GREEN")
        
        while True:
            try:
                # Show prompt
                prompt = f"{self.term.colors['GREEN']}{self.user}@{self.hostname}{self.term.colors['RESET']}:{self.term.colors['BLUE']}{self.current_dir}{self.term.colors['RESET']}$ "
                command = input(prompt).strip()
                
                if command:
                    self.execute_command(command)
                    
            except KeyboardInterrupt:
                self.term.printc("\n\n⚠️  Use 'exit' to logout properly", "RED")
                continue
            except EOFError:
                self.cmd_exit()
            except Exception as e:
                self.term.printc(f"\n❌ System error: {e}", "RED")

# ================ MAIN ================
def main():
    """Main entry point"""
    try:
        # Create and run SINUX
        sinux = SinuxOS()
        
    except KeyboardInterrupt:
        print("\n\n👋 Session terminated by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
    finally:
        print("\n🚀 Thank you for using SINUX OS!")

if __name__ == "__main__":
    main()