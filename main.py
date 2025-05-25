import platform
import os
import time
import json
import ipaddress
import queue
import datetime
from scapy.all import sniff, IP, TCP, UDP
from rich.console import Console, Group
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box
from rich.align import Align
from rich.traceback import install
import threading
import random
import socket
import sys
import select

# Add for input handling within Live
from threading import Event
from queue import Queue

# Install rich traceback handler
install()

# For Windows packet interception
try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    pydivert = None

# Path to firewall rules JSON file
RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall_rules.json")

# Global queues for packet data and actions
packet_queue = queue.Queue(maxsize=100)
rule_action_queue = queue.Queue()

# Communication between input and main thread
input_queue = Queue()
command_history = []
MAX_COMMAND_HISTORY = 10
current_input = ""
input_ready = Event()
input_processed = Event()
command_feedback = ""
command_feedback_color = "green"

# Initialize Rich console
console = Console()

# Global stats
stats = {"blocked": 0, "allowed": 0, "start_time": time.time()}
recent_packets = []
MAX_RECENT_PACKETS = 50

# Rule types and default rule sets
class RuleType:
    IP_BLOCK = "ip_block"
    PORT_BLOCK = "port_block"
    IP_PORT_BLOCK = "ip_port_block"

# Function to load rules from JSON file
def load_rules():
    rules = {
        "blocked_ips": [],
        "blocked_ports": [],
        "ip_port_rules": []
    }
    
    try:
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                rules = json.load(f)
                console.log(f"[green]Loaded {len(rules['blocked_ips'])} IP rules and {len(rules['blocked_ports'])} port rules")
        else:
            # Create default rules file
            save_rules(rules)
            console.log("[yellow]Created new rules file")
    except Exception as e:
        console.log(f"[bold red]Error loading rules: {e}")
    
    return rules

# Function to save rules to JSON file
def save_rules(rules):
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(rules, f, indent=4)
        return True
    except Exception as e:
        console.log(f"[bold red]Error saving rules: {e}")
        return False

# Create a layout for the UI
def create_layout() -> Layout:
    """Define the layout with command input panel and traffic section spanning two rows."""
    layout = Layout(name="root")

    # Main vertical layout split
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="input_area", size=5),  # Command input
        Layout(name="footer", size=3),
    )
    
    # Main area split into columns first
    layout["main"].split_row(
        Layout(name="left_column", ratio=3),
        Layout(name="right_column", ratio=2),
    )
    
    # Right column split into rows - rules and stats
    layout["right_column"].split(
        Layout(name="rules", ratio=2),
        Layout(name="stats", ratio=1),
    )
    
    
    return layout


def update_input_panel():
    """Create the input panel where user can enter commands."""
    global command_feedback, command_feedback_color
    
    # Show command history (most recent entries)
    history_text = ""
    if command_history:
        history_lines = []
        for cmd in command_history[-5:]:  # Show only recent 5 commands
            history_lines.append(f"[dim]{cmd}[/]")
        history_text = "\n".join(history_lines)
    
    # Create command input line with cursor
    input_line = f"[cyan]PyFirewall >[/] {current_input}[blink]_[/]"
    
    # Add feedback from the last command
    feedback = ""
    if command_feedback:
        feedback = f"[{command_feedback_color}]{command_feedback}[/]"
    
    # Combine all elements
    content = []
    if history_text:
        content.append(history_text)
    if feedback:
        content.append(feedback)
    content.append(input_line)
    
    # Create panel with content
    return Panel(
        "\n".join(content),
        title="[bold]Command Input[/]",
        border_style="bright_cyan",
        box=box.ROUNDED
    )

# Update the monitoring panel with actual or simulated traffic
def update_monitoring_panel():
    table = Table(
        title="[bold cyan]Real-time Traffic Monitor[/]",
        box=box.ROUNDED,
        padding=(0, 1),
        show_header=True,
        header_style="bold magenta",
        expand=True
    )
    
    table.add_column("Time", style="dim", width=10)
    table.add_column("Source IP", style="dim", width=15)
    table.add_column("Dest IP", width=15)
    table.add_column("Protocol", width=8)
    table.add_column("Src Port", justify="right", style="green", width=7)
    table.add_column("Dst Port", justify="right", style="green", width=7)
    table.add_column("Action", justify="center", width=8)

    if recent_packets:
        for packet in list(recent_packets)[-14:]:  # Show more packets since we have more space
            time_str = packet.get("time", "")
            src_ip = packet.get("src_ip", "")
            dst_ip = packet.get("dst_ip", "")
            protocol = packet.get("protocol", "")
            src_port = packet.get("src_port", "")
            dst_port = packet.get("dst_port", "")
            action = packet.get("action", "[yellow]UNKNOWN[/]")
            
            table.add_row(
                time_str, 
                src_ip, 
                dst_ip, 
                protocol,
                str(src_port), 
                str(dst_port), 
                action
            )
    else:
        # Generate simulated traffic (increased to fill the larger panel)
        for _ in range(min(18, random.randint(5, 18))):
            src_ip = f"192.168.1.{random.randint(10, 200)}"
            dst_ip = f"{random.randint(1, 200)}.{random.randint(1, 200)}.{random.randint(1, 200)}.{random.randint(1, 200)}"
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            src_port = random.randint(1024, 65535) if protocol in ["TCP", "UDP"] else ""
            dst_port = random.choice([80, 443, 53, 22, 3389, 8080, 8443]) if protocol in ["TCP", "UDP"] else ""
            
            action = random.choice(["[green]ALLOW[/]", "[red]BLOCK[/]"])
            time_str = datetime.datetime.now().strftime("%H:%M:%S")
            
            # Ensure blocked IPs are shown correctly
            if action == "[red]BLOCK[/]" and rules["blocked_ips"] and random.random() < 0.3:
                src_ip = random.choice(rules["blocked_ips"])
            
            table.add_row(
                time_str, 
                src_ip, 
                dst_ip, 
                protocol,
                str(src_port) if src_port else "", 
                str(dst_port) if dst_port else "", 
                action
            )

    # Create a section to show packet details directly below the table
    packet_details = []
    if recent_packets and len(recent_packets) > 0:
        latest_packet = recent_packets[-1]
        packet_details = [
            "\n[bold]Latest Packet Details:[/]",
            f"[cyan]Time:[/] {latest_packet.get('time', 'Unknown')}",
            f"[cyan]Source:[/] {latest_packet.get('src_ip', 'Unknown')}:{latest_packet.get('src_port', '')}",
            f"[cyan]Destination:[/] {latest_packet.get('dst_ip', 'Unknown')}:{latest_packet.get('dst_port', '')}",
            f"[cyan]Protocol:[/] {latest_packet.get('protocol', 'Unknown')}",
            f"[cyan]Size:[/] {latest_packet.get('size', 0)} bytes",
            f"[cyan]Action:[/] {latest_packet.get('action', '[yellow]UNKNOWN[/]')}"
        ]
        
        if latest_packet.get('matched_rule'):
            packet_details.append(f"[cyan]Matched Rule:[/] {latest_packet.get('matched_rule', '')}")
    else:
        packet_details = ["\n[italic]No packet data available yet. Waiting for traffic...[/italic]"]

    # Combine table and details into a single Group
    combined_content = Group(
        table,
        "\n".join(packet_details)
    )

    return Panel(
        combined_content,
        box=box.ROUNDED,
        padding=(1, 1),
        title="[b]Network Traffic Monitor[/b]",
        border_style="bright_blue",
        height=None  # Let it expand to fill available space
    )

# Update the packet details panel
def update_details_panel():
    if not recent_packets:
        return Panel(
            "[i]No packet data available yet. Waiting for traffic...[/i]",
            box=box.ROUNDED,
            padding=(1, 1),
            title="[b]Packet Details[/b]",
            border_style="green"
        )
    
    # Take the most recent packet
    latest_packet = recent_packets[-1]
    
    details = []
    details.append(f"[bold cyan]Time:[/] {latest_packet.get('time', 'Unknown')}")
    details.append(f"[bold cyan]Source:[/] {latest_packet.get('src_ip', 'Unknown')}:{latest_packet.get('src_port', '')}")
    details.append(f"[bold cyan]Destination:[/] {latest_packet.get('dst_ip', 'Unknown')}:{latest_packet.get('dst_port', '')}")
    details.append(f"[bold cyan]Protocol:[/] {latest_packet.get('protocol', 'Unknown')}")
    details.append(f"[bold cyan]Size:[/] {latest_packet.get('size', 0)} bytes")
    details.append(f"[bold cyan]Action:[/] {latest_packet.get('action', '[yellow]UNKNOWN[/]')}")
    
    # Add rule that matched if applicable
    if latest_packet.get('matched_rule'):
        details.append(f"[bold cyan]Matched Rule:[/] {latest_packet.get('matched_rule', '')}")
    
    return Panel(
        "\n".join(details),
        box=box.ROUNDED,
        padding=(1, 1),
        title="[b]Latest Packet Details[/b]",
        border_style="green"
    )

# Update the rules panel
def update_rules_panel():
    # Create a table for IP-based rules
    ip_table = Table(
        title="[bold cyan]IP-Based Rules[/]",
        box=box.SIMPLE,
        padding=(0, 1),
        show_header=True,
        header_style="bold blue",
        expand=True
    )
    
    ip_table.add_column("IP Address", style="dim")
    ip_table.add_column("Status", justify="center")
    ip_table.add_column("Added", justify="right", style="dim")
    
    # Add IP rules
    if not rules["blocked_ips"]:
        ip_table.add_row("[i]No IP rules defined.[/i]", "", "")
    else:
        for ip in rules["blocked_ips"]:
            # In a real app, you'd have timestamps for each rule
            ip_table.add_row(ip, "[red]BLOCKED[/]", "Active")
    
    # Create a table for port-based rules
    port_table = Table(
        title="[bold cyan]Port-Based Rules[/]",
        box=box.SIMPLE,
        padding=(0, 1),
        show_header=True,
        header_style="bold blue",
        expand=True
    )
    
    port_table.add_column("Port", style="dim")
    port_table.add_column("Protocol", justify="center")
    port_table.add_column("Status", justify="center")
    
    # Add port rules
    if not rules["blocked_ports"]:
        port_table.add_row("[i]No port rules defined.[/i]", "", "")
    else:
        for port in rules["blocked_ports"]:
            # Assuming port is stored as "port/protocol"
            if "/" in str(port):
                port_num, protocol = port.split("/")
            else:
                port_num, protocol = port, "ALL"
            port_table.add_row(str(port_num), protocol, "[red]BLOCKED[/]")
    
    # Instructions for rule management
    instructions = Text.assemble(
        ("Rule Management Commands:", "bold yellow"),
        "\n• add-ip <ip>: Block an IP address",
        "\n• add-port <port>[/protocol]: Block a port",
        "\n• remove-ip <ip>: Unblock an IP",
        "\n• remove-port <port>[/protocol]: Unblock a port",
        "\n• list: Show all rules",
        "\n• help: Show command help",
        "\n• exit: Exit rule management",
        style="dim"
    )

    combined_content = Group(
        ip_table,
        "\n",  # Add spacing
        port_table,
        "\n",  # Add spacing
        instructions
    )
    
    return Panel(
        combined_content,
        box=box.ROUNDED,
        padding=(1, 1),
        title="[b]Firewall Rules[/b]",
        border_style="bright_green",
    )

# Update the stats panel
def update_stats_panel():
    uptime = int(time.time() - stats["start_time"])
    uptime_str = f"{uptime // 3600:02d}:{(uptime % 3600) // 60:02d}:{uptime % 60:02d}"
    
    stats_content = [
        f"[bold]Uptime:[/] {uptime_str}",
        f"[bold]Packets Processed:[/] {stats['blocked'] + stats['allowed']}",
        f"[red]Packets Blocked:[/] {stats['blocked']}",
        f"[green]Packets Allowed:[/] {stats['allowed']}",
        f"[bold]Block Rate:[/] {calculate_block_rate():.1f}%"
    ]
    
    # Add system info
    stats_content.extend([
        "",
        f"[bold]System:[/] {platform.system()} {platform.release()}",
        f"[bold]Hostname:[/] {socket.gethostname()}"
    ])
    
    # Add PyDivert status for Windows
    if platform.system() == "Windows":
        divert_status = "[green]Available[/]" if PYDIVERT_AVAILABLE else "[red]Not Available[/]"
        stats_content.append(f"[bold]WinDivert:[/] {divert_status}")
    
    return Panel(
        "\n".join(stats_content),
        box=box.ROUNDED,
        padding=(1, 2),  # Increased horizontal padding
        title="[b]Firewall Statistics[/b]",
        border_style="yellow",
        height=None  # Let panel expand to fit content
    )

def calculate_block_rate():
    total = stats['blocked'] + stats['allowed']
    if total == 0:
        return 0
    return (stats['blocked'] / total) * 100

# Function to record packet information
def record_packet(src_ip, dst_ip, protocol, src_port, dst_port, size, action, matched_rule=None):
    time_str = datetime.datetime.now().strftime("%H:%M:%S")
    
    # Create packet record
    packet_info = {
        "time": time_str,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "size": size,
        "action": action
    }
    
    if matched_rule:
        packet_info["matched_rule"] = matched_rule
    
    # Add to recent packets queue
    recent_packets.append(packet_info)
    
    # Limit the size of recent_packets
    if len(recent_packets) > MAX_RECENT_PACKETS:
        recent_packets.pop(0)
    
    # Update stats
    if action == "[red]BLOCK[/]":
        stats["blocked"] += 1
    elif action == "[green]ALLOW[/]":
        stats["allowed"] += 1

# Detect OS
def get_os():
    os_name = platform.system()
    if os_name == "Windows":
        return "Windows"
    elif os_name == "Linux":
        return "Linux"
    else:
        return "Unknown"

# Check if a packet should be blocked based on rules
def should_block_packet(src_ip, dst_ip, protocol, src_port, dst_port):
    # Check IP rules
    if src_ip in rules["blocked_ips"] or dst_ip in rules["blocked_ips"]:
        return True, f"IP rule: {src_ip if src_ip in rules['blocked_ips'] else dst_ip}"
    
    # Check port rules
    port_str = f"{src_port}/TCP" if protocol == "TCP" else f"{src_port}/UDP"
    if protocol in ["TCP", "UDP"]:
        if str(src_port) in rules["blocked_ports"] or port_str in rules["blocked_ports"]:
            return True, f"Port rule: {src_port}"
        if str(dst_port) in rules["blocked_ports"] or f"{dst_port}/{protocol}" in rules["blocked_ports"]:
            return True, f"Port rule: {dst_port}"
    
    # Check IP/port combination rules (for future implementation)
    for rule in rules.get("ip_port_rules", []):
        if (rule.get("ip") == src_ip and rule.get("port") == src_port) or \
           (rule.get("ip") == dst_ip and rule.get("port") == dst_port):
            return True, f"IP/Port rule: {rule.get('ip')}:{rule.get('port')}"
    
    return False, None

# Linux: Add iptables rules
def linux_block_ip(ip):
    try:
        # Test if IP is valid
        ipaddress.ip_address(ip)
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        os.system(f"sudo iptables -A OUTPUT -d {ip} -j DROP")
        return True
    except ValueError:
        console.log(f"[bold red]Invalid IP address: {ip}")
        return False

def linux_unblock_ip(ip):
    try:
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
        os.system(f"sudo iptables -D OUTPUT -d {ip} -j DROP")
        return True
    except Exception as e:
        console.log(f"[bold red]Error unblocking IP {ip}: {e}")
        return False

def linux_block_port(port, protocol="all"):
    try:
        if protocol.lower() == "tcp" or protocol.lower() == "all":
            os.system(f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP")
        if protocol.lower() == "udp" or protocol.lower() == "all":
            os.system(f"sudo iptables -A INPUT -p udp --dport {port} -j DROP")
        return True
    except Exception as e:
        console.log(f"[bold red]Error blocking port {port}: {e}")
        return False

def linux_unblock_port(port, protocol="all"):
    try:
        if protocol.lower() == "tcp" or protocol.lower() == "all":
            os.system(f"sudo iptables -D INPUT -p tcp --dport {port} -j DROP")
        if protocol.lower() == "udp" or protocol.lower() == "all":
            os.system(f"sudo iptables -D INPUT -p udp --dport {port} -j DROP")
        return True
    except Exception as e:
        console.log(f"[bold red]Error unblocking port {port}: {e}")
        return False

# Windows packet handling thread using WinDivert
def windows_packet_handler():
    if not PYDIVERT_AVAILABLE:
        console.log("[bold red]WinDivert not available. Install with 'pip install pydivert'")
        return
    
    console.log("[cyan]Starting Windows packet handler using WinDivert...")
    
    # Define a filter to capture all IP traffic
    filter_string = "true"
    
    try:
        with pydivert.WinDivert(filter_string) as w:
            console.log("[green]WinDivert initialized successfully")
            
            while True:
                # Check if we should process a rule action
                try:
                    while not rule_action_queue.empty():
                        action = rule_action_queue.get_nowait()
                        console.log(f"[yellow]Processed rule action: {action}")
                except queue.Empty:
                    pass
                
                # Get the next packet
                packet = w.recv()
                
                # Extract packet information
                protocol = "UNKNOWN"
                src_port = dst_port = ""
                
                if packet.ip:
                    src_ip = packet.ip.src_addr
                    dst_ip = packet.ip.dst_addr
                    
                    if packet.tcp:
                        protocol = "TCP"
                        src_port = packet.tcp.src_port
                        dst_port = packet.tcp.dst_port
                    elif packet.udp:
                        protocol = "UDP"
                        src_port = packet.udp.src_port
                        dst_port = packet.udp.dst_port
                    else:
                        protocol = "IP"
                    
                    # Check if packet should be blocked
                    should_block, rule = should_block_packet(src_ip, dst_ip, protocol, src_port, dst_port)
                    
                    if should_block:
                        # Block packet by not forwarding it
                        action = "[red]BLOCK[/]"
                        # Don't send the packet
                    else:
                        # Allow packet
                        action = "[green]ALLOW[/]"
                        w.send(packet)
                    
                    # Record packet
                    size = len(packet.raw)
                    record_packet(src_ip, dst_ip, protocol, src_port, dst_port, size, action, rule)
                    
    except Exception as e:
        console.log(f"[bold red]Error in WinDivert packet handler: {e}")
        # Try to restart if this is temporary
        time.sleep(2)
        console.log("[yellow]Attempting to restart packet handler...")
        windows_packet_handler()

# Common: Use Scapy to monitor network traffic
def monitor_traffic():
    console.log("[cyan]Starting Scapy packet monitor...")

    def packet_callback(packet):
        # Process only IP packets
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "IP"
            src_port = dst_port = ""
            
            # Extract protocol and port information
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Check if packet should be blocked (monitoring only, doesn't actually block)
            should_block, rule = should_block_packet(src_ip, dst_ip, protocol, src_port, dst_port)
            
            # Set action based on blocking decision
            action = "[red]BLOCK[/]" if should_block else "[green]ALLOW[/]"
            
            # Get packet size
            size = len(packet)
            
            # Record packet information
            record_packet(src_ip, dst_ip, protocol, src_port, dst_port, size, action, rule)

    # Start packet capture with error handling
    try:
        sniff(filter="ip", prn=packet_callback, store=0)
    except Exception as e:
        console.log(f"[bold red]Error starting packet sniffer: {e}")
        console.log("[yellow]Monitoring will continue in simulation mode")

# Move the rule application functions outside of the manage_rules function
# so they can be called from multiple places
def apply_rule(rule_type, value):
    """Apply a rule to the system based on OS."""
    system_os = get_os()
    success = False
    
    # Add to rule_action_queue for the Windows packet handler
    rule_action_queue.put({"type": rule_type, "value": value, "action": "add"})
    
    if rule_type == RuleType.IP_BLOCK:
        if system_os == "Linux":
            success = linux_block_ip(value)
        elif system_os == "Windows":
            # Rule will be applied by the packet handler thread
            success = True
    elif rule_type == RuleType.PORT_BLOCK:
        port = value
        protocol = "all"
        
        if "/" in value:
            port, protocol = value.split("/")
        
        if system_os == "Linux":
            success = linux_block_port(port, protocol)
        elif system_os == "Windows":
            # Rule will be applied by the packet handler thread
            success = True
            
    return success

def remove_rule(rule_type, value):
    """Remove a rule from the system based on OS."""
    system_os = get_os()
    success = False
    
    # Add to rule_action_queue for the Windows packet handler
    rule_action_queue.put({"type": rule_type, "value": value, "action": "remove"})
    
    if rule_type == RuleType.IP_BLOCK:
        if system_os == "Linux":
            success = linux_unblock_ip(value)
        elif system_os == "Windows":
            # Rule will be removed by the packet handler thread
            success = True
    elif rule_type == RuleType.PORT_BLOCK:
        port = value
        protocol = "all"
        
        if "/" in value:
            port, protocol = value.split("/")
        
        if system_os == "Linux":
            success = linux_unblock_port(port, protocol)
        elif system_os == "Windows":
            # Rule will be removed by the packet handler thread
            success = True
            
    return success

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except ValueError:
        return False

# Enhanced rule management with command parsing
def manage_rules():
    # Add a small delay to let the Live display start
    time.sleep(2)
    console.print("\n\n[bold yellow]PyFirewall Rule Management[/]")
    console.print("[dim]Type 'help' for available commands[/]")
    
    def print_help():
        help_text = """
[bold]Available Commands:[/]
[cyan]add-ip <ip>[/] - Block an IP address
[cyan]add-port <port>[/tcp|udp] - Block a port (optionally specify protocol)
[cyan]remove-ip <ip>[/] - Unblock an IP address
[cyan]remove-port <port>[/tcp|udp] - Unblock a port
[cyan]list[/] - List all current rules
[cyan]save[/] - Save rules to file
[cyan]reload[/] - Reload rules from file
[cyan]help[/] - Show this help message
[cyan]exit[/] - Exit rule management
        """
        console.print(help_text)
    
    
    # Note: apply_rule and remove_rule functions moved outside
    
    while True:
        try:
            command = Prompt.ask("\n[cyan]PyFirewall[/]", console=console)
            parts = command.strip().split()
            
            if not parts:
                continue
                
            cmd = parts[0].lower()
            
            if cmd == "exit":
                console.print("[bold yellow]Exiting rule management")
                break
                
            elif cmd == "help":
                print_help()
                
            elif cmd == "list":
                console.print("[bold]Current Rules:[/]")
                console.print("\n[bold cyan]Blocked IPs:[/]")
                if not rules["blocked_ips"]:
                    console.print("  [dim]None[/]")
                else:
                    for ip in rules["blocked_ips"]:
                        console.print(f"  [red]{ip}[/]")
                
                console.print("\n[bold cyan]Blocked Ports:[/]")
                if not rules["blocked_ports"]:
                    console.print("  [dim]None[/]")
                else:
                    for port in rules["blocked_ports"]:
                        console.print(f"  [red]{port}[/]")
                
            elif cmd == "add-ip" and len(parts) > 1:
                ip = parts[1]
                if not is_valid_ip(ip):
                    console.print(f"[bold red]Invalid IP address: {ip}")
                    continue
                    
                if ip not in rules["blocked_ips"]:
                    if Confirm.ask(f"Block IP address [bold]{ip}[/]?"):
                        if apply_rule(RuleType.IP_BLOCK, ip):
                            rules["blocked_ips"].append(ip)
                            save_rules(rules)
                            console.print(f"[green]IP {ip} added to blocklist")
                        else:
                            console.print(f"[bold red]Failed to block IP {ip}")
                else:
                    console.print(f"[yellow]IP {ip} is already blocked")
                    
            elif cmd == "add-port" and len(parts) > 1:
                port_spec = parts[1]
                
                # Parse port/protocol format
                if "/" in port_spec:
                    port, protocol = port_spec.split("/")
                    if protocol.upper() not in ["TCP", "UDP", "ALL"]:
                        console.print(f"[bold red]Invalid protocol: {protocol}")
                        continue
                else:
                    port = port_spec
                    protocol = "ALL"
                    port_spec = f"{port}/ALL"
                
                if not is_valid_port(port):
                    console.print(f"[bold red]Invalid port number: {port}")
                    continue
                    
                if port_spec not in rules["blocked_ports"]:
                    if Confirm.ask(f"Block port [bold]{port_spec}[/]?"):
                        if apply_rule(RuleType.PORT_BLOCK, port_spec):
                            rules["blocked_ports"].append(port_spec)
                            save_rules(rules)
                            console.print(f"[green]Port {port_spec} added to blocklist")
                        else:
                            console.print(f"[bold red]Failed to block port {port_spec}")
                else:
                    console.print(f"[yellow]Port {port_spec} is already blocked")
                    
            elif cmd == "remove-ip" and len(parts) > 1:
                ip = parts[1]
                
                if ip in rules["blocked_ips"]:
                    if Confirm.ask(f"Unblock IP address [bold]{ip}[/]?"):
                        if remove_rule(RuleType.IP_BLOCK, ip):
                            rules["blocked_ips"].remove(ip)
                            save_rules(rules)
                            console.print(f"[green]IP {ip} removed from blocklist")
                        else:
                            console.print(f"[bold red]Failed to unblock IP {ip}")
                else:
                    console.print(f"[yellow]IP {ip} is not in the blocklist")
                    
            elif cmd == "remove-port" and len(parts) > 1:
                port_spec = parts[1]
                
                # Handle missing protocol specification
                if "/" not in port_spec:
                    port_spec = f"{port_spec}/ALL"
                
                if port_spec in rules["blocked_ports"]:
                    if Confirm.ask(f"Unblock port [bold]{port_spec}[/]?"):
                        if remove_rule(RuleType.PORT_BLOCK, port_spec):
                            rules["blocked_ports"].remove(port_spec)
                            save_rules(rules)
                            console.print(f"[green]Port {port_spec} removed from blocklist")
                        else:
                            console.print(f"[bold red]Failed to unblock port {port_spec}")
                else:
                    console.print(f"[yellow]Port {port_spec} is not in the blocklist")
                    
            elif cmd == "save":
                if save_rules(rules):
                    console.print("[green]Rules saved successfully")
                else:
                    console.print("[bold red]Failed to save rules")
                    
            elif cmd == "reload":
                rules.update(load_rules())
                console.print("[green]Rules reloaded successfully")
                
            else:
                console.print("[bold red]Unknown command. Type 'help' for available commands")
                
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Rule management interrupted")
            break
        except Exception as e:
            console.print(f"[bold red]Error: {e}")
            
        # Small pause to allow Live display to refresh
        time.sleep(0.2)

# Input handler function that reads keypresses without blocking
def input_handler():
    global current_input, command_history, command_feedback, command_feedback_color
    
    console.print("[dim]Input handler thread started[/]")
    
    if sys.platform == "win32":
        # Windows doesn't have select on sys.stdin, so we use a different approach
        import msvcrt
        
        def getch():
            if msvcrt.kbhit():
                return msvcrt.getch().decode('utf-8', errors='ignore')
            return None
    else:
        # Unix-like systems can use select
        def getch():
            if select.select([sys.stdin], [], [], 0)[0]:
                return sys.stdin.read(1)
            return None
    
    while True:
        try:
            # Check for keypress
            key = getch()
            
            if key:
                # Handle different key types
                if key == '\r' or key == '\n':  # Enter key
                    # Process the command
                    command = current_input.strip()
                    if command:
                        command_history.append(command)
                        input_queue.put(command)
                        # Keep only recent commands
                        if len(command_history) > MAX_COMMAND_HISTORY:
                            command_history.pop(0)
                        # Reset input
                        current_input = ""
                        input_ready.set()
                        # Wait for processing before getting feedback
                        input_processed.wait()
                        input_processed.clear()
                elif key == '\b' or key == '\x7f':  # Backspace
                    current_input = current_input[:-1]
                elif key == '\x03':  # Ctrl+C
                    # Signal to quit
                    input_queue.put("QUIT")
                    break
                elif key and len(key) == 1 and key.isprintable():
                    # Add to current input
                    current_input += key
            
            # Avoid tight loop
            time.sleep(0.05)
            
        except Exception as e:
            command_feedback = f"Input error: {e}"
            command_feedback_color = "red"
            time.sleep(1)  # Delay before clearing error

# Process commands and apply firewall rules
def process_commands():
    global current_input, command_feedback, command_feedback_color, rules
    
    while True:
        try:
            # Wait for a command to be available
            command = input_queue.get()
            
            if command == "QUIT":
                break
                
            # Process based on command
            parts = command.strip().split()
            
            if not parts:
                command_feedback = ""
                input_processed.set()
                continue
                
            cmd = parts[0].lower()
            
            if cmd == "exit":
                command_feedback = "Exiting FireWall. Press Ctrl+C to confirm."
                command_feedback_color = "yellow"
                
            elif cmd == "help":
                command_feedback = "Available commands: add-ip, add-port, remove-ip, remove-port, list, save, reload, help, exit"
                command_feedback_color = "blue"
                
            elif cmd == "list":
                ip_count = len(rules["blocked_ips"])
                port_count = len(rules["blocked_ports"])
                command_feedback = f"Rules: {ip_count} IPs and {port_count} ports blocked"
                command_feedback_color = "blue"
                
            elif cmd == "add-ip" and len(parts) > 1:
                ip = parts[1]
                if not is_valid_ip(ip):
                    command_feedback = f"Invalid IP address: {ip}"
                    command_feedback_color = "red"
                elif ip in rules["blocked_ips"]:
                    command_feedback = f"IP {ip} is already blocked"
                    command_feedback_color = "yellow"
                else:
                    # Apply the rule
                    apply_rule(RuleType.IP_BLOCK, ip)
                    rules["blocked_ips"].append(ip)
                    save_rules(rules)
                    command_feedback = f"IP {ip} added to blocklist"
                    command_feedback_color = "green"
                    
            elif cmd == "add-port" and len(parts) > 1:
                port_spec = parts[1]
                
                # Parse port/protocol format
                if "/" in port_spec:
                    port, protocol = port_spec.split("/")
                    if protocol.upper() not in ["TCP", "UDP", "ALL"]:
                        command_feedback = f"Invalid protocol: {protocol}"
                        command_feedback_color = "red"
                        input_processed.set()
                        continue
                else:
                    port = port_spec
                    protocol = "ALL"
                    port_spec = f"{port}/ALL"
                
                if not is_valid_port(port):
                    command_feedback = f"Invalid port number: {port}"
                    command_feedback_color = "red"
                elif port_spec in rules["blocked_ports"]:
                    command_feedback = f"Port {port_spec} is already blocked"
                    command_feedback_color = "yellow"
                else:
                    # Apply the rule
                    apply_rule(RuleType.PORT_BLOCK, port_spec)
                    rules["blocked_ports"].append(port_spec)
                    save_rules(rules)
                    command_feedback = f"Port {port_spec} added to blocklist"
                    command_feedback_color = "green"
                    
            elif cmd == "remove-ip" and len(parts) > 1:
                ip = parts[1]
                
                if ip in rules["blocked_ips"]:
                    # Remove the rule
                    remove_rule(RuleType.IP_BLOCK, ip)
                    rules["blocked_ips"].remove(ip)
                    save_rules(rules)
                    command_feedback = f"IP {ip} removed from blocklist"
                    command_feedback_color = "green"
                else:
                    command_feedback = f"IP {ip} is not in the blocklist"
                    command_feedback_color = "yellow"
                    
            elif cmd == "remove-port" and len(parts) > 1:
                port_spec = parts[1]
                
                # Handle missing protocol specification
                if "/" not in port_spec:
                    port_spec = f"{port_spec}/ALL"
                
                if port_spec in rules["blocked_ports"]:
                    # Remove the rule
                    remove_rule(RuleType.PORT_BLOCK, port_spec)
                    rules["blocked_ports"].remove(port_spec)
                    save_rules(rules)
                    command_feedback = f"Port {port_spec} removed from blocklist"
                    command_feedback_color = "green"
                else:
                    command_feedback = f"Port {port_spec} is not in the blocklist"
                    command_feedback_color = "yellow"
                    
            elif cmd == "save":
                if save_rules(rules):
                    command_feedback = "Rules saved successfully"
                    command_feedback_color = "green"
                else:
                    command_feedback = "Failed to save rules"
                    command_feedback_color = "red"
                    
            elif cmd == "reload":
                rules.update(load_rules())
                command_feedback = "Rules reloaded successfully"
                command_feedback_color = "green"
                
            else:
                command_feedback = f"Unknown command: {cmd}. Type 'help' for available commands."
                command_feedback_color = "red"
                
            # Signal that we've processed the command
            input_processed.set()
            
        except Exception as e:
            command_feedback = f"Error processing command: {e}"
            command_feedback_color = "red"
            input_processed.set()
        
        # Small delay to ensure the display updates
        time.sleep(0.1)

# Main function
if __name__ == "__main__":
    system_os = get_os()
    console.log(f"[cyan]Starting PyFirewall on [bold]{system_os}[/]")
    
    # Create layout
    layout = create_layout()
    
    # Load rules
    rules = load_rules()
    
    # Show startup banner
    console.print(Panel.fit(
        "[bold magenta]PyFirewall[/bold magenta] - Advanced Network Protection",
        box=box.DOUBLE,
        border_style="bright_magenta",
        padding=(1, 10)
    ))
    
    # Start input handler
    input_thread = threading.Thread(target=input_handler, daemon=True)
    input_thread.start()
    
    # Start command processor
    command_thread = threading.Thread(target=process_commands, daemon=True)
    command_thread.start()
    
    # Start the appropriate packet handler for this OS
    if system_os == "Windows":
        if PYDIVERT_AVAILABLE:
            # For Windows, start the WinDivert packet handler in a separate thread
            packet_thread = threading.Thread(target=windows_packet_handler, daemon=True)
            packet_thread.start()
            console.log("[green]Windows packet handler started")
        else:
            # Fall back to monitoring only
            console.log("[yellow]WinDivert not available, using Scapy for monitoring only (no blocking)")
            monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
            monitor_thread.start()
    elif system_os == "Linux":
        # For Linux, apply initial iptables rules
        console.log("[cyan]Applying initial iptables rules...")
        for ip in rules["blocked_ips"]:
            linux_block_ip(ip)
        
        for port_spec in rules["blocked_ports"]:
            if "/" in port_spec:
                port, protocol = port_spec.split("/")
            else:
                port, protocol = port_spec, "all"
            linux_block_port(port, protocol)
        
        # Start packet monitoring
        monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
        monitor_thread.start()
    else:
        # For other systems, just monitor
        console.log("[yellow]OS not supported for active blocking. Monitoring only.")
        monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
        monitor_thread.start()
    
    try:
        with Live(layout, console=console, screen=True, refresh_per_second=2, vertical_overflow="visible") as live:
            while True:
                # Update layout components
                title = "[bold magenta]🔥 PyFirewall Dashboard 🔥[/]"
                live.update(layout)
                
                # Update header
                layout["header"].update(
                    Panel(
                        Align.center(title, vertical="middle"),
                        border_style="bright_magenta",
                        subtitle="[bold green]Coded[/bold green] [white]by[/white] [bold red]Zaeem[bold green]20[/bold green][/bold red]",
                        subtitle_align='right',
                        box=box.HEAVY
                    )
                )
                
                # Update monitoring panels
                layout["left_column"].update(update_monitoring_panel())
                
                # Update rules panels
                layout["rules"].update(update_rules_panel())
                layout["stats"].update(update_stats_panel())
                
                # Update input area
                layout["input_area"].update(update_input_panel())
                
                # Update footer with keybindings and status
                layout["footer"].update(
                    Panel(
                        Align.center(
                            "[bold]Press Ctrl+C to exit | Type commands directly in the input area[/]", 
                            vertical="middle"
                        ),
                        border_style="bright_blue",
                        box=box.HEAVY
                    )
                )
                
                # Sleep to reduce CPU usage
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Exiting PyFirewall...[/]")
    except Exception as e:
        console.print(f"\n[bold red]Error in main loop: {e}")
    finally:
        # Cleanup
        if system_os == "Linux":
            # Clean up iptables rules if desired
            if Confirm.ask("Remove all firewall rules?"):
                for ip in rules["blocked_ips"]:
                    linux_unblock_ip(ip)
                for port_spec in rules["blocked_ports"]:
                    if "/" in port_spec:
                        port, protocol = port_spec.split("/")
                    else:
                        port, protocol = port_spec, "all"
                    linux_unblock_port(port, protocol)
        
        console.print("[bold green]PyFirewall stopped.[/]")
