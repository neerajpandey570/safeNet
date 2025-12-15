"""Router Integration Module - SSH into supported routers and collect network-wide data.

Supports OpenWrt, Merlin, DD-WRT and compatible firmware.
Provides access to:
  - conntrack: Active connections for all devices
  - dnsmasq logs: DNS queries from all devices
  - DHCP leases: Device IP to MAC/hostname mapping
  
Usage:
    monitor = RouterMonitor(router_ip='192.168.1.1', username='root', password='admin')
    
    # With authentication (prompts if not provided)
    data = monitor.connect()
    connections = monitor.get_all_device_connections()
    dns_queries = monitor.get_all_dns_queries()
    devices = monitor.get_device_list()
    
    # Gracefully degrades if router unavailable
    merged_data = monitor.merge_with_local_connections(local_connections)
"""

import paramiko
import socket
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import re
import logging

logger = logging.getLogger(__name__)


@dataclass
class RouterConnection:
    """Represents a network connection from router conntrack."""
    protocol: str  # tcp, udp
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    state: str  # ESTABLISHED, TIME_WAIT, etc.
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    

@dataclass
class DeviceInfo:
    """Information about a device on the network."""
    ip_address: str
    mac_address: str
    hostname: Optional[str] = None
    device_type: str = "Unknown"  # Phone, Laptop, IoT, etc.
    connections: List[RouterConnection] = None
    dns_queries: List[str] = None
    
    def __post_init__(self):
        if self.connections is None:
            self.connections = []
        if self.dns_queries is None:
            self.dns_queries = []


class RouterMonitor:
    """SSH into router and collect network-wide monitoring data."""
    
    ROUTER_DEFAULTS = {
        'openwrt': {
            'username': 'root',
            'password': '',
            'port': 22,
            'shell': '/bin/sh'
        },
        'merlin': {
            'username': 'admin',
            'password': 'admin',
            'port': 22,
            'shell': '/bin/sh'
        }
    }
    
    def __init__(self, router_ip: str, username: Optional[str] = None, 
                 password: Optional[str] = None, timeout: int = 10, 
                 key_filename: Optional[str] = None):
        """Initialize router monitor.
        
        Args:
            router_ip: IP address of router (e.g., 192.168.1.1)
            username: SSH username (optional, will prompt)
            password: SSH password (optional, will prompt)
            timeout: SSH connection timeout in seconds
            key_filename: Path to SSH private key for auth
        """
        self.router_ip = router_ip
        self.username = username or 'root'
        self.password = password
        self.key_filename = key_filename
        self.timeout = timeout
        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.connected = False
        self.router_os = None  # detected OS
        self.local_ip = None
        self._get_local_ip()
    
    def _get_local_ip(self) -> str:
        """Get local machine's IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.router_ip, 1))
            self.local_ip = s.getsockname()[0]
            s.close()
        except Exception as e:
            logger.warning(f"Could not determine local IP: {e}")
            self.local_ip = None
        return self.local_ip
    
    def connect(self, interactive: bool = True) -> bool:
        """Connect to router via SSH.
        
        Args:
            interactive: Prompt for credentials if connection fails
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try key-based auth first if provided
            if self.key_filename and os.path.exists(self.key_filename):
                try:
                    self.ssh_client.connect(
                        self.router_ip,
                        port=22,
                        username=self.username,
                        key_filename=self.key_filename,
                        timeout=self.timeout,
                        look_for_keys=True,
                        allow_agent=True
                    )
                    self.connected = True
                    logger.info(f"Connected to {self.router_ip} via SSH key")
                    self._detect_router_os()
                    return True
                except Exception as e:
                    logger.warning(f"SSH key auth failed: {e}")
            
            # Fall back to password auth
            if self.password:
                try:
                    self.ssh_client.connect(
                        self.router_ip,
                        port=22,
                        username=self.username,
                        password=self.password,
                        timeout=self.timeout
                    )
                    self.connected = True
                    logger.info(f"Connected to {self.router_ip} via password")
                    self._detect_router_os()
                    return True
                except paramiko.AuthenticationException:
                    if not interactive:
                        logger.error("Authentication failed")
                        return False
                    logger.warning("Authentication failed, please try again")
            
            # Interactive mode: prompt for credentials
            if interactive:
                print("\n" + "="*60)
                print("ROUTER INTEGRATION - SSH AUTHENTICATION")
                print("="*60)
                print(f"Router IP: {self.router_ip}")
                print("\nEnter router credentials (leave blank for defaults):")
                username = input(f"Username [{self.username}]: ").strip() or self.username
                password = input("Password [empty for key auth]: ").strip()
                
                if not password and not self.key_filename:
                    print("\nNo password provided and no SSH key configured.")
                    print("Router integration will be skipped.")
                    return False
                
                self.username = username
                self.password = password
                
                # Retry connection
                self.ssh_client.connect(
                    self.router_ip,
                    port=22,
                    username=self.username,
                    password=self.password if password else None,
                    key_filename=self.key_filename if not password else None,
                    timeout=self.timeout,
                    allow_agent=True
                )
                self.connected = True
                logger.info(f"Connected to {self.router_ip} via SSH")
                self._detect_router_os()
                return True
                
        except socket.timeout:
            logger.error(f"Connection timeout to {self.router_ip}:22 - router unreachable")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to router: {e}")
            return False
    
    def disconnect(self):
        """Close SSH connection."""
        if self.ssh_client:
            self.ssh_client.close()
            self.connected = False
            logger.info("Disconnected from router")
    
    def _run_command(self, command: str) -> Tuple[str, str, int]:
        """Execute command on router via SSH.
        
        Args:
            command: Shell command to execute
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        if not self.connected or not self.ssh_client:
            raise RuntimeError("Not connected to router")
        
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=self.timeout)
            out = stdout.read().decode('utf-8', errors='ignore')
            err = stderr.read().decode('utf-8', errors='ignore')
            return_code = stdout.channel.recv_exit_status()
            return out, err, return_code
        except Exception as e:
            logger.error(f"Failed to execute command: {e}")
            return "", str(e), 1
    
    def _detect_router_os(self) -> str:
        """Detect router firmware type (OpenWrt, Merlin, DD-WRT, etc)."""
        try:
            # Check for OpenWrt
            out, _, rc = self._run_command("test -f /etc/openwrt_version && echo 'OpenWrt'")
            if rc == 0 and out.strip():
                self.router_os = 'openwrt'
                logger.info("Detected OpenWrt firmware")
                return 'openwrt'
            
            # Check for Merlin (ASUS with custom firmware)
            out, _, rc = self._run_command("test -f /etc/merlin.version && echo 'Merlin'")
            if rc == 0 and out.strip():
                self.router_os = 'merlin'
                logger.info("Detected Merlin firmware")
                return 'merlin'
            
            # Check for DD-WRT
            out, _, rc = self._run_command("test -f /etc/os-release && grep -q DD-WRT /etc/os-release && echo 'DD-WRT'")
            if rc == 0 and out.strip():
                self.router_os = 'ddwrt'
                logger.info("Detected DD-WRT firmware")
                return 'ddwrt'
            
            # Generic Linux
            self.router_os = 'linux'
            logger.info("Detected generic Linux firmware")
            return 'linux'
        except Exception as e:
            logger.warning(f"Could not detect router OS: {e}")
            self.router_os = 'unknown'
            return 'unknown'
    
    def get_all_device_connections(self, include_established_only: bool = True) -> List[RouterConnection]:
        """Get all active connections on the network from router.
        
        Args:
            include_established_only: If True, only return ESTABLISHED connections
            
        Returns:
            List of RouterConnection objects
        """
        if not self.connected:
            logger.warning("Not connected to router")
            return []
        
        connections = []
        
        try:
            # Try conntrack first (most reliable)
            if self._has_conntrack():
                connections = self._parse_conntrack(include_established_only)
                if connections:
                    logger.info(f"Retrieved {len(connections)} connections from conntrack")
                    return connections
            
            # Fallback to netstat
            out, _, _ = self._run_command("netstat -an 2>/dev/null || ss -an")
            if out:
                connections = self._parse_netstat(out, include_established_only)
                logger.info(f"Retrieved {len(connections)} connections from netstat fallback")
        
        except Exception as e:
            logger.error(f"Failed to get connections: {e}")
        
        return connections
    
    def _has_conntrack(self) -> bool:
        """Check if router has conntrack available."""
        try:
            _, _, rc = self._run_command("which conntrack")
            return rc == 0
        except:
            return False
    
    def _parse_conntrack(self, include_established_only: bool = True) -> List[RouterConnection]:
        """Parse conntrack output for active connections.
        
        Example conntrack output:
        ipv4     2 tcp      6 431996 ESTABLISHED src=192.168.1.100 dst=8.8.8.8 ...
        """
        connections = []
        try:
            out, _, rc = self._run_command("conntrack -L 2>/dev/null | grep -E 'tcp|udp'")
            if rc != 0:
                return []
            
            for line in out.split('\n'):
                if not line.strip():
                    continue
                
                try:
                    # Parse: ipv4 2 tcp 6 431996 ESTABLISHED src=... dst=...
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    
                    protocol = parts[2]  # tcp or udp
                    state = "ESTABLISHED"  # conntrack defaults to established
                    
                    # Extract src and dst IPs/ports
                    src_ip = src_port = dst_ip = dst_port = None
                    
                    for part in parts:
                        if part.startswith('src='):
                            src_ip = part[4:]
                        elif part.startswith('sport='):
                            src_port = int(part[6:])
                        elif part.startswith('dst='):
                            dst_ip = part[4:]
                        elif part.startswith('dport='):
                            dst_port = int(part[6:])
                    
                    if src_ip and dst_ip and src_port and dst_port:
                        conn = RouterConnection(
                            protocol=protocol,
                            source_ip=src_ip,
                            source_port=src_port,
                            dest_ip=dst_ip,
                            dest_port=dst_port,
                            state=state
                        )
                        connections.append(conn)
                
                except (ValueError, IndexError) as e:
                    logger.debug(f"Failed to parse conntrack line: {line}")
                    continue
        
        except Exception as e:
            logger.error(f"Error parsing conntrack: {e}")
        
        return connections
    
    def _parse_netstat(self, netstat_output: str, include_established_only: bool = True) -> List[RouterConnection]:
        """Parse netstat output (fallback method)."""
        connections = []
        
        for line in netstat_output.split('\n'):
            if not line.strip() or line.startswith('Active'):
                continue
            
            try:
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                protocol = parts[0]
                if protocol not in ['tcp', 'udp']:
                    continue
                
                # Parse local and remote addresses
                local = parts[3].rsplit(':', 1)
                remote = parts[4].rsplit(':', 1)
                
                if len(local) != 2 or len(remote) != 2:
                    continue
                
                state = parts[5] if len(parts) > 5 else "UNKNOWN"
                
                if include_established_only and state != "ESTABLISHED":
                    continue
                
                conn = RouterConnection(
                    protocol=protocol,
                    source_ip=local[0],
                    source_port=int(local[1]),
                    dest_ip=remote[0],
                    dest_port=int(remote[1]),
                    state=state
                )
                connections.append(conn)
            
            except (ValueError, IndexError):
                continue
        
        return connections
    
    def get_all_dns_queries(self, minutes: int = 5) -> Dict[str, List[str]]:
        """Get DNS queries for all devices.
        
        Args:
            minutes: How many minutes of history to retrieve
            
        Returns:
            Dict mapping device IP to list of queried domains
        """
        if not self.connected:
            logger.warning("Not connected to router")
            return {}
        
        dns_by_device = {}
        
        try:
            # Try dnsmasq logs first
            dns_entries = self._get_dnsmasq_logs(minutes)
            
            # Parse and group by source IP
            for timestamp, source_ip, domain in dns_entries:
                if source_ip not in dns_by_device:
                    dns_by_device[source_ip] = []
                dns_by_device[source_ip].append(domain)
            
            if dns_by_device:
                total_queries = sum(len(v) for v in dns_by_device.values())
                logger.info(f"Retrieved {total_queries} DNS queries for {len(dns_by_device)} devices")
        
        except Exception as e:
            logger.error(f"Failed to get DNS queries: {e}")
        
        return dns_by_device
    
    def _get_dnsmasq_logs(self, minutes: int = 5) -> List[Tuple[str, str, str]]:
        """Get DNS queries from dnsmasq logs.
        
        Returns:
            List of (timestamp, source_ip, domain) tuples
        """
        queries = []
        
        try:
            # Try different dnsmasq log locations
            commands = [
                "tail -500 /tmp/dnsmasq.log 2>/dev/null",
                "tail -500 /var/log/dnsmasq.log 2>/dev/null",
                "logread | grep dnsmasq 2>/dev/null"
            ]
            
            for cmd in commands:
                out, _, rc = self._run_command(cmd)
                if rc == 0 and out.strip():
                    # Parse dnsmasq log format: timestamp, query, client
                    # Example: Dec 16 12:34:56 dnsmasq[1234]: query[A] example.com from 192.168.1.100
                    
                    for line in out.split('\n'):
                        if not line or 'query' not in line:
                            continue
                        
                        try:
                            # Extract domain and source IP
                            match = re.search(r'query\[.*?\]\s+(\S+)\s+from\s+(\S+)', line)
                            if match:
                                domain = match.group(1)
                                source_ip = match.group(2)
                                timestamp = datetime.now().isoformat()
                                queries.append((timestamp, source_ip, domain))
                        except:
                            continue
                    
                    if queries:
                        break
        
        except Exception as e:
            logger.error(f"Error getting dnsmasq logs: {e}")
        
        return queries
    
    def get_device_list(self) -> Dict[str, DeviceInfo]:
        """Get list of all devices on network with DHCP info.
        
        Returns:
            Dict mapping IP to DeviceInfo
        """
        if not self.connected:
            logger.warning("Not connected to router")
            return {}
        
        devices = {}
        
        try:
            # Get DHCP leases
            leases = self._parse_dhcp_leases()
            
            # Get connected devices via ARP
            arp_devices = self._parse_arp_table()
            
            # Merge data
            for ip, mac, hostname in leases:
                devices[ip] = DeviceInfo(
                    ip_address=ip,
                    mac_address=mac,
                    hostname=hostname
                )
            
            for ip, mac in arp_devices:
                if ip not in devices:
                    devices[ip] = DeviceInfo(
                        ip_address=ip,
                        mac_address=mac
                    )
                else:
                    devices[ip].mac_address = mac
            
            logger.info(f"Found {len(devices)} devices on network")
        
        except Exception as e:
            logger.error(f"Failed to get device list: {e}")
        
        return devices
    
    def _parse_dhcp_leases(self) -> List[Tuple[str, str, str]]:
        """Parse DHCP leases to get IP -> MAC -> hostname mapping.
        
        Returns:
            List of (ip, mac, hostname) tuples
        """
        leases = []
        
        try:
            out, _, rc = self._run_command("cat /tmp/dnsmasq.leases 2>/dev/null")
            if rc != 0:
                # Try alternative location
                out, _, _ = self._run_command("cat /var/lib/dnsmasq/dnsmasq.leases 2>/dev/null")
            
            # Format: timestamp mac ip hostname md5hash
            for line in out.split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        mac = parts[1]
                        ip = parts[2]
                        hostname = parts[3] if parts[3] != '*' else "Unknown"
                        leases.append((ip, mac, hostname))
                    except:
                        continue
        
        except Exception as e:
            logger.debug(f"Failed to parse DHCP leases: {e}")
        
        return leases
    
    def _parse_arp_table(self) -> List[Tuple[str, str]]:
        """Parse ARP table to get IP -> MAC mapping.
        
        Returns:
            List of (ip, mac) tuples
        """
        devices = []
        
        try:
            out, _, rc = self._run_command("arp -n 2>/dev/null || ip neigh")
            if rc != 0:
                return []
            
            for line in out.split('\n'):
                if not line.strip():
                    continue
                
                # Format varies but usually: IP HWType HWAddress Flags Mask Iface
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        ip = parts[0]
                        mac = parts[2] if ':' in parts[2] else parts[3]
                        if ':' in mac and '.' in ip:  # Valid MAC and IP
                            devices.append((ip, mac))
                    except:
                        continue
        
        except Exception as e:
            logger.debug(f"Failed to parse ARP table: {e}")
        
        return devices
    
    def merge_with_local_connections(self, local_connections: List[Dict]) -> Dict[str, Any]:
        """Merge router data with local machine connections.
        
        Returns:
            {
                'devices': {ip: DeviceInfo},
                'all_connections': List[RouterConnection],
                'dns_queries': {ip: [domains]},
                'local_ip': local_machine_ip
            }
        """
        try:
            devices = self.get_device_list()
            all_conns = self.get_all_device_connections()
            dns_data = self.get_all_dns_queries()
            
            # Attach DNS and connections to devices
            for ip, device in devices.items():
                device.dns_queries = dns_data.get(ip, [])
                device.connections = [c for c in all_conns if c.source_ip == ip]
            
            return {
                'devices': devices,
                'all_connections': all_conns,
                'dns_queries': dns_data,
                'local_ip': self.local_ip,
                'router_os': self.router_os,
                'connected': self.connected
            }
        
        except Exception as e:
            logger.error(f"Failed to merge data: {e}")
            return {
                'devices': {},
                'all_connections': [],
                'dns_queries': {},
                'local_ip': self.local_ip,
                'router_os': None,
                'connected': False,
                'error': str(e)
            }
    
    def test_connection(self) -> bool:
        """Quick test to verify router connectivity."""
        try:
            out, _, rc = self._run_command("uname -a")
            return rc == 0 and bool(out.strip())
        except:
            return False


def main():
    """Test router monitor."""
    import sys
    
    router_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
    
    print(f"Testing router at {router_ip}...")
    monitor = RouterMonitor(router_ip)
    
    if not monitor.connect(interactive=True):
        print("Failed to connect to router")
        return
    
    print(f"\nRouter OS: {monitor.router_os}")
    print(f"Local IP: {monitor.local_ip}")
    
    # Test getting data
    print("\nConnections from router:")
    conns = monitor.get_all_device_connections()
    for conn in conns[:10]:
        print(f"  {conn.source_ip}:{conn.source_port} -> {conn.dest_ip}:{conn.dest_port} ({conn.protocol})")
    
    print(f"\nTotal connections: {len(conns)}")
    
    print("\nDNS Queries by device:")
    dns = monitor.get_all_dns_queries(5)
    for ip, queries in list(dns.items())[:5]:
        print(f"  {ip}: {queries[:3]}...")
    
    print("\nDevices on network:")
    devices = monitor.get_device_list()
    for ip, dev in list(devices.items())[:5]:
        print(f"  {ip}: {dev.mac_address} ({dev.hostname})")
    
    monitor.disconnect()
    print("\nTest complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
