"""Device profiling and identification module.

Identifies device types, manufacturers, and capabilities through:
  - mDNS/Bonjour discovery (device names and services)
  - Banner grabbing (HTTP, SSH server identification)
  - MAC address OUI lookup (manufacturer detection)
  - Port scanning results analysis
  - Hostname resolution
  - Historical connection patterns

Usage:
    profiler = DeviceProfiler()
    profiles = profiler.profile_device('192.168.1.100', '00:11:22:33:44:55')
    
    # With mDNS
    mdns_info = profiler.get_mdns_info()
"""

import socket
import struct
import subprocess
import re
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
import requests

try:
    from zeroconf import ServiceBrowser, Zeroconf, ServiceStateChange
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False

logger = logging.getLogger(__name__)


def assign_privacy_risks(device_type: str) -> str:
    """Assign privacy risk categories based on device type.
    
    Args:
        device_type: Classification of device (e.g., "Router", "Laptop", "Camera")
    
    Returns:
        String describing primary privacy/data risks for this device type
    """
    device_type_lower = device_type.lower()
    
    if "router" in device_type_lower or "gateway" in device_type_lower:
        return "Traffic Logs, Firewall, ISP Visibility"
    if "phone" in device_type_lower or "tablet" in device_type_lower:
        return "Telemetry, Cloud Sync, App Data, Location"
    if "laptop" in device_type_lower or "pc" in device_type_lower:
        return "OS Telemetry, Cloud Accounts, Browser History"
    if "camera" in device_type_lower:
        return "Video, Audio, Cloud Streaming, Snapshots"
    if "printer" in device_type_lower:
        return "Scanned Documents, Cloud Upload, Usage Data"
    if "speaker" in device_type_lower or "smart home" in device_type_lower:
        return "Voice Recordings, Behavioral Patterns, Cloud Sync"
    if "tv" in device_type_lower or "streaming" in device_type_lower:
        return "Viewing Habits, Cloud Sync, Advertising ID"
    if "nvr" in device_type_lower or "nas" in device_type_lower:
        return "Stored Files, Access Logs, Remote Access"
    
    return "Unknown"


# MAC Address OUI (Organizationally Unique Identifier) Database
# Maps first 3 octets (vendor prefix) to manufacturer name
MAC_OUI_DATABASE = {
    # Apple
    '00:05:02': 'Apple',
    '00:0A:27': 'Apple',
    '00:1A:4D': 'Apple',
    '00:1C:B0': 'Apple',
    '00:1D:4F': 'Apple',
    '00:1E:52': 'Apple',
    '00:21:E9': 'Apple',
    '00:22:41': 'Apple',
    '00:23:6C': 'Apple',
    '00:24:36': 'Apple',
    '00:25:00': 'Apple',
    '00:25:86': 'Apple',
    '00:26:4A': 'Apple',
    
    # Samsung
    '00:1C:01': 'Samsung',
    '00:16:32': 'Samsung',
    '00:0D:14': 'Samsung',
    '50:F2:C5': 'Samsung',
    'A4:D1:D2': 'Samsung',
    '94:BA:7F': 'Samsung',
    
    # LG Electronics
    '00:02:C7': 'LG Electronics',
    '00:0D:96': 'LG Electronics',
    '00:19:37': 'LG Electronics',
    '00:1E:8F': 'LG Electronics',
    '00:1F:E1': 'LG Electronics',
    '34:23:87': 'LG Electronics',
    
    # TP-Link
    '54:04:A6': 'TP-Link',
    'C8:3A:35': 'TP-Link',
    '08:10:76': 'TP-Link',
    
    # Philips (Hue)
    '00:17:88': 'Philips',
    '00:21:9E': 'Philips',
    'EC:B5:FA': 'Philips',
    '00:22:A3': 'Philips',
    
    # Amazon
    '00:13:10': 'Amazon',
    '00:0A:95': 'Amazon',
    '50:F5:DA': 'Amazon',
    '54:60:09': 'Amazon',
    
    # Google
    '00:18:6B': 'Google',
    '00:1F:3F': 'Google',
    '00:25:31': 'Google',
    '00:26:15': 'Google',
    'AC:BC:32': 'Google',
    '90:18:87': 'Google',
    
    # Nest (Google)
    '18:B4:30': 'Google Nest',
    
    # Sonos
    '00:0E:58': 'Sonos',
    '54:38:75': 'Sonos',
    
    # Ring (Amazon)
    'C4:91:37': 'Ring',
    
    # Wyze
    '00:25:86': 'Wyze',
    'A0:80:69': 'Wyze',
    
    # Netgear
    '00:03:25': 'Netgear',
    '00:04:6B': 'Netgear',
    'B8:27:EB': 'Netgear',
    
    # Microsoft
    '00:01:02': 'Microsoft',
    '00:0C:29': 'Microsoft',
    '00:1F:29': 'Microsoft',
    '44:2C:05': 'Microsoft',
    
    # NVIDIA
    '00:04:4B': 'NVIDIA',
    '00:05:47': 'NVIDIA',
    
    # Cisco/Linksys
    '00:04:5A': 'Cisco/Linksys',
    '00:0B:85': 'Cisco/Linksys',
    '00:0F:66': 'Cisco/Linksys',
    
    # Brother Industries
    '00:80:77': 'Brother Industries',
    '00:1B:A0': 'Brother Industries',
    
    # Canon
    '00:08:25': 'Canon',
    '00:19:09': 'Canon',
    
    # Xerox
    '00:00:93': 'Xerox',
    '00:07:8C': 'Xerox',
    
    # HP/Hewlett Packard
    '00:12:79': 'HP',
    '00:14:38': 'HP',
    '00:1B:78': 'HP',
    'E0:55:3D': 'HP',
    
    # Epson
    '00:0A:F4': 'Epson',
    '00:0D:3E': 'Epson',
    
    # GoPro
    '00:18:56': 'GoPro',
    'B8:A6:1F': 'GoPro',
}


@dataclass
class DeviceProfile:
    """Complete device profile and identification."""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: str = "Unknown"  # Phone, Laptop, IoT Device, Camera, Router, Printer, etc.
    confidence: float = 0.0  # 0.0-1.0, how sure we are about the identification
    os_type: Optional[str] = None  # iOS, Android, Windows, Linux, macOS, etc.
    mdns_name: Optional[str] = None
    mdns_services: List[str] = None  # Bonjour services advertised
    ssh_banner: Optional[str] = None
    http_server: Optional[str] = None  # From HTTP Server header
    open_ports: List[int] = None
    inferred_services: List[str] = None  # Inferred from ports and banners
    
    def __post_init__(self):
        if self.mdns_services is None:
            self.mdns_services = []
        if self.open_ports is None:
            self.open_ports = []
        if self.inferred_services is None:
            self.inferred_services = []


class DeviceProfiler:
    """Identify and profile network devices."""
    
    def __init__(self):
        """Initialize device profiler."""
        self.mdns_zeroconf: Optional[Any] = None
        self.mdns_devices: Dict[str, Dict[str, Any]] = {}
        self.mdns_ready = False
    
    def start_mdns_discovery(self, timeout: int = 5) -> bool:
        """Start mDNS/Bonjour discovery.
        
        Args:
            timeout: How long to listen for mDNS announcements
        
        Returns:
            True if mDNS discovery started, False otherwise
        """
        if not HAS_ZEROCONF:
            logger.warning("zeroconf (Bonjour) not available")
            return False
        
        try:
            print(f"Starting mDNS discovery for {timeout}s...")
            self.mdns_zeroconf = Zeroconf()
            
            # Service browser for common device types
            services = [
                '_http._tcp.local.',
                '_ssh._tcp.local.',
                '_printer._tcp.local.',
                '_airplay._tcp.local.',
                '_raop._tcp.local.',
                '_dacp._tcp.local.',
                '_spotify-connect._tcp.local.',
                '_hap._tcp.local.',  # HomeKit
                '_homekit._tcp.local.',
            ]
            
            browsers = []
            for service in services:
                try:
                    browser = ServiceBrowser(
                        self.mdns_zeroconf,
                        service,
                        handlers=[self._on_mdns_service_state_change]
                    )
                    browsers.append(browser)
                except Exception as e:
                    logger.debug(f"Could not browse {service}: {e}")
            
            # Wait for responses
            time.sleep(timeout)
            
            # Close browsers
            for browser in browsers:
                browser.cancel()
            
            self.mdns_ready = len(self.mdns_devices) > 0
            return True
        
        except Exception as e:
            logger.error(f"mDNS discovery failed: {e}")
            return False
    
    def stop_mdns_discovery(self):
        """Stop mDNS/Bonjour discovery."""
        if self.mdns_zeroconf:
            self.mdns_zeroconf.close()
            self.mdns_zeroconf = None
    
    def _on_mdns_service_state_change(self, zeroconf, service_type, name, state_change):
        """Callback when mDNS service state changes."""
        if state_change == ServiceStateChange.Added:
            try:
                info = zeroconf.get_service_info(service_type, name)
                if info:
                    ip = None
                    if info.addresses:
                        # Convert address bytes to IP string
                        for addr in info.addresses:
                            if len(addr) == 4:  # IPv4
                                ip = '.'.join(str(b) for b in addr)
                                break
                    
                    if ip:
                        if ip not in self.mdns_devices:
                            self.mdns_devices[ip] = {
                                'names': [],
                                'services': [],
                                'properties': {}
                            }
                        
                        self.mdns_devices[ip]['names'].append(name)
                        self.mdns_devices[ip]['services'].append(service_type)
                        if hasattr(info, 'properties'):
                            self.mdns_devices[ip]['properties'].update(info.properties)
            except Exception as e:
                logger.debug(f"Error processing mDNS service: {e}")
    
    def lookup_mac_manufacturer(self, mac_address: str) -> str:
        """Look up MAC vendor (Two-Tier: API → Offline Database).
        
        Tier 1: Try API (macvendors.com) for current data
        Tier 2: Fall back to local offline database
        
        Args:
            mac_address: MAC address (e.g., "AA:BB:CC:DD:EE:FF")
        
        Returns:
            Manufacturer name or "Unknown"
        """
        if not mac_address:
            return "Unknown"
        
        # TIER 1: Try online API
        try:
            response = requests.get(
                f"https://api.macvendors.com/{mac_address}",
                timeout=2
            )
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor:
                    return vendor
        except Exception:
            pass  # Fall through to local database
        
        # TIER 2: Fall back to offline database
        try:
            oui = ':'.join(mac_address.split(':')[:3]).upper()
            if oui in MAC_OUI_DATABASE:
                return MAC_OUI_DATABASE[oui]
            if oui.startswith('B8:27:EB'):  # Raspberry Pi
                return 'Raspberry Pi Foundation'
        except (IndexError, AttributeError, ValueError):
            pass
        
        return "Unknown"
    
    def get_banner(self, ip_address: str, port: int, timeout: int = 2) -> Optional[str]:
        """Get service banner from a port.
        
        Args:
            ip_address: Target IP
            port: Target port
            timeout: Connection timeout in seconds
        
        Returns:
            Banner text or None if connection failed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip_address, port))
            
            # Read banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip() if banner else None
        
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"Banner grab failed for {ip_address}:{port}: {e}")
            return None
    
    def get_ssh_info(self, ip_address: str) -> Optional[str]:
        """Get SSH server banner (identify OS/device type).
        
        Args:
            ip_address: Target IP
        
        Returns:
            SSH banner (e.g., "OpenSSH_7.4") or None
        """
        return self.get_banner(ip_address, 22)
    
    def get_http_server(self, ip_address: str) -> Optional[str]:
        """Get HTTP Server header.
        
        Args:
            ip_address: Target IP
        
        Returns:
            Server string (e.g., "nginx/1.16.0") or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip_address, 80))
            
            # Send HTTP request
            sock.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Extract Server header
            for line in response.split('\r\n'):
                if line.lower().startswith('server:'):
                    return line[7:].strip()
        
        except Exception:
            pass
        
        return None
    
    def infer_device_type(self, ip_address: str, mac_address: Optional[str],
                         open_ports: List[int],
                         mdns_info: Optional[Dict[str, Any]] = None) -> Tuple[str, float]:
        """Infer device type from available signals.
        
        Args:
            ip_address: Device IP
            mac_address: Device MAC (optional)
            open_ports: List of open ports detected
            mdns_info: mDNS/Bonjour info dict
        
        Returns:
            Tuple of (device_type, confidence)
        """
        signals = []
        
        # Check mDNS services
        if mdns_info and mdns_info.get('services'):
            services = ' '.join(mdns_info['services']).lower()
            
            if '_airplay' in services or '_raop' in services:
                signals.append(('Apple TV / Airplay Device', 0.9))
            if '_homekit' in services or '_hap' in services:
                signals.append(('HomeKit Device', 0.85))
            if '_dacp' in services:
                signals.append(('Apple Device', 0.8))
            if '_printer' in services:
                signals.append(('Printer', 0.95))
        
        # Check HTTP Server header
        http_server = self.get_http_server(ip_address)
        if http_server:
            lower = http_server.lower()
            
            if 'asus' in lower or 'merlin' in lower:
                signals.append(('Router (ASUS)', 0.9))
            if 'netgear' in lower:
                signals.append(('Router (Netgear)', 0.9))
            if 'linksys' in lower:
                signals.append(('Router (Linksys)', 0.9))
            if 'openwrt' in lower:
                signals.append(('Router (OpenWrt)', 0.95))
            if 'nginx' in lower and 22 in open_ports:
                signals.append(('Linux Server', 0.7))
            if 'apache' in lower:
                signals.append(('Web Server', 0.6))
        
        # Check SSH
        ssh_banner = self.get_ssh_info(ip_address)
        if ssh_banner:
            lower = ssh_banner.lower()
            
            if 'openssh' in lower:
                if '6.6' in lower or '7.4' in lower:
                    signals.append(('Linux Device / NAS', 0.7))
                else:
                    signals.append(('Linux / Unix Device', 0.6))
            if 'libssh' in lower:
                signals.append(('Embedded Device', 0.6))
        
        # Check ports
        if 445 in open_ports or 139 in open_ports:
            signals.append(('Windows PC / NAS', 0.7))
        
        if 5900 in open_ports or 5901 in open_ports:
            signals.append(('Mac / VNC Server', 0.6))
        
        if 3306 in open_ports or 5432 in open_ports:
            signals.append(('Database Server', 0.7))
        
        # Check MAC manufacturer
        if mac_address:
            manufacturer = self.lookup_mac_manufacturer(mac_address)
            if manufacturer and manufacturer != "Unknown":
                signals.append((f"{manufacturer} Device", 0.6))
        
        # Combine signals
        if signals:
            # Weight votes by confidence
            votes = defaultdict(float)
            for device_type, confidence in signals:
                votes[device_type] += confidence
            
            # Get highest scoring device type
            best_type = max(votes.items(), key=lambda x: x[1])
            avg_confidence = best_type[1] / len([s for s in signals if s[0] == best_type[0]])
            
            return best_type[0], min(1.0, avg_confidence)
        
        return "Unknown Device", 0.3
    
    def profile_device(self, ip_address: str, mac_address: Optional[str] = None,
                      hostname: Optional[str] = None,
                      open_ports: Optional[List[int]] = None) -> DeviceProfile:
        """Create a complete profile for a network device.
        
        Args:
            ip_address: Device IP address
            mac_address: Device MAC address (optional)
            hostname: Device hostname (optional)
            open_ports: List of detected open ports (optional)
        
        Returns:
            DeviceProfile with all available information
        """
        if open_ports is None:
            open_ports = []
        
        # Look up mDNS info if available
        mdns_info = self.mdns_devices.get(ip_address)
        mdns_name = None
        if mdns_info and mdns_info['names']:
            mdns_name = mdns_info['names'][0]
        
        # Get manufacturer from MAC
        manufacturer = "Unknown"
        if mac_address:
            manufacturer = self.lookup_mac_manufacturer(mac_address)
        
        # Get service banners
        ssh_banner = None
        if 22 in open_ports:
            ssh_banner = self.get_ssh_info(ip_address)
        
        http_server = None
        if 80 in open_ports or 8080 in open_ports:
            http_server = self.get_http_server(ip_address)
        
        # Infer device type
        device_type, confidence = self.infer_device_type(
            ip_address, mac_address, open_ports, mdns_info
        )
        
        return DeviceProfile(
            ip_address=ip_address,
            mac_address=mac_address,
            hostname=hostname or mdns_name,
            manufacturer=manufacturer,
            device_type=device_type,
            confidence=confidence,
            mdns_name=mdns_name,
            mdns_services=mdns_info['services'] if mdns_info else [],
            ssh_banner=ssh_banner,
            http_server=http_server,
            open_ports=open_ports,
        )


def main():
    """Test device profiling."""
    logging.basicConfig(level=logging.INFO)
    
    profiler = DeviceProfiler()
    
    # Start mDNS discovery
    print("Starting mDNS discovery...")
    profiler.start_mdns_discovery(timeout=3)
    
    # Profile a test device
    test_ip = "192.168.1.1"
    print(f"\nProfiling {test_ip}...")
    
    profile = profiler.profile_device(test_ip, open_ports=[22, 80, 443])
    
    print(f"\nDevice Profile:")
    print(f"  IP: {profile.ip_address}")
    print(f"  Type: {profile.device_type} (confidence: {profile.confidence:.0%})")
    print(f"  Manufacturer: {profile.manufacturer}")
    print(f"  SSH: {profile.ssh_banner}")
    print(f"  HTTP Server: {profile.http_server}")
    print(f"  mDNS Name: {profile.mdns_name}")
    print(f"  mDNS Services: {profile.mdns_services}")
    
    profiler.stop_mdns_discovery()


if __name__ == "__main__":
    main()
