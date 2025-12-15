import nmap
from getmac import get_mac_address
from tabulate import tabulate
import requests
from functools import lru_cache
import socket
import ipaddress

# -------------------------------
# MAC Vendor Lookup
# -------------------------------
@lru_cache(maxsize=128)
def get_vendor_from_mac(mac):
    """Retrieve vendor name for a given MAC address via API lookup.
    
    Args:
        mac: MAC address string (e.g., "AA:BB:CC:DD:EE:FF")
        
    Returns:
        Vendor name or "Unknown" if lookup fails
    """
    if not mac:
        return "Unknown"
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        return response.text.strip() if response.status_code == 200 else "Unknown"
    except Exception:
        return "Unknown"


def get_local_subnet():
    """Auto-detect the local network subnet in CIDR notation.
    
    Returns:
        Subnet string in CIDR notation (e.g., "192.168.1.0/24")
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"
    return str(ipaddress.IPv4Network(local_ip + "/24", strict=False))

# -------------------------------
def identify_device_type(ip, vendor, nmap_data):
    last_octet = int(ip.split(".")[-1])
    vendor = vendor.lower() if vendor else ""
    tcp = nmap_data.get("tcp", {})

    # Router / Gateway (very strong signal - .1 address)
    if last_octet == 1:
        return "Router / Gateway"

    # IP Camera (RTSP protocol on port 554)
    if 554 in tcp:
        return "IP Camera"

    # OS fingerprint from nmap
    if nmap_data.get("osmatch"):
        os_name = nmap_data["osmatch"][0]["name"].lower()

        if any(x in os_name for x in ["windows", "mac os"]):
            return "Laptop / PC"

        if "linux" in os_name and any(p in tcp for p in [22, 3389, 5900]):
            return "Laptop / PC"

        if any(x in os_name for x in ["android", "ios"]):
            return "Phone / Tablet"

    # Weak vendor-only signal - insufficient evidence for classification
    return "Unknown (Insufficient Evidence)"

# -------------------------------
def assign_privacy_risks(device_type):
    if "router" in device_type.lower():
        return "Traffic Logs, Firewall, ISP Visibility"
    if "phone" in device_type.lower():
        return "Telemetry, Cloud Sync, App Data"
    if "laptop" in device_type.lower():
        return "OS Telemetry, Cloud Accounts"
    if "camera" in device_type.lower():
        return "Video, Audio, Cloud Streaming"
    return "Unknown"

# -------------------------------
def scan_network():
    subnet = get_local_subnet()
    print(f"\nScanning subnet: {subnet}\n")
    print("  Using ARP scan for device discovery (most reliable for LAN)")
    print("  For accurate OS detection (-O), run as Administrator\n")

    discovery = nmap.PortScanner()
    # Use -PR (ARP ping) for reliable local network discovery
    # This finds iPhones, Smart TVs, Echo devices, etc that don't respond to ICMP
    discovery.scan(hosts=subnet, arguments="-PR -sn")

    devices = []

    for host in discovery.all_hosts():
        mac = discovery[host]["addresses"].get("mac") or get_mac_address(ip=host)
        vendor = get_vendor_from_mac(mac)

        # Deep scan (new scanner → no overwrite bug)
        deep = {}
        confidence = "Low"

        try:
            deep_scanner = nmap.PortScanner()
            deep_scanner.scan(hosts=host, arguments="-O -sV --top-ports 20")
            if host in deep_scanner.all_hosts():
                deep = deep_scanner[host]
                confidence = "High"
        except Exception:
            pass

        device_type = identify_device_type(host, vendor, deep)
        privacy = assign_privacy_risks(device_type)
        
        # Extract open ports for privacy risk analysis
        open_ports = list(deep.get("tcp", {}).keys()) if deep else []
        
        # Log scan results
        if open_ports:
            print(f"  {host}: {len(open_ports)} ports open - {sorted(open_ports)[:10]}")
        else:
            print(f"  {host}: No ports found (confidence: {confidence})")

        devices.append({
            "IP": host,
            "MAC": mac or "Unknown",
            "Vendor": vendor,
            "Type": device_type,
            "Privacy": privacy,
            "Confidence": confidence,
            "Open Ports": open_ports
        })

    return devices

# -------------------------------
def display_devices(devices):
    """Display device scan results in a formatted table.
    
    Args:
        devices: List of device dicts from scan_network()
    """
    table = [
        [i+1, d["IP"], d["MAC"], d["Vendor"], d["Type"], d["Privacy"], d["Confidence"]]
        for i, d in enumerate(devices)
    ]
    print(tabulate(
        table,
        headers=[
            "#", "IP Address", "MAC Address",
            "Vendor", "Device Type",
            "Privacy / Capabilities", "Confidence"
        ],
        tablefmt="grid"
    ))

# -------------------------------

if __name__ == "__main__":
    """Entry point for direct module execution."""
    devices = scan_network()
    display_devices(devices)
