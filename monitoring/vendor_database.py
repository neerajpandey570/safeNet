"""Vendor IP ranges and domain database.

Maps IP address ranges and domains to vendors and service categories.
Used to identify what company/service a connection is to.

Classification:
  FUNCTIONAL: Essential for device to work (streaming, video call, etc)
  TELEMETRY: Optional data collection (usage analytics, crash reports)
  ADVERTISING: Ad networks and tracking pixels
  CLOUD: Cloud storage and sync services
  INFRASTRUCTURE: Essential infrastructure (NTP, DNS, updates)
"""

import ipaddress
from typing import Dict, List, Optional, Tuple


# Major vendors and their IP ranges (CIDR notation)
# Sources: AWS IP ranges, Google Cloud, Azure, etc.
VENDOR_IP_RANGES = {
    "Google": [
        "142.251.0.0/16",
        "172.217.0.0/16",
        "172.218.0.0/16",
        "172.219.0.0/16",
        "172.220.0.0/16",
        "172.221.0.0/16",
        "172.222.0.0/16",
        "172.223.0.0/16",
        "199.36.153.4/30",
        "199.36.153.8/30",
    ],
    "Amazon AWS": [
        "13.32.0.0/11",
        "13.33.0.0/16",
        "13.34.0.0/16",
        "13.35.0.0/16",
        "13.36.0.0/16",
        "13.37.0.0/16",
        "13.38.0.0/16",
        "13.39.0.0/16",
        "13.40.0.0/16",
        "13.41.0.0/16",
        "13.42.0.0/16",
        "13.43.0.0/16",
        "13.44.0.0/16",
        "13.45.0.0/16",
        "13.46.0.0/16",
        "13.48.0.0/15",
        "13.50.0.0/16",
        "13.51.0.0/16",
        "13.52.0.0/16",
        "13.53.0.0/16",
        "13.54.0.0/16",
        "13.55.0.0/16",
        "13.56.0.0/16",
        "13.57.0.0/16",
        "13.58.0.0/16",
        "13.59.0.0/16",
        "13.107.0.0/16",
        "13.108.0.0/16",
        "13.109.0.0/16",
    ],
    "Microsoft Azure": [
        "13.64.0.0/11",
        "13.96.0.0/13",
        "13.104.0.0/14",
        "20.0.0.0/8",
        "23.96.0.0/13",
        "40.64.0.0/10",
        "40.128.0.0/9",
        "52.0.0.0/6",
        "64.4.0.0/14",
    ],
    "Meta/Facebook": [
        "31.13.24.0/21",
        "31.13.33.0/24",
        "31.13.35.0/24",
        "31.13.64.0/18",
        "31.13.128.0/17",
        "45.64.40.0/22",
        "45.64.56.0/22",
        "45.64.88.0/22",
        "45.64.92.0/22",
        "45.64.96.0/22",
        "45.64.100.0/22",
        "45.64.102.0/22",
        "45.64.104.0/22",
        "45.64.108.0/22",
        "45.64.110.0/22",
        "45.64.112.0/22",
        "45.64.116.0/22",
        "45.64.118.0/22",
        "45.64.120.0/22",
    ],
    "Apple": [
        "17.142.0.0/16",
        "17.143.0.0/16",
        "17.144.0.0/16",
        "17.145.0.0/16",
        "17.146.0.0/16",
        "17.147.0.0/16",
        "17.148.0.0/16",
        "17.149.0.0/16",
        "17.150.0.0/16",
        "17.151.0.0/16",
        "17.152.0.0/16",
        "17.153.0.0/16",
        "17.154.0.0/16",
        "17.155.0.0/16",
        "17.156.0.0/16",
        "17.157.0.0/16",
        "17.158.0.0/16",
        "17.159.0.0/16",
    ],
    "Netflix": [
        "198.38.0.0/16",
        "198.39.0.0/16",
        "198.45.0.0/16",
        "198.51.100.0/24",
    ],
    "CloudFlare": [
        "104.16.0.0/12",
    ],
    "Samsung": [
        "58.29.0.0/16",
        "125.209.0.0/16",
    ],
    "LG Electronics": [
        "61.42.0.0/16",
        "114.207.0.0/16",
    ],
    "TP-Link": [
        "120.26.0.0/16",
    ],
    "Philips": [
        "195.34.89.0/24",
        "31.3.104.0/22",
    ],
    "NVIDIA": [
        "198.41.0.0/16",
        "199.27.0.0/16",
    ],
    "Intel": [
        "1.28.0.0/13",
        "134.134.0.0/16",
    ],
    "Qualcomm": [
        "64.76.0.0/14",
    ],
    "MediaTek": [
        "118.173.0.0/16",
    ],
    "Broadcom": [
        "12.96.0.0/12",
    ],
    "Realtek": [
        "58.154.0.0/15",
    ],
    "Sonos": [
        "77.50.0.0/16",
    ],
    "Ring": [
        "142.132.0.0/15",
        "88.198.0.0/13",
    ],
    "Wyze": [
        "52.87.0.0/16",
        "13.92.0.0/14",
    ],
    "ASUS": [
        "61.228.0.0/15",
        "61.230.0.0/15",
    ],
    "Netgear": [
        "61.240.0.0/14",
    ],
    "D-Link": [
        "210.105.0.0/16",
    ],
    "Belkin": [
        "76.13.0.0/16",
    ],
    "Rpi Foundation": [
        "217.23.0.0/16",
    ],
    "Ubiquiti": [
        "108.166.0.0/16",
    ],
}

# Domain patterns and their services
VENDOR_DOMAINS = {
    # Google Services
    "google.com": {"vendor": "Google", "service": "Search", "category": "FUNCTIONAL"},
    "googleapis.com": {"vendor": "Google", "service": "Google APIs", "category": "TELEMETRY"},
    "googleanalytics.com": {"vendor": "Google", "service": "Analytics", "category": "TELEMETRY"},
    "google-analytics.com": {"vendor": "Google", "service": "Analytics", "category": "TELEMETRY"},
    "gstatic.com": {"vendor": "Google", "service": "Static Content", "category": "FUNCTIONAL"},
    "googleusercontent.com": {"vendor": "Google", "service": "User Content", "category": "FUNCTIONAL"},
    "gmail.com": {"vendor": "Google", "service": "Email", "category": "FUNCTIONAL"},
    "maps.google.com": {"vendor": "Google", "service": "Maps/Location", "category": "FUNCTIONAL"},
    "youtubeadvertisements.g.doubleclick.net": {"vendor": "Google", "service": "YouTube Ads", "category": "ADVERTISING"},
    "youtube.com": {"vendor": "Google", "service": "Video Streaming", "category": "FUNCTIONAL"},
    
    # Meta/Facebook Services
    "facebook.com": {"vendor": "Meta", "service": "Social Media", "category": "FUNCTIONAL"},
    "instagram.com": {"vendor": "Meta", "service": "Social Media", "category": "FUNCTIONAL"},
    "fbcdn.net": {"vendor": "Meta", "service": "CDN", "category": "FUNCTIONAL"},
    "doubleclick.net": {"vendor": "Google/DoubleClick", "service": "Advertising", "category": "ADVERTISING"},
    
    # Amazon Services
    "amazon.com": {"vendor": "Amazon", "service": "E-commerce", "category": "FUNCTIONAL"},
    "amazonaws.com": {"vendor": "Amazon AWS", "service": "Cloud Storage", "category": "CLOUD"},
    "amazon-adsystem.com": {"vendor": "Amazon", "service": "Advertising", "category": "ADVERTISING"},
    "alexa.amazon.com": {"vendor": "Amazon", "service": "Voice Assistant", "category": "TELEMETRY"},
    
    # Apple Services
    "apple.com": {"vendor": "Apple", "service": "Apple Services", "category": "FUNCTIONAL"},
    "icloud.com": {"vendor": "Apple", "service": "Cloud Storage", "category": "CLOUD"},
    "push.apple.com": {"vendor": "Apple", "service": "Push Notifications", "category": "FUNCTIONAL"},
    
    # Microsoft Services
    "microsoft.com": {"vendor": "Microsoft", "service": "Services", "category": "FUNCTIONAL"},
    "onedrive.live.com": {"vendor": "Microsoft", "service": "Cloud Storage", "category": "CLOUD"},
    "outlook.com": {"vendor": "Microsoft", "service": "Email", "category": "FUNCTIONAL"},
    "windows.com": {"vendor": "Microsoft", "service": "Windows Updates", "category": "INFRASTRUCTURE"},
    
    # Streaming Services
    "netflix.com": {"vendor": "Netflix", "service": "Streaming", "category": "FUNCTIONAL"},
    "nflxso.net": {"vendor": "Netflix", "service": "Streaming", "category": "FUNCTIONAL"},
    "spotify.com": {"vendor": "Spotify", "service": "Music Streaming", "category": "FUNCTIONAL"},
    "akamai.com": {"vendor": "Akamai", "service": "CDN", "category": "FUNCTIONAL"},
    
    # Cloud Storage
    "dropbox.com": {"vendor": "Dropbox", "service": "Cloud Storage", "category": "CLOUD"},
    "box.com": {"vendor": "Box", "service": "Cloud Storage", "category": "CLOUD"},
    "sync.com": {"vendor": "Sync.com", "service": "Cloud Storage", "category": "CLOUD"},
    "nextcloud.com": {"vendor": "Nextcloud", "service": "Cloud Storage", "category": "CLOUD"},
    
    # IoT Platforms & Hubs
    "amazon-devices.com": {"vendor": "Amazon", "service": "IoT Devices", "category": "TELEMETRY"},
    "smartthings.com": {"vendor": "Samsung", "service": "Smart Home Hub", "category": "TELEMETRY"},
    "googleapis.com/storage": {"vendor": "Google", "service": "Cloud Storage", "category": "CLOUD"},
    
    # Device Manufacturers & Smart Home
    "samsung.com": {"vendor": "Samsung", "service": "Samsung Services", "category": "TELEMETRY"},
    "lg.com": {"vendor": "LG Electronics", "service": "LG Services", "category": "TELEMETRY"},
    "tp-link.com": {"vendor": "TP-Link", "service": "Router/Network", "category": "FUNCTIONAL"},
    "philips.com": {"vendor": "Philips", "service": "Smart Lighting", "category": "FUNCTIONAL"},
    "philips-hue.com": {"vendor": "Philips", "service": "Hue Lighting", "category": "FUNCTIONAL"},
    "meethue.com": {"vendor": "Philips", "service": "Hue App", "category": "TELEMETRY"},
    "wyze.com": {"vendor": "Wyze", "service": "Smart Home", "category": "TELEMETRY"},
    "wyzecam.com": {"vendor": "Wyze", "service": "Smart Camera", "category": "TELEMETRY"},
    "ring.com": {"vendor": "Ring", "service": "Video Doorbell", "category": "TELEMETRY"},
    "nesthub.google.com": {"vendor": "Google", "service": "Nest Hub", "category": "TELEMETRY"},
    "nest.com": {"vendor": "Google", "service": "Nest Services", "category": "TELEMETRY"},
    "sonos.com": {"vendor": "Sonos", "service": "Speaker System", "category": "FUNCTIONAL"},
    
    # Printers & Peripherals
    "hp.com": {"vendor": "HP", "service": "Printer", "category": "FUNCTIONAL"},
    "canon.com": {"vendor": "Canon", "service": "Printer/Camera", "category": "FUNCTIONAL"},
    "epson.com": {"vendor": "Epson", "service": "Printer", "category": "FUNCTIONAL"},
    "xerox.com": {"vendor": "Xerox", "service": "Printer", "category": "FUNCTIONAL"},
    "brother.com": {"vendor": "Brother", "service": "Printer", "category": "FUNCTIONAL"},
    
    # VPN & Security
    "expressvpn.com": {"vendor": "ExpressVPN", "service": "VPN", "category": "FUNCTIONAL"},
    "nordvpn.com": {"vendor": "NordVPN", "service": "VPN", "category": "FUNCTIONAL"},
    "protonvpn.com": {"vendor": "ProtonVPN", "service": "VPN", "category": "FUNCTIONAL"},
    "tailscale.com": {"vendor": "Tailscale", "service": "VPN", "category": "FUNCTIONAL"},
    
    # Software & Development
    "ubuntu.com": {"vendor": "Canonical", "service": "Software", "category": "INFRASTRUCTURE"},
    "ntp.ubuntu.com": {"vendor": "Ubuntu", "service": "NTP Time Server", "category": "INFRASTRUCTURE"},
    "cloudflare.com": {"vendor": "Cloudflare", "service": "CDN/DNS", "category": "INFRASTRUCTURE"},
    "1.1.1.1": {"vendor": "Cloudflare", "service": "Public DNS", "category": "INFRASTRUCTURE"},
    "8.8.8.8": {"vendor": "Google", "service": "Public DNS", "category": "INFRASTRUCTURE"},
    "8.8.4.4": {"vendor": "Google", "service": "Public DNS", "category": "INFRASTRUCTURE"},
    
    # Social & Messaging
    "whatsapp.com": {"vendor": "Meta", "service": "Messaging", "category": "FUNCTIONAL"},
    "telegram.org": {"vendor": "Telegram", "service": "Messaging", "category": "FUNCTIONAL"},
    "discord.com": {"vendor": "Discord", "service": "Voice Chat", "category": "FUNCTIONAL"},
    "slack.com": {"vendor": "Slack", "service": "Team Chat", "category": "FUNCTIONAL"},
    
    # Analytics & Telemetry
    "amplitude.com": {"vendor": "Amplitude", "service": "Analytics", "category": "TELEMETRY"},
    "mixpanel.com": {"vendor": "Mixpanel", "service": "Analytics", "category": "TELEMETRY"},
    "segment.com": {"vendor": "Segment", "service": "Analytics", "category": "TELEMETRY"},
    "firebase.google.com": {"vendor": "Google Firebase", "service": "Analytics", "category": "TELEMETRY"},
    "sentry.io": {"vendor": "Sentry", "service": "Error Tracking", "category": "TELEMETRY"},
    
    # Advertising Networks
    "adroll.com": {"vendor": "AdRoll", "service": "Ad Network", "category": "ADVERTISING"},
    "criteo.com": {"vendor": "Criteo", "service": "Ad Network", "category": "ADVERTISING"},
    "openx.com": {"vendor": "OpenX", "service": "Ad Exchange", "category": "ADVERTISING"},
    "pubmatic.com": {"vendor": "PubMatic", "service": "Ad Exchange", "category": "ADVERTISING"},
    
    # Video Conferencing
    "zoom.us": {"vendor": "Zoom", "service": "Video Conference", "category": "FUNCTIONAL"},
    "skype.com": {"vendor": "Microsoft", "service": "Video Call", "category": "FUNCTIONAL"},
    "webex.com": {"vendor": "Cisco", "service": "Video Conference", "category": "FUNCTIONAL"},
}


def find_vendor_by_ip(ip_address: str) -> Optional[str]:
    """Find vendor owning an IP address.
    
    Args:
        ip_address: IP address to check
    
    Returns:
        Vendor name or None
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip_address)
    except ValueError:
        return None
    
    for vendor, ranges in VENDOR_IP_RANGES.items():
        for cidr in ranges:
            try:
                network = ipaddress.IPv4Network(cidr, strict=False)
                if ip_obj in network:
                    return vendor
            except ValueError:
                continue
    
    return None


def find_vendor_by_domain(domain: str) -> Optional[Dict[str, str]]:
    """Find vendor information for a domain.
    
    Args:
        domain: Domain name
    
    Returns:
        Dict with vendor, service, category or None
    """
    domain_lower = domain.lower()
    
    # Exact match
    if domain_lower in VENDOR_DOMAINS:
        return VENDOR_DOMAINS[domain_lower]
    
    # Suffix match (e.g., "api.google.com" matches "google.com")
    for known_domain, info in VENDOR_DOMAINS.items():
        if domain_lower.endswith(known_domain):
            return info
    
    return None


def classify_connection(remote_ip: str, domain: Optional[str] = None) -> Dict[str, str]:
    """Classify a connection by IP and/or domain.
    
    Args:
        remote_ip: Remote IP address
        domain: Remote domain (optional)
    
    Returns:
        Dict with: vendor, service, category
    """
    result = {
        "vendor": "Unknown",
        "service": "Unknown",
        "category": "UNKNOWN"
    }
    
    # Try domain first (more reliable)
    if domain:
        domain_info = find_vendor_by_domain(domain)
        if domain_info:
            return domain_info
    
    # Fall back to IP
    vendor = find_vendor_by_ip(remote_ip)
    if vendor:
        result["vendor"] = vendor
        result["service"] = vendor  # Default service = vendor name
        # Infer category from vendor
        if vendor in ["Google", "Amazon AWS", "Microsoft Azure", "Meta/Facebook"]:
            result["category"] = "CLOUD"
        else:
            result["category"] = "FUNCTIONAL"
    
    return result


def get_category_explanation(category: str) -> str:
    """Get explanation of what a category means.
    
    Args:
        category: Category name
    
    Returns:
        Human-readable explanation
    """
    explanations = {
        "FUNCTIONAL": "Essential service - device needs this to work properly",
        "TELEMETRY": "Usage data collection - optional, can usually be disabled",
        "ADVERTISING": "Ad network tracking - can usually be blocked without impact",
        "CLOUD": "Cloud storage/sync - stores your data on remote servers",
        "INFRASTRUCTURE": "Core network service - needed for basic functionality",
        "UNKNOWN": "Unidentified service - classify with caution"
    }
    
    return explanations.get(category, "Unknown category")


def can_safely_block(category: str) -> bool:
    """Determine if a connection can be safely blocked.
    
    Args:
        category: Connection category
    
    Returns:
        True if safe to block, False otherwise
    """
    return category in ["ADVERTISING", "TELEMETRY"]


# ============================================================================
# Simple CLI test
# ============================================================================

if __name__ == "__main__":
    print("SafeNet - Vendor Database")
    print("=" * 60)
    print()
    
    # Test IP lookup
    test_ips = [
        "142.251.32.5",      # Google
        "31.13.64.50",       # Facebook
        "52.42.189.100",     # AWS
        "198.38.10.50",      # Netflix
        "192.168.1.1",       # Local
        "185.22.33.44",      # NTP
    ]
    
    print("Testing IP-to-Vendor Lookup:")
    for ip in test_ips:
        vendor = find_vendor_by_ip(ip)
        print(f"  {ip:.<20} → {vendor or 'Unknown'}")
    
    print("\n" + "=" * 60)
    print("\nTesting Domain-to-Vendor Lookup:")
    
    test_domains = [
        "google.com",
        "api.google.com",
        "facebook.com",
        "doubleclick.net",
        "amazonaws.com",
        "ntp.ubuntu.com",
    ]
    
    for domain in test_domains:
        info = find_vendor_by_domain(domain)
        if info:
            print(f"  {domain:.<25} → {info['vendor']} ({info['category']})")
        else:
            print(f"  {domain:.<25} → Unknown")
