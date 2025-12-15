from datetime import datetime
import os
import json
from typing import Dict, List, Any, Optional

def _safe_lower(s: str) -> str:
    """Safely convert string to lowercase, handling None values."""
    return (s or "").lower()

def _has_port(device: dict, port: int) -> bool:
    """Check if a port is in device's open ports list."""
    return port in (device.get("Open Ports") or [])

def suggest_blocking_rules(connection_analysis: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    """Generate specific firewall rules for blocking unsafe connections.
    
    Args:
        connection_analysis: Result from connection_analyzer.analyze_connections()
    
    Returns:
        List of blocking rule recommendations with exact IPs/domains
    """
    rules = []
    
    if not connection_analysis:
        return rules
    
    # Get blocking recommendations from analyzer
    blocking_recs = connection_analysis.get('blocking_recommendations', [])
    
    for rec in blocking_recs:
        endpoint = rec.get('endpoint', '')
        vendor = rec.get('vendor', '')
        category = rec.get('category', '')
        remote_ip = rec['connection'].get('remote_ip', '')
        remote_port = rec['connection'].get('remote_port', '')
        
        # Generate platform-specific blocking rules
        rule = {
            'endpoint': endpoint,
            'vendor': vendor,
            'category': category,
            'reason': rec.get('reason', ''),
            'Windows Firewall': f'Add-NetFirewallRule -DisplayName "Block {vendor} {category}" -Direction Outbound -Action Block -RemoteAddress {remote_ip} -RemotePort {remote_port} -Protocol TCP',
            'Linux iptables': f'iptables -A OUTPUT -d {remote_ip} -p tcp --dport {remote_port} -j DROP',
            'Router (iptables)': f'iptables -A FORWARD -d {remote_ip} -p tcp --dport {remote_port} -j REJECT',
            'PiHole DNS': f'{remote_ip} # {vendor} - {category}',
            'confidence': 'HIGH' if category in ['ADVERTISING', 'TELEMETRY'] else 'MEDIUM'
        }
        rules.append(rule)
    
    return rules


def suggest_domain_blocking(connection_analysis: Optional[Dict[str, Any]] = None) -> List[Dict[str, str]]:
    """Generate domain-based blocking recommendations (DNS-level).
    
    Args:
        connection_analysis: Connection analysis with domain information
    
    Returns:
        List of domain blocking rules
    """
    rules = []
    
    if not connection_analysis:
        return rules
    
    # Collect domains from analyzed connections
    analyzed_conns = connection_analysis.get('analyzed_connections', [])
    domains_by_category = {}
    
    for conn in analyzed_conns:
        domain = conn.get('domain')
        if not domain:
            continue
        
        category = conn.get('category', 'UNKNOWN')
        if category not in domains_by_category:
            domains_by_category[category] = []
        
        if domain not in domains_by_category[category]:
            domains_by_category[category].append(domain)
    
    # Generate rules for blockable categories
    blockable_categories = ['ADVERTISING', 'TELEMETRY']
    
    for category in blockable_categories:
        domains = domains_by_category.get(category, [])
        for domain in domains:
            rule = {
                'domain': domain,
                'category': category,
                'pihole_blocklist': f'regex:({domain})',
                'adblock_plus': f'||{domain}^',
                'hosts_file': f'0.0.0.0 {domain}',
                'dnsmasq': f'address=/{domain}/0.0.0.0',
                'unbound': f'local-data: "{domain} A 0.0.0.0"',
            }
            rules.append(rule)
    
    return rules


def suggest_mitigations(device: dict, analysis: dict = None, 
                       connection_analysis: Optional[Dict[str, Any]] = None) -> dict:
    """Suggest mitigations for a device, with optional connection-specific recommendations.
    
    Args:
        device: Device dict from network scan
        analysis: Risk analysis result
        connection_analysis: Connection analysis with specific blocked domains/IPs
    
    Returns:
        Dict with mitigation actions and blocking rules
    """
    ip = device.get("IP", "<unknown>")
    vendor = device.get("Vendor", "Unknown")
    device_type = device.get("Type", "Unknown")
    ports = device.get("Open Ports", []) or []
    confidence = device.get("Confidence", "Low")

    v = _safe_lower(vendor)
    t = _safe_lower(device_type)

    actions = []
    
    # Generate IP/domain-specific blocking rules if connection data available
    blocking_rules = suggest_blocking_rules(connection_analysis) if connection_analysis else []
    domain_rules = suggest_domain_blocking(connection_analysis) if connection_analysis else []

    # --- Always recommended (generic) ---
    actions.append({
        "id": "firmware-update",
        "title": "Update firmware / software",
        "description": "Check vendor firmware and OS updates and apply latest security patches.",
        "difficulty": "Easy",
        "impact": "High",
        "apply_on": "device",
        "commands": [
            "Check the device UI or vendor support site for firmware updates and follow vendor instructions."
        ]
    })

    actions.append({
        "id": "change-default-passwords",
        "title": "Change default/admin passwords",
        "description": "If the device uses default credentials, change them to a strong unique password.",
        "difficulty": "Easy",
        "impact": "High",
        "apply_on": "device",
        "commands": [
            "Login to the device web UI (http://{ip} or vendor app) and change the admin password.",
            "Use a password manager to store the new password."
        ]
    })

    actions.append({
        "id": "isolate-guest-network",
        "title": "Isolate device on a guest / IoT VLAN",
        "description": "Move the device to a separate network (guest SSID or VLAN) to limit lateral movement and access to local resources.",
        "difficulty": "Medium",
        "impact": "High",
        "apply_on": "router",
        "commands": [
            "On router: create Guest SSID or VLAN and move the device to it (see your router manual).",
            "Block inter-VLAN routing so IoT VLAN cannot access internal LAN."
        ]
    })

    # --- Device-type specific ---
    if "router" in t or "gateway" in t:
        actions.append({
            "id": "disable-remote-mgmt",
            "title": "Disable remote management / UPnP",
            "description": "Disable remote admin access and UPnP unless you explicitly need them. Remote management exposes your router to internet-facing attacks and data leakage.",
            "difficulty": "Easy",
            "impact": "High",
            "apply_on": "router",
            "commands": [
                "Router UI -> Administration / Remote Management -> Disable remote management",
                "Router UI -> Advanced -> UPnP -> Disable"
            ]
        })
        actions.append({
            "id": "change-router-default",
            "title": "Use strong Wi-Fi and router admin settings",
            "description": "Use WPA2/WPA3 with a strong passphrase, change SSID, disable WPS, and set admin UI to HTTPS.",
            "difficulty": "Easy",
            "impact": "High",
            "apply_on": "router",
            "commands": [
                "Router UI -> Wireless -> Security -> Set WPA2/WPA3 and strong passphrase",
                "Router UI -> Administration -> Enable HTTPS for admin UI and disable HTTP"
            ]
        })

    if "ip camera" in t or "camera" in t:
        actions.append({
            "id": "disable-cloud-sync",
            "title": "Disable cloud sync / remote upload (if available)",
            "description": "Turn off cloud upload or motion-clip upload to vendor servers, switch to local recording when possible.",
            "difficulty": "Easy",
            "impact": "High",
            "apply_on": "device",
            "commands": [
                "Camera app/UI -> Settings -> Cloud / Remote Upload -> Disable",
                "Enable local SD recording or local NVR (Network Video Recorder) instead"
            ]
        })
        actions.append({
            "id": "restrict-camera-outbound",
            "title": "Block camera outbound network access (router-level)",
            "description": "Block traffic from the camera to internet origins except allowed services (or block outbound entirely). This forces local-only operation.",
            "difficulty": "Medium",
            "impact": "High",
            "apply_on": "router",
            "commands": [
                "# Example iptables rule (on router/gateway):",
                "iptables -A FORWARD -s {ip} -p tcp --dport 443 -j REJECT",
                "# Or create a firewall rule on your router UI to block outbound traffic from {ip}"
            ]
        })

    if "phone" in t or "tablet" in t:
        actions.append({
            "id": "review-app-permissions",
            "title": "Review app permissions & disable unnecessary sync",
            "description": "On mobile, check app permissions (camera, microphone, location) and disable unused cloud backups/sync for apps you don't trust.",
            "difficulty": "Easy",
            "impact": "Medium",
            "apply_on": "user",
            "commands": [
                "Android: Settings -> Apps -> Permissions; disable location / camera for non-essential apps",
                "iOS: Settings -> Privacy -> Review permissions; disable background app refresh for apps you don't trust"
            ]
        })

    if "laptop" in t or "pc" in t:
        actions.append({
            "id": "limit-telemetry",
            "title": "Limit OS & app telemetry",
            "description": "Turn off optional telemetry, browser sync, and cloud services not needed for work.",
            "difficulty": "Easy",
            "impact": "Medium",
            "apply_on": "device",
            "commands": [
                "Windows: Settings -> Privacy -> Diagnostics & feedback -> Set diagnostic data to Basic or Off where allowed",
                "Sign out of cloud accounts (OneDrive, iCloud, Google Drive) if not required; pause sync"
            ]
        })
        actions.append({
            "id": "enable-host-firewall",
            "title": "Enable host firewall & close risky ports",
            "description": "Ensure the system firewall is enabled and restrict inbound remote-access services.",
            "difficulty": "Easy",
            "impact": "High",
            "apply_on": "device",
            "commands": [
                "# Windows PowerShell (run as admin):",
                'netsh advfirewall set allprofiles state on',
                "# Linux UFW example (run as root):",
                "ufw enable",
                "ufw deny from any to {ip} port 22 comment 'Block SSH to device'"
            ]
        })

    if "iot" in t:
        actions.append({
            "id": "change-default-creds-iot",
            "title": "Change default credentials and reduce privileges",
            "description": "IoT devices often ship with default credentials—change them and remove unnecessary services.",
            "difficulty": "Easy",
            "impact": "High",
            "apply_on": "device",
            "commands": [
                "Device admin UI -> Change default user/password",
                "Disable services you don't need (telnet, ftp, remote shell)"
            ]
        })
        # If MQTT port
        if 8883 in ports:
            actions.append({
                "id": "mqtt-check",
                "title": "Audit MQTT usage",
                "description": "If device uses MQTT (8883), confirm broker is private or requires auth. Consider blocking if unknown.",
                "difficulty": "Medium",
                "impact": "Medium",
                "apply_on": "device/router",
                "commands": [
                    "# Router-level: block outbound mqtt (port 1883/8883) from {ip}",
                    "iptables -A FORWARD -s {ip} -p tcp --dport 8883 -j REJECT"
                ]
            })

    # --- Port-based suggestions (specific) ---
    if 22 in ports or 3389 in ports or 5900 in ports:
        actions.append({
            "id": "restrict-remote-access",
            "title": "Restrict or disable remote access (SSH/RDP/VNC)",
            "description": "If remote access is not required, disable it. If required, restrict to specific source IPs and use keys/passwords properly.",
            "difficulty": "Medium",
            "impact": "High",
            "apply_on": "device/router",
            "commands": [
                "# Example: close SSH on device (device UI) or block on router:",
                "iptables -A FORWARD -s {ip} -p tcp --dport 22 -j REJECT",
                "# For Windows RDP: disable or restrict to specific IPs in firewall rules"
            ]
        })

    if 443 in ports:
        actions.append({
            "id": "inspect-https",
            "title": "Inspect HTTPS destinations & vendor docs",
            "description": "Presence of HTTPS likely means cloud communication. Inspect vendor privacy docs and domain list; consider blocking vendor endpoints if you want local-only operation.",
            "difficulty": "Medium",
            "impact": "Medium",
            "apply_on": "user/router",
            "commands": [
                "Check network logs for outbound destinations (on router) and search vendor documentation for 'cloud' endpoints.",
                "If comfortable, block vendor domains on router level (e.g., cloud.example.com)"
            ]
        })

    # --- Prioritization using analysis if provided ---
    if analysis:
        rl = analysis.get("risk_level", "").upper()
        # Add a small hint action to act now for high risk
        if rl == "HIGH":
            actions.insert(0, {
                "id": "urgent-isolate",
                "title": "URGENT: Isolate device from network",
                "description": "Temporarily disconnect or move the device to a guest network until you apply mitigations.",
                "difficulty": "Easy",
                "impact": "High",
                "apply_on": "user/router",
                "commands": [
                    "Disconnect the device from Wi-Fi or unplug its network cable",
                    "Or move it to a Guest SSID / IoT VLAN immediately"
                ]
            })

    # Always include checklist summarizing top actions
    checklist = []
    top_actions = []
    # pick highest-impact easy/medium actions
    for a in actions:
        if a["impact"] in ("High",) and a["difficulty"] in ("Easy", "Medium"):
            top_actions.append(a)
        if len(top_actions) >= 5:
            break

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "device_ip": ip,
        "device_vendor": vendor,
        "device_type": device_type,
        "confidence": confidence,
        "open_ports": ports,
        "actions": actions,
        "top_actions": top_actions,
        "blocking_rules": blocking_rules,
        "domain_rules": domain_rules,
        "rule_count": len(blocking_rules) + len(domain_rules)
    }

def print_mitigation_report(device, analysis=None, actions_obj=None, save_path=None):
    """
    Pretty-print mitigation suggestions and optionally save to file.
    actions_obj: result of suggest_mitigations(...)
    """
    if actions_obj is None:
        actions_obj = suggest_mitigations(device, analysis)

    ip = actions_obj["device_ip"]
    vendor = actions_obj["device_vendor"]
    dev_type = actions_obj["device_type"]
    conf = actions_obj["confidence"]
    ports = actions_obj["open_ports"]

    print("\n" + "="*60)
    print(f"Mitigation Report for {ip} ({vendor})")
    print("="*60)
    print(f"Device Type: {dev_type}    Confidence: {conf}")
    print(f"Open Ports: {ports}\n")

    print("Top Recommended Actions:")
    for i, a in enumerate(actions_obj["top_actions"], start=1):
        print(f"\n{i}. {a['title']} ({a['difficulty']} / impact: {a['impact']})")
        print(f"   - {a['description']}")
        if a.get("commands"):
            print("   - Example commands / steps:")
            for cmd in a["commands"]:
                print(f"       {cmd}".replace("{ip}", ip))

    print("\nFull Action List:")
    for i, a in enumerate(actions_obj["actions"], start=1):
        print(f"\n[{i}] {a['title']} ({a['difficulty']} / impact: {a['impact']})")
        print(f"    {a['description']}")
        if a.get("commands"):
            for cmd in a["commands"]:
                print("      -> " + cmd.replace("{ip}", ip))

    if save_path:
        try:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(actions_obj, f, indent=2)
            print(f"\nSaved mitigation report to {save_path}")
        except Exception as e:
            print(f"\nFailed to save report: {e}")

# Simple CLI test
if __name__ == "__main__":
    # demo device
    sample = {
        "IP": "192.168.1.33",
        "MAC": "98:22:6E:44:3A:3F",
        "Vendor": "Amazon Technologies Inc.",
        "Type": "Unknown",
        "Open Ports": [443, 8883],
        "Confidence": "High"
    }
    a = suggest_mitigations(sample, {"risk_level": "MEDIUM"})
    print_mitigation_report(sample, {"risk_level": "MEDIUM"}, a)
