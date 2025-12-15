"""Connection analyzer module.

Correlates active connections with DNS queries and vendor information.
Generates human-readable insights about what the machine is connecting to.
Supports merging router data for network-wide analysis.

Functions:
    - analyze_connections: Full analysis of active connections (local machine)
    - analyze_router_device: Analyze connections for specific device on network
    - merge_router_data: Merge router data with local connection analysis
    - get_connection_insights: Detailed insights per connection
    - generate_connection_report: Summary report
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict

# Handle imports for both direct execution and module import
try:
    from monitoring.connection_monitor import (
        get_active_connections, get_connection_summary
    )
    from monitoring.dns_monitor import get_dns_queries, get_unique_domains
    from monitoring.vendor_database import (
        find_vendor_by_ip, find_vendor_by_domain, 
        classify_connection, can_safely_block, get_category_explanation
    )
    from monitoring.process_mapper import (
        get_process_name, get_all_process_connections,
        get_categorized_process_summary
    )
except ModuleNotFoundError:
    from connection_monitor import (
        get_active_connections, get_connection_summary
    )
    from dns_monitor import get_dns_queries, get_unique_domains
    from vendor_database import (
        find_vendor_by_ip, find_vendor_by_domain, 
        classify_connection, can_safely_block, get_category_explanation
    )
    from process_mapper import (
        get_process_name, get_all_process_connections,
        get_categorized_process_summary
    )


def analyze_single_connection(conn: Dict[str, Any], 
                             domain: Optional[str] = None) -> Dict[str, Any]:
    """Analyze a single connection.
    
    Args:
        conn: Connection dict from netstat
        domain: Domain if known
    
    Returns:
        Dict with full analysis
    """
    remote_ip = conn['remote_ip']
    remote_port = conn['remote_port']
    
    # Try to find domain if not provided
    if not domain:
        # Check against known domains (future: could do reverse DNS)
        domains = get_unique_domains()
        matching = [d for d in domains if f"{remote_ip}" in d or remote_ip in d]
        domain = matching[0] if matching else None
    
    # Classify connection
    classification = classify_connection(remote_ip, domain)
    
    # Get process info
    process_name = get_process_name(conn.get('pid', ''))
    
    analysis = {
        'connection': conn,
        'domain': domain,
        'vendor': classification['vendor'],
        'service': classification['service'],
        'category': classification['category'],
        'process': process_name,
        'safe_to_block': can_safely_block(classification['category']),
        'explanation': get_category_explanation(classification['category']),
        'endpoint': f"{remote_ip}:{remote_port}"
    }
    
    return analysis


def analyze_connections(include_process_info: bool = True) -> Dict[str, Any]:
    """Analyze all active connections.
    
    Args:
        include_process_info: If True, map connections to processes
    
    Returns:
        Dict with complete analysis
    """
    connections = get_active_connections()
    domains = get_unique_domains()
    
    analyzed = []
    by_vendor = defaultdict(list)
    by_category = defaultdict(list)
    
    for conn in connections:
        analysis = analyze_single_connection(conn)
        analyzed.append(analysis)
        
        by_vendor[analysis['vendor']].append(analysis)
        by_category[analysis['category']].append(analysis)
    
    # Get process info if requested
    process_summary = None
    if include_process_info:
        process_summary = get_categorized_process_summary(connections)
    
    return {
        'total_connections': len(connections),
        'analyzed_connections': analyzed,
        'by_vendor': dict(by_vendor),
        'by_category': dict(by_category),
        'known_domains': domains,
        'summary': get_connection_summary(),
        'process_summary': process_summary
    }


def get_vendor_summary(analysis: Dict[str, Any]) -> Dict[str, int]:
    """Get count of connections per vendor.
    
    Args:
        analysis: Result from analyze_connections()
    
    Returns:
        Dict mapping vendor to connection count
    """
    vendor_counts = defaultdict(int)
    
    for conn_analysis in analysis['analyzed_connections']:
        vendor = conn_analysis['vendor']
        vendor_counts[vendor] += 1
    
    return dict(sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True))


def get_category_breakdown(analysis: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Get breakdown by category with statistics.
    
    Args:
        analysis: Result from analyze_connections()
    
    Returns:
        Dict mapping category to stats
    """
    breakdown = {}
    
    for category, connections in analysis['by_category'].items():
        breakdown[category] = {
            'count': len(connections),
            'vendors': list(set(c['vendor'] for c in connections)),
            'processes': list(set(c['process'] for c in connections if c['process'])),
            'safe_to_block': can_safely_block(category)
        }
    
    return breakdown


def get_suspicious_connections(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get potentially suspicious connections.
    
    Criteria:
    - Unknown vendor
    - Unknown category
    - Non-standard ports
    - Encrypted (port 443) but unknown vendor
    
    Args:
        analysis: Result from analyze_connections()
    
    Returns:
        List of suspicious connections
    """
    suspicious = []
    
    for conn_analysis in analysis['analyzed_connections']:
        flags = []
        
        # Unknown vendor
        if conn_analysis['vendor'] == 'Unknown':
            flags.append('Unknown vendor')
        
        # Unknown category
        if conn_analysis['category'] == 'UNKNOWN':
            flags.append('Unknown category')
        
        # Suspicious port
        remote_port = conn_analysis['connection']['remote_port']
        if remote_port not in [80, 443, 22, 3306, 5432, 25, 110, 143, 587, 993]:
            # Non-standard port (rough check)
            if remote_port > 1024:  # Not a well-known port
                flags.append(f'Non-standard port {remote_port}')
        
        if flags:
            conn_analysis['suspicious_flags'] = flags
            suspicious.append(conn_analysis)
    
    return suspicious


def get_privacy_risks(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Assess privacy risks from connections.
    
    Returns assessment of:
    - Data collection
    - Tracking
    - Third-party analytics
    
    Args:
        analysis: Result from analyze_connections()
    
    Returns:
        Privacy risk assessment
    """
    telemetry_conns = analysis['by_category'].get('TELEMETRY', [])
    advertising_conns = analysis['by_category'].get('ADVERTISING', [])
    cloud_conns = analysis['by_category'].get('CLOUD', [])
    
    risks = {
        'telemetry_connections': len(telemetry_conns),
        'advertising_connections': len(advertising_conns),
        'cloud_connections': len(cloud_conns),
        'total_tracking': len(telemetry_conns) + len(advertising_conns),
        'telemetry_vendors': list(set(c['vendor'] for c in telemetry_conns)),
        'advertising_vendors': list(set(c['vendor'] for c in advertising_conns)),
        'cloud_vendors': list(set(c['vendor'] for c in cloud_conns)),
    }
    
    return risks


def get_blocking_recommendations(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get recommendations for blocking unsafe connections.
    
    Returns connections that:
    - Can be safely blocked (ADVERTISING, TELEMETRY)
    - Won't break functionality
    - Have privacy benefits
    
    Args:
        analysis: Result from analyze_connections()
    
    Returns:
        List of blocking recommendations
    """
    recommendations = []
    
    for conn_analysis in analysis['analyzed_connections']:
        if conn_analysis['safe_to_block']:
            recommendations.append({
                'endpoint': conn_analysis['endpoint'],
                'vendor': conn_analysis['vendor'],
                'service': conn_analysis['service'],
                'category': conn_analysis['category'],
                'process': conn_analysis['process'],
                'reason': f"Block {conn_analysis['category'].lower()} - no functional impact",
                'action': f"iptables -A OUTPUT -d {conn_analysis['connection']['remote_ip']} -j DROP"
            })
    
    # Sort by vendor (group same vendors together)
    recommendations.sort(key=lambda x: x['vendor'])
    
    return recommendations


def analyze_router_device(device_ip: str, device_connections: List[Any], 
                         dns_queries: Optional[List[str]] = None,
                         device_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Analyze connections for a specific device discovered via router.
    
    Args:
        device_ip: IP address of the device
        device_connections: List of RouterConnection objects or dicts from conntrack
        dns_queries: List of domains queried by this device
        device_info: Additional device info (MAC, hostname, type)
    
    Returns:
        Analysis dict for this device
    """
    analyzed = []
    by_vendor = defaultdict(list)
    by_category = defaultdict(list)
    
    if dns_queries is None:
        dns_queries = []
    
    # Convert router connections to standard format and analyze
    for conn in device_connections:
        # Handle both RouterConnection dataclass and dict format
        if hasattr(conn, '__dict__'):
            conn_dict = vars(conn)
        else:
            conn_dict = conn
        
        # Analyze this connection
        conn_analysis = {
            'connection': conn_dict,
            'device_ip': device_ip,
            'domain': None,
            'vendor': 'Unknown',
            'service': 'Unknown',
            'category': 'UNKNOWN',
            'endpoint': f"{conn_dict.get('dest_ip', '?')}:{conn_dict.get('dest_port', '?')}",
            'bytes_sent': conn_dict.get('bytes_sent', 0),
            'bytes_received': conn_dict.get('bytes_received', 0),
        }
        
        # Try to classify by IP
        remote_ip = conn_dict.get('dest_ip', '')
        classification = classify_connection(remote_ip, None)
        conn_analysis.update({
            'vendor': classification['vendor'],
            'service': classification['service'],
            'category': classification['category'],
            'safe_to_block': can_safely_block(classification['category']),
        })
        
        analyzed.append(conn_analysis)
        by_vendor[conn_analysis['vendor']].append(conn_analysis)
        by_category[conn_analysis['category']].append(conn_analysis)
    
    return {
        'device_ip': device_ip,
        'device_info': device_info,
        'total_connections': len(device_connections),
        'analyzed_connections': analyzed,
        'by_vendor': dict(by_vendor),
        'by_category': dict(by_category),
        'dns_queries': dns_queries,
        'unique_domains': list(set(dns_queries)) if dns_queries else [],
        'bytes_sent': sum(c.get('bytes_sent', 0) for c in analyzed),
        'bytes_received': sum(c.get('bytes_received', 0) for c in analyzed),
    }


def merge_router_data(local_analysis: Dict[str, Any], 
                     router_data: Dict[str, Any]) -> Dict[str, Any]:
    """Merge router data with local machine analysis.
    
    Creates per-device analyses for all network devices discovered via router,
    while skipping the local machine to avoid duplication.
    
    Args:
        local_analysis: Result from analyze_connections() for local machine
        router_data: Result from RouterMonitor.merge_with_local_connections()
    
    Returns:
        Combined analysis with:
            - local_analysis: unchanged local machine analysis
            - network_devices: Dict[ip] -> device analysis
            - summary: Network-wide summary
    """
    merged = {
        'local_analysis': local_analysis,
        'network_devices': {},
        'summary': {
            'total_devices': 0,
            'devices_with_tracking': 0,
            'devices_with_ads': 0,
            'total_network_connections': 0,
            'network_telemetry': 0,
            'network_advertising': 0,
        },
        'router_connected': router_data.get('connected', False),
        'router_os': router_data.get('router_os'),
        'local_ip': router_data.get('local_ip'),
    }
    
    local_ip = router_data.get('local_ip')
    devices = router_data.get('devices', {})
    
    # Analyze each device (skip local machine)
    for ip, device_info in devices.items():
        # Skip local machine
        if ip == local_ip:
            continue
        
        # Analyze this device
        device_analysis = analyze_router_device(
            device_ip=ip,
            device_connections=device_info.connections if hasattr(device_info, 'connections') else [],
            dns_queries=device_info.dns_queries if hasattr(device_info, 'dns_queries') else [],
            device_info={
                'mac': device_info.mac_address if hasattr(device_info, 'mac_address') else None,
                'hostname': device_info.hostname if hasattr(device_info, 'hostname') else None,
                'device_type': device_info.device_type if hasattr(device_info, 'device_type') else 'Unknown',
            }
        )
        
        merged['network_devices'][ip] = device_analysis
        
        # Update summary
        merged['summary']['total_devices'] += 1
        merged['summary']['total_network_connections'] += device_analysis['total_connections']
        
        # Count tracking
        if device_analysis['by_category'].get('TELEMETRY'):
            merged['summary']['devices_with_tracking'] += 1
            merged['summary']['network_telemetry'] += len(device_analysis['by_category']['TELEMETRY'])
        
        if device_analysis['by_category'].get('ADVERTISING'):
            merged['summary']['devices_with_ads'] += 1
            merged['summary']['network_advertising'] += len(device_analysis['by_category']['ADVERTISING'])
    
    return merged


def generate_text_report(analysis: Dict[str, Any]) -> str:
    """Generate human-readable text report.
    
    Args:
        analysis: Result from analyze_connections()
    
    Returns:
        Formatted text report
    """
    lines = []
    
    lines.append("=" * 80)
    lines.append("LOCAL MACHINE CONNECTION ANALYSIS")
    lines.append("=" * 80)
    lines.append("")
    
    # Summary
    summary = analysis['summary']
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Total Connections: {summary['total_connections']}")
    lines.append(f"Established Connections: {summary['established']}")
    lines.append(f"TCP: {summary['tcp']}, UDP: {summary['udp']}")
    lines.append(f"Unique Remote IPs: {summary['unique_remote_ips']}")
    lines.append("")
    
    # By Vendor
    vendor_summary = get_vendor_summary(analysis)
    lines.append("TOP VENDORS")
    lines.append("-" * 40)
    for vendor, count in list(vendor_summary.items())[:10]:
        lines.append(f"  {vendor:.<30} {count:>3} connections")
    lines.append("")
    
    # By Category
    category_breakdown = get_category_breakdown(analysis)
    lines.append("BY CATEGORY")
    lines.append("-" * 40)
    for category in ['FUNCTIONAL', 'CLOUD', 'TELEMETRY', 'ADVERTISING', 'INFRASTRUCTURE', 'UNKNOWN']:
        if category in category_breakdown:
            info = category_breakdown[category]
            blockable = "✓ Can block" if info['safe_to_block'] else "✗ Essential"
            lines.append(
                f"  {category:.<20} {info['count']:>3} connections [{blockable}]"
            )
    lines.append("")
    
    # Privacy Risks
    privacy = get_privacy_risks(analysis)
    lines.append("PRIVACY ASSESSMENT")
    lines.append("-" * 40)
    lines.append(f"Telemetry Connections: {privacy['telemetry_connections']}")
    lines.append(f"Advertising Connections: {privacy['advertising_connections']}")
    lines.append(f"Cloud Connections: {privacy['cloud_connections']}")
    lines.append(f"Total Tracking: {privacy['total_tracking']} connections")
    lines.append("")
    
    # Blocking Recommendations
    recommendations = get_blocking_recommendations(analysis)
    if recommendations:
        lines.append("SAFE TO BLOCK (No Functional Impact)")
        lines.append("-" * 40)
        for rec in recommendations[:10]:
            lines.append(
                f"  {rec['vendor']:.<20} {rec['endpoint']:>20} [{rec['category']}]"
            )
        if len(recommendations) > 10:
            lines.append(f"  ... and {len(recommendations) - 10} more")
        lines.append("")
    
    # Suspicious
    suspicious = get_suspicious_connections(analysis)
    if suspicious:
        lines.append("POTENTIALLY SUSPICIOUS")
        lines.append("-" * 40)
        for conn in suspicious[:5]:
            lines.append(f"  {conn['endpoint']}")
            for flag in conn.get('suspicious_flags', []):
                lines.append(f"    - {flag}")
        lines.append("")
    
    lines.append("=" * 80)
    
    return "\n".join(lines)


def generate_device_report(device_analysis: Dict[str, Any]) -> str:
    """Generate report for a specific network device.
    
    Args:
        device_analysis: Result from analyze_router_device()
    
    Returns:
        Formatted text report
    """
    lines = []
    
    device_ip = device_analysis['device_ip']
    device_info = device_analysis.get('device_info', {})
    hostname = device_info.get('hostname', 'Unknown')
    mac = device_info.get('mac', 'Unknown')
    
    lines.append("=" * 80)
    lines.append(f"DEVICE: {hostname} ({device_ip})")
    lines.append(f"MAC: {mac}")
    lines.append("=" * 80)
    lines.append("")
    
    lines.append("NETWORK ACTIVITY")
    lines.append("-" * 40)
    lines.append(f"Active Connections: {device_analysis['total_connections']}")
    lines.append(f"Bytes Sent: {device_analysis['bytes_sent']:,}")
    lines.append(f"Bytes Received: {device_analysis['bytes_received']:,}")
    lines.append("")
    
    # DNS Queries
    if device_analysis['dns_queries']:
        lines.append("DNS QUERIES")
        lines.append("-" * 40)
        for domain in sorted(set(device_analysis['dns_queries']))[:10]:
            lines.append(f"  • {domain}")
        if len(set(device_analysis['dns_queries'])) > 10:
            lines.append(f"  ... and {len(set(device_analysis['dns_queries'])) - 10} more")
        lines.append("")
    
    # By Category
    category_breakdown = {}
    for category, conns in device_analysis['by_category'].items():
        category_breakdown[category] = {
            'count': len(conns),
            'vendors': list(set(c['vendor'] for c in conns)),
            'safe_to_block': can_safely_block(category)
        }
    
    lines.append("CONNECTION CATEGORIES")
    lines.append("-" * 40)
    for category in ['FUNCTIONAL', 'CLOUD', 'TELEMETRY', 'ADVERTISING', 'INFRASTRUCTURE', 'UNKNOWN']:
        if category in category_breakdown:
            info = category_breakdown[category]
            lines.append(f"  {category:.<20} {info['count']:>3} connections")
    lines.append("")
    
    # Top vendors
    vendor_counts = defaultdict(int)
    for conn in device_analysis['analyzed_connections']:
        vendor_counts[conn['vendor']] += 1
    
    if vendor_counts:
        lines.append("TOP VENDORS")
        lines.append("-" * 40)
        for vendor, count in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            lines.append(f"  {vendor:.<30} {count:>3} connections")
        lines.append("")
    
    lines.append("=" * 80)
    
    return "\n".join(lines)


# ============================================================================
# Simple CLI test
# ============================================================================

if __name__ == "__main__":
    print("SafeNet - Connection Analyzer")
    print("=" * 60)
    print()
    
    print("Analyzing active connections...")
    analysis = analyze_connections()
    
    # Print report
    report = generate_text_report(analysis)
    print(report)
