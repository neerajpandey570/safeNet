"""Local connection monitoring module.

Captures active network connections from this machine's netstat output.
No admin privileges required for basic functionality.
Works on Windows, Linux, and macOS.

Functions:
    - get_active_connections: Get list of current TCP/UDP connections
    - get_connection_stats: Calculate data flow and statistics
    - filter_connections_by_ip: Get connections to/from specific IP
"""

import subprocess
import re
import platform
from typing import List, Dict, Any, Optional
from collections import defaultdict
import time


def parse_netstat_windows() -> List[Dict[str, Any]]:
    """Parse Windows netstat -ano output.
    
    Returns:
        List of connection dicts with keys: local_ip, local_port, remote_ip, 
        remote_port, protocol, state, pid
    """
    try:
        result = subprocess.run(
            ['netstat', '-ano'],
            capture_output=True,
            text=True,
            timeout=10
        )
    except Exception as e:
        print(f"Error running netstat: {e}")
        return []
    
    connections = []
    lines = result.stdout.split('\n')
    
    # Skip header lines
    for line in lines:
        line = line.strip()
        if not line or 'Proto' in line or '----' in line:
            continue
        
        parts = line.split()
        if len(parts) < 5:
            continue
        
        try:
            protocol = parts[0]  # TCP or UDP
            local_addr = parts[1]  # 192.168.1.43:54321
            remote_addr = parts[2]  # 142.251.32.5:443
            state = parts[3]  # ESTABLISHED, LISTENING, etc
            pid = parts[4]  # Process ID
            
            # Parse local address
            if ':' not in local_addr:
                continue
            local_ip, local_port_str = local_addr.rsplit(':', 1)
            
            # Parse remote address
            if ':' not in remote_addr:
                continue
            remote_ip, remote_port_str = remote_addr.rsplit(':', 1)
            
            try:
                local_port = int(local_port_str)
                remote_port = int(remote_port_str)
            except ValueError:
                continue
            
            connections.append({
                'protocol': protocol,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'state': state,
                'pid': pid
            })
        except Exception:
            continue
    
    return connections


def parse_netstat_unix() -> List[Dict[str, Any]]:
    """Parse Linux/macOS netstat -an output.
    
    Returns:
        List of connection dicts
    """
    try:
        result = subprocess.run(
            ['netstat', '-an'],
            capture_output=True,
            text=True,
            timeout=10
        )
    except Exception as e:
        print(f"Error running netstat: {e}")
        return []
    
    connections = []
    lines = result.stdout.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or 'Proto' in line or '----' in line:
            continue
        
        parts = line.split()
        if len(parts) < 5:
            continue
        
        try:
            protocol = parts[0]  # tcp, udp
            # Skip proto if it's not tcp/udp
            if 'tcp' not in protocol and 'udp' not in protocol:
                continue
            
            local_addr = parts[3]  # Local address
            remote_addr = parts[4]  # Foreign address
            state = parts[5] if len(parts) > 5 else 'UNKNOWN'
            
            # Parse addresses
            if '.' not in local_addr or '.' not in remote_addr:
                continue
            
            local_ip, local_port_str = local_addr.rsplit('.', 1)
            remote_ip, remote_port_str = remote_addr.rsplit('.', 1)
            
            # Convert port notation from decimal
            try:
                local_port = int(local_port_str, 16) if '.' in local_port_str else int(local_port_str)
                remote_port = int(remote_port_str, 16) if '.' in remote_port_str else int(remote_port_str)
            except ValueError:
                continue
            
            connections.append({
                'protocol': protocol,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'state': state,
                'pid': 'N/A'
            })
        except Exception:
            continue
    
    return connections


def get_active_connections(established_only: bool = True) -> List[Dict[str, Any]]:
    """Get list of active network connections on this machine.
    
    Args:
        established_only: If True, only return ESTABLISHED connections
                         If False, return all states (LISTENING, TIME_WAIT, etc)
    
    Returns:
        List of connection dicts with local/remote IP:port, protocol, state, PID
    """
    system = platform.system()
    
    if system == 'Windows':
        connections = parse_netstat_windows()
    else:
        connections = parse_netstat_unix()
    
    # Filter for established connections only
    if established_only:
        connections = [
            c for c in connections 
            if c['state'] == 'ESTABLISHED' or c['state'] == 'ESTAB'
        ]
    
    return connections


def calculate_connection_duration(local_ip: str, local_port: int, 
                                 remote_ip: str, remote_port: int) -> Optional[float]:
    """Estimate connection duration (stub for future enhancement).
    
    Note: Requires OS-specific APIs to get accurate connection age.
    For now, returns None.
    """
    # TODO: Implement using Windows API or /proc/net/tcp on Linux
    return None


def get_connection_activity(sample_interval: int = 5) -> Dict[str, Dict[str, Any]]:
    """Measure connection activity over time interval.
    
    Captures connections at start and end of interval, identifies:
    - New connections (established during interval)
    - Closed connections (disappeared during interval)
    - Active connections (present at both times = sustained)
    
    Args:
        sample_interval: Seconds to wait between samples
    
    Returns:
        Dict with 'new', 'active', 'closed' connection lists
    """
    before = get_active_connections(established_only=True)
    before_set = {
        (c['local_ip'], c['local_port'], c['remote_ip'], c['remote_port'])
        for c in before
    }
    
    time.sleep(sample_interval)
    
    after = get_active_connections(established_only=True)
    after_set = {
        (c['local_ip'], c['local_port'], c['remote_ip'], c['remote_port'])
        for c in after
    }
    
    new_connections = [
        c for c in after 
        if (c['local_ip'], c['local_port'], c['remote_ip'], c['remote_port']) not in before_set
    ]
    
    active_connections = [
        c for c in after 
        if (c['local_ip'], c['local_port'], c['remote_ip'], c['remote_port']) in before_set
    ]
    
    closed_connections = [
        c for c in before 
        if (c['local_ip'], c['local_port'], c['remote_ip'], c['remote_port']) not in after_set
    ]
    
    return {
        'new': new_connections,
        'active': active_connections,
        'closed': closed_connections,
        'sample_interval': sample_interval
    }


def filter_connections_by_remote_ip(remote_ip: str) -> List[Dict[str, Any]]:
    """Get all connections to a specific remote IP.
    
    Args:
        remote_ip: IP address to filter for
    
    Returns:
        List of connections matching remote_ip
    """
    connections = get_active_connections()
    return [c for c in connections if c['remote_ip'] == remote_ip]


def filter_connections_by_local_port(port: int) -> List[Dict[str, Any]]:
    """Get all connections using a specific local port.
    
    Args:
        port: Port number
    
    Returns:
        List of connections using this port
    """
    connections = get_active_connections()
    return [c for c in connections if c['local_port'] == port]


def get_connection_summary() -> Dict[str, Any]:
    """Get summary statistics of active connections.
    
    Returns:
        Dict with counts: total, tcp, udp, established, listening
    """
    all_connections = get_active_connections(established_only=False)
    established = get_active_connections(established_only=True)
    
    tcp_conns = [c for c in all_connections if c['protocol'].upper() == 'TCP']
    udp_conns = [c for c in all_connections if c['protocol'].upper() == 'UDP']
    listening = [c for c in all_connections if 'LISTEN' in c['state'].upper()]
    
    # Get unique remote IPs
    remote_ips = set(c['remote_ip'] for c in established)
    
    return {
        'total_connections': len(all_connections),
        'established': len(established),
        'tcp': len(tcp_conns),
        'udp': len(udp_conns),
        'listening': len(listening),
        'unique_remote_ips': len(remote_ips)
    }


# ============================================================================
# Simple CLI test
# ============================================================================

if __name__ == "__main__":
    print("SafeNet - Local Connection Monitor")
    print("=" * 60)
    print()
    
    print("Getting active connections...")
    connections = get_active_connections()
    
    print(f"\nTotal ESTABLISHED connections: {len(connections)}\n")
    
    print("Sample connections:")
    for i, conn in enumerate(connections[:10], 1):
        print(
            f"{i}. {conn['protocol']:4} {conn['local_ip']:15}:{conn['local_port']:5} "
            f"→ {conn['remote_ip']:15}:{conn['remote_port']:5} [{conn['state']}]"
        )
    
    if len(connections) > 10:
        print(f"... and {len(connections) - 10} more")
    
    print("\n" + "=" * 60)
    print("\nConnection Summary:")
    summary = get_connection_summary()
    for key, value in summary.items():
        print(f"  {key:.<30} {value}")
