"""Process-to-connection mapper for Windows.

Maps PIDs (Process IDs) to application names and correlates with network connections.
Shows which applications are making which network connections.

No admin required for basic functionality.

Functions:
    - get_process_name: Get app name for a given PID
    - get_process_connections: Get all connections for a process
    - get_process_network_summary: Detailed breakdown per process
"""

import subprocess
import platform
from typing import Dict, List, Any, Optional
from collections import defaultdict


def get_process_name(pid: str) -> Optional[str]:
    """Get process name for a given PID.
    
    Args:
        pid: Process ID (string or int)
    
    Returns:
        Process name or executable name, or None if not found
    """
    system = platform.system()
    
    try:
        if system == 'Windows':
            # Try using tasklist command
            result = subprocess.run(
                ['tasklist', '/FI', f'PID eq {pid}', '/FO', 'CSV'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                # CSV format: "name","pid"
                parts = lines[1].split(',')
                if len(parts) >= 1:
                    return parts[0].strip().strip('"')
            
            # Fallback: try WMI if tasklist fails
            try:
                import wmi
                c = wmi.WMI()
                processes = c.Win32_Process(ProcessId=int(pid))
                if processes:
                    return processes[0].Name
            except:
                pass
        
        else:
            # Linux/macOS: ps command
            result = subprocess.run(
                ['ps', '-o', 'comm=', '-p', pid],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.stdout:
                return result.stdout.strip()
    
    except Exception:
        pass
    
    return None


def get_process_connections(connections: List[Dict[str, Any]], 
                           process_name: str) -> List[Dict[str, Any]]:
    """Get all connections for a specific process.
    
    Args:
        connections: List of connection dicts (from connection_monitor)
        process_name: Name of process to filter for
    
    Returns:
        Connections matching this process
    """
    matching = []
    process_pids = set()
    
    # First, get all PIDs for this process
    result = subprocess.run(
        ['tasklist', '/FI', f'IMAGENAME eq {process_name}', '/FO', 'CSV'],
        capture_output=True,
        text=True,
        timeout=5
    )
    
    lines = result.stdout.strip().split('\n')
    for line in lines[1:]:  # Skip header
        if line.strip():
            parts = line.split(',')
            if len(parts) >= 2:
                try:
                    pid = parts[1].strip().strip('"')
                    process_pids.add(pid)
                except:
                    pass
    
    # Find connections with these PIDs
    for conn in connections:
        if conn.get('pid') in process_pids:
            matching.append(conn)
    
    return matching


def get_all_process_connections(connections: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Map all connections by process name.
    
    Args:
        connections: List of connection dicts
    
    Returns:
        Dict mapping process names to their connections
    """
    by_process = defaultdict(list)
    
    for conn in connections:
        pid = conn.get('pid')
        if pid:
            process_name = get_process_name(pid)
            if process_name:
                by_process[process_name].append(conn)
            else:
                by_process[f'Unknown (PID {pid})'].append(conn)
    
    return dict(by_process)


def get_process_network_summary(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate network activity summary per process.
    
    Args:
        connections: List of active connections
    
    Returns:
        List of process summaries with connection details
    """
    by_process = get_all_process_connections(connections)
    
    summaries = []
    
    for process_name, conns in by_process.items():
        # Get unique remote servers
        remote_servers = set()
        for conn in conns:
            remote_servers.add(f"{conn['remote_ip']}:{conn['remote_port']}")
        
        summary = {
            'process': process_name,
            'connection_count': len(conns),
            'protocols': set(c.get('protocol', 'Unknown').upper() for c in conns),
            'remote_servers': list(remote_servers),
            'connections': conns
        }
        
        summaries.append(summary)
    
    # Sort by connection count (most active first)
    summaries.sort(key=lambda x: x['connection_count'], reverse=True)
    
    return summaries


def get_top_processes_by_connections(connections: List[Dict[str, Any]], 
                                     top_n: int = 10) -> List[Dict[str, Any]]:
    """Get top N processes by number of connections.
    
    Args:
        connections: List of active connections
        top_n: How many to return
    
    Returns:
        Top processes sorted by connection count
    """
    summaries = get_process_network_summary(connections)
    return summaries[:top_n]


def categorize_application(process_name: str) -> str:
    """Categorize application type based on name.
    
    Args:
        process_name: Name of process/executable
    
    Returns:
        Category: 'Browser', 'Cloud', 'OS', 'Messaging', 'Media', 'Development', 'Other'
    """
    name_lower = process_name.lower()
    
    # Browsers
    if any(x in name_lower for x in ['chrome', 'firefox', 'edge', 'safari', 'iexplore', 'opera']):
        return 'Browser'
    
    # Cloud/Storage
    if any(x in name_lower for x in ['dropbox', 'onedrive', 'icloud', 'gdrive', 'nextcloud', 'sync']):
        return 'Cloud Storage'
    
    # Messaging
    if any(x in name_lower for x in ['telegram', 'discord', 'slack', 'whatsapp', 'outlook', 'mail']):
        return 'Messaging'
    
    # Media/Streaming
    if any(x in name_lower for x in ['spotify', 'netflix', 'youtube', 'vlc', 'mpv', 'media']):
        return 'Media'
    
    # OS Services
    if any(x in name_lower for x in ['svchost', 'system', 'csrss', 'explorer', 'dwm', 'lsass', 'winsvc']):
        return 'OS Service'
    
    # Development
    if any(x in name_lower for x in ['python', 'node', 'java', 'vscode', 'git', 'docker']):
        return 'Development'
    
    return 'Other'


def get_categorized_process_summary(connections: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Get process summary grouped by category.
    
    Args:
        connections: List of active connections
    
    Returns:
        Dict mapping categories to process lists
    """
    by_process = get_all_process_connections(connections)
    by_category = defaultdict(list)
    
    for process_name, conns in by_process.items():
        category = categorize_application(process_name)
        
        summary = {
            'process': process_name,
            'category': category,
            'connection_count': len(conns),
            'protocols': list(set(c.get('protocol', 'Unknown').upper() for c in conns))
        }
        
        by_category[category].append(summary)
    
    return dict(by_category)


# ============================================================================
# Simple CLI test
# ============================================================================

if __name__ == "__main__":
    from monitoring.connection_monitor import get_active_connections
    
    print("SafeNet - Process-to-Connection Mapper")
    print("=" * 60)
    print()
    
    print("Getting active connections...")
    connections = get_active_connections()
    
    print(f"\nFound {len(connections)} established connections\n")
    
    # Get summary by process
    print("Top Processes by Connection Count:")
    print("-" * 60)
    
    summaries = get_process_network_summary(connections)
    
    for i, proc_summary in enumerate(summaries[:10], 1):
        print(f"\n{i}. {proc_summary['process']}")
        print(f"   Connections: {proc_summary['connection_count']}")
        print(f"   Protocols: {', '.join(proc_summary['protocols'])}")
        print(f"   Remote Servers: {len(proc_summary['remote_servers'])} unique")
    
    print("\n" + "=" * 60)
    print("\nCategorized Summary:")
    categorized = get_categorized_process_summary(connections)
    for category, processes in sorted(categorized.items()):
        total_conns = sum(p['connection_count'] for p in processes)
        print(f"  {category:.<20} {len(processes):>3} processes, {total_conns:>3} connections")
