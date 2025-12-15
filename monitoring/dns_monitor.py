"""DNS monitoring module for Windows.

Reads Windows DNS Client Event Log to capture DNS queries made by this machine.
Shows what domains the machine is trying to reach.

Works on Windows only (uses Windows Event Log API).
No admin required for reading logs.

Functions:
    - get_dns_queries: Get recent DNS queries from Event Log
    - get_unique_domains: Get list of unique domains queried
    - filter_dns_by_domain: Search for specific domain
"""

import platform
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import re


def get_dns_queries_windows(last_n_minutes: int = 5) -> List[Dict[str, Any]]:
    """Get DNS queries from Windows Event Log (DNS Client).
    
    Requires: Windows only
    No admin needed to read logs.
    
    Args:
        last_n_minutes: Only return queries from last N minutes
    
    Returns:
        List of DNS query dicts with: timestamp, query_name, query_type, result
    """
    try:
        import win32evtlog
        import win32evtlogutil
        import win32api
    except ImportError:
        return []
    
    queries = []
    
    try:
        # Open the DNS Client event log
        # Event ID 3008 = DNS query (successful or failed)
        handle = win32evtlog.OpenEventLog(
            None,  # Local computer
            "Microsoft-Windows-DNS-Client/Operational"
        )
        
        # Get flags for reading events
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        # Calculate cutoff time
        cutoff = datetime.now() - timedelta(minutes=last_n_minutes)
        
        # Read events
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        
        while events:
            for event in events:
                # Only care about event ID 3008 (DNS query response)
                if event.EventID == 3008:
                    timestamp = event.TimeGenerated
                    
                    # Skip if too old
                    if timestamp < cutoff:
                        continue
                    
                    # Extract query name from event description
                    description = str(event.StringInserts) if event.StringInserts else ""
                    
                    # Event format varies, but typically contains domain name
                    # Try to extract it
                    query_name = None
                    if description:
                        # Try to find FQDN pattern
                        match = re.search(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', description)
                        if match:
                            query_name = match.group(0)
                    
                    if query_name:
                        queries.append({
                            'timestamp': timestamp,
                            'domain': query_name,
                            'type': 'A',  # Simplified, actual type would need parsing
                            'event_id': event.EventID
                        })
            
            # Get next batch
            events = win32evtlog.ReadEventLog(handle, flags, 0)
        
        win32evtlog.CloseEventLog(handle)
    
    except Exception as e:
        # If Event Log not available or not Windows, return empty
        pass
    
    return queries


def get_dns_queries_via_netsh() -> List[Dict[str, Any]]:
    """Alternative: Get DNS cache using netsh (all Windows versions).
    
    Shows cached DNS entries on this machine.
    Less real-time than Event Log but works on all Windows versions.
    No admin required.
    
    Returns:
        List of DNS cache entries
    """
    import subprocess
    
    queries = []
    
    try:
        result = subprocess.run(
            ['ipconfig', '/displaydns'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        lines = result.stdout.split('\n')
        current_record = {}
        
        for line in lines:
            line = line.strip()
            
            # Record name line
            if 'Record Name' in line and ':' in line:
                if current_record and 'name' in current_record:
                    queries.append(current_record)
                current_record = {'name': line.split(':', 1)[1].strip()}
            
            # Record type line
            elif 'Record Type' in line and ':' in line:
                current_record['type'] = line.split(':', 1)[1].strip()
            
            # Time to Live line
            elif 'Time To Live' in line and ':' in line:
                current_record['ttl'] = line.split(':', 1)[1].strip()
            
            # Data Length line
            elif 'Data Length' in line and ':' in line:
                current_record['data_len'] = line.split(':', 1)[1].strip()
        
        # Add last record
        if current_record and 'name' in current_record:
            queries.append(current_record)
    
    except Exception as e:
        pass
    
    return queries


def get_dns_queries(method: str = 'cache', last_n_minutes: int = 5) -> List[Dict[str, Any]]:
    """Get DNS queries made by this machine.
    
    Args:
        method: 'eventlog' (real-time, requires Windows) or 'cache' (DNS cache)
        last_n_minutes: For eventlog method, how far back to look
    
    Returns:
        List of DNS queries
    """
    system = platform.system()
    
    if system != 'Windows':
        return []
    
    if method == 'eventlog':
        return get_dns_queries_windows(last_n_minutes)
    else:
        return get_dns_queries_via_netsh()


def get_unique_domains(queries: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    """Get list of unique domains queried.
    
    Args:
        queries: List of DNS queries (gets fresh if None)
    
    Returns:
        Sorted list of unique domain names
    """
    if queries is None:
        queries = get_dns_queries()
    
    domains = set()
    
    for q in queries:
        if 'domain' in q:
            domains.add(q['domain'])
        elif 'name' in q:
            domains.add(q['name'])
    
    return sorted(list(domains))


def filter_dns_by_domain(domain_pattern: str) -> List[Dict[str, Any]]:
    """Find DNS queries matching a domain pattern.
    
    Args:
        domain_pattern: Domain or pattern (can use * for wildcard)
    
    Returns:
        Matching queries
    """
    queries = get_dns_queries()
    
    # Convert wildcard pattern to regex
    pattern = domain_pattern.replace('.', r'\.').replace('*', '.*')
    pattern = f"^{pattern}$"
    
    matches = []
    for q in queries:
        domain = q.get('domain') or q.get('name', '')
        if re.match(pattern, domain, re.IGNORECASE):
            matches.append(q)
    
    return matches


def get_dns_summary() -> Dict[str, Any]:
    """Get summary of DNS activity.
    
    Returns:
        Dict with count and categories
    """
    queries = get_dns_queries()
    domains = get_unique_domains(queries)
    
    # Categorize by top-level domain
    categories = {}
    for domain in domains:
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = '.'.join(parts[-2:])
            if tld not in categories:
                categories[tld] = []
            categories[tld].append(domain)
    
    return {
        'total_queries': len(queries),
        'unique_domains': len(domains),
        'categories': categories
    }


# ============================================================================
# Simple CLI test
# ============================================================================

if __name__ == "__main__":
    print("SafeNet - DNS Monitor")
    print("=" * 60)
    print()
    
    print("Reading DNS cache from this machine...")
    print("(Showing recently queried domains)\n")
    
    queries = get_dns_queries(method='cache')
    domains = get_unique_domains(queries)
    
    if domains:
        print(f"Found {len(domains)} unique domains in DNS cache:\n")
        for i, domain in enumerate(domains[:20], 1):
            print(f"  {i:2}. {domain}")
        
        if len(domains) > 20:
            print(f"\n  ... and {len(domains) - 20} more")
    else:
        print("No DNS cache entries found.")
        print("(This is normal if DNS cache is small or feature not available)")
    
    print("\n" + "=" * 60)
    print("\nDNS Summary:")
    summary = get_dns_summary()
    print(f"  Total Queries: {summary['total_queries']}")
    print(f"  Unique Domains: {summary['unique_domains']}")
