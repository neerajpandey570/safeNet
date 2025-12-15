"""SafeNet Monitoring Module

Local connection and activity monitoring for privacy auditing.

Submodules:
    - connection_monitor: Capture active network connections (netstat)
    - dns_monitor: Get DNS queries from Windows Event Log or cache
    - process_mapper: Map processes to network connections
    - vendor_database: IP/domain to vendor mapping
    - connection_analyzer: Correlate and analyze connections
"""

__version__ = "1.0.0"
__all__ = [
    'connection_monitor',
    'dns_monitor',
    'process_mapper',
    'vendor_database',
    'connection_analyzer'
]
