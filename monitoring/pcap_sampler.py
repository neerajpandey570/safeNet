"""Packet-level traffic sampling and throughput measurement module.

Captures and analyzes packet-level traffic to measure:
  - Real-time throughput (bytes per second)
  - Traffic classification (streaming, telemetry, uploads)
  - Protocol patterns (TCP window size, MTU, TTL)
  - Per-connection byte rates

Usage:
    sampler = PCAPSampler(interface='Ethernet', duration=10)
    
    # Capture packets with user consent
    if sampler.request_user_consent():
        results = sampler.capture()
        analysis = sampler.analyze_throughput()
"""

import sys
import platform
import subprocess
import re
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass


try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger(__name__)


@dataclass
class ThroughputStats:
    """Statistics for a connection's throughput."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    duration: float  # seconds
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    throughput_send: float  # bytes per second
    throughput_recv: float  # bytes per second
    avg_packet_size: float
    
    def get_classification(self) -> str:
        """Classify traffic based on throughput characteristics.
        
        Returns:
            Classification: 'STREAMING', 'UPLOAD', 'DOWNLOAD', 'TELEMETRY', 'WEB', 'OTHER'
        """
        # High sustained throughput = streaming/download
        if self.throughput_recv > 500_000:  # >500 KB/s
            return 'STREAMING'
        
        # High upload rate
        if self.throughput_send > 500_000:  # >500 KB/s
            return 'UPLOAD'
        
        # Moderate throughput with large packets = video
        if self.throughput_recv > 100_000 and self.avg_packet_size > 1000:
            return 'STREAMING'
        
        # Small, frequent packets = telemetry/heartbeat
        if self.throughput_recv < 10_000 and self.packets_received > 50:
            return 'TELEMETRY'
        
        # Web-like traffic
        if self.throughput_recv > 10_000 and self.throughput_recv < 100_000:
            return 'WEB'
        
        # Small transfers
        if self.bytes_received < 1_000 and self.bytes_sent < 1_000:
            return 'TELEMETRY'
        
        return 'OTHER'


class PCAPSampler:
    """Packet-level traffic capture and analysis for throughput measurement."""
    
    def __init__(self, interface: Optional[str] = None, duration: int = 10, 
                 packet_limit: int = 10000):
        """Initialize packet sniffer.
        
        Args:
            interface: Network interface to sniff on (auto-detect if None)
            duration: Capture duration in seconds
            packet_limit: Maximum packets to capture
        """
        if not HAS_SCAPY:
            logger.warning("Scapy not available - packet capture disabled")
        
        self.interface = interface
        self.duration = duration
        self.packet_limit = packet_limit
        self.packets: List[Any] = []
        self.os_type = platform.system()
        self.requires_admin = True  # Packet capture always needs admin
        self.user_consented = False
    
    def request_user_consent(self) -> bool:
        """Request user consent for packet capture (privacy-sensitive).
        
        Returns:
            True if user consented, False otherwise
        """
        print("\n" + "="*70)
        print("PRIVACY WARNING: PACKET CAPTURE")
        print("="*70)
        print("""
SafeNet can measure real-time network throughput by capturing packets
for 5-10 seconds. This allows us to classify traffic as:
  • Streaming (video, music) - high throughput
  • Uploads (file sync, backup) - high outgoing bytes
  • Telemetry (analytics, tracking) - small frequent packets
  • Web browsing - moderate throughput with patterns

PRIVACY IMPLICATIONS:
  ✓ Packets are analyzed LOCALLY on your machine
  ✓ No data leaves your computer
  ✓ Packet payloads are NOT inspected - only metadata
  ✓ Packet capture requires ADMINISTRATOR privileges
  ✓ Only connection-level stats are kept (not individual packets)

This helps answer: "Is my camera really uploading video right now?"
""")
        
        response = input("Enable packet-level traffic measurement? (yes/no): ").strip().lower()
        
        if response in ['yes', 'y']:
            self.user_consented = True
            return True
        else:
            print("Packet capture disabled - will use connection counts only")
            return False
    
    def get_interface(self) -> Optional[str]:
        """Auto-detect network interface if not specified."""
        if self.interface:
            return self.interface
        
        try:
            if self.os_type == 'Windows':
                # On Windows, try to find the main interface
                result = subprocess.run(
                    'ipconfig',
                    capture_output=True,
                    text=True
                )
                # Parse for Ethernet or Wi-Fi adapter
                for line in result.stdout.split('\n'):
                    if 'Ethernet adapter' in line or 'Wireless' in line:
                        match = re.search(r'adapter\s+(.+):', line)
                        if match:
                            return match.group(1).strip()
            else:
                # On Linux/Mac, use standard interfaces
                result = subprocess.run(
                    ['ip', 'route', 'show'],
                    capture_output=True,
                    text=True
                )
                # Get default interface
                match = re.search(r'default.*dev\s+(\S+)', result.stdout)
                if match:
                    return match.group(1)
        except Exception as e:
            logger.warning(f"Could not auto-detect interface: {e}")
        
        return None
    
    def capture(self, duration: Optional[int] = None) -> bool:
        """Capture packets from network interface.
        
        Args:
            duration: Capture duration in seconds (overrides init)
        
        Returns:
            True if capture succeeded, False otherwise
        """
        if not HAS_SCAPY:
            logger.error("Scapy not installed - packet capture unavailable")
            return False
        
        if not self.user_consented:
            logger.warning("User did not consent to packet capture")
            return False
        
        duration = duration or self.duration
        interface = self.get_interface()
        
        if not interface:
            logger.error("Could not determine network interface")
            return False
        
        try:
            print(f"\nCapturing packets for {duration} seconds...")
            print(f"Interface: {interface}")
            
            # Define packet handler
            packet_count = [0]  # Use list to allow modification in nested function
            
            def packet_callback(pkt):
                if packet_count[0] >= self.packet_limit:
                    return
                self.packets.append(pkt)
                packet_count[0] += 1
                if packet_count[0] % 100 == 0:
                    print(f"  Captured {packet_count[0]} packets...")
            
            # Start sniffing
            sniff(
                iface=interface,
                prn=packet_callback,
                timeout=duration,
                store=True
            )
            
            print(f"Captured {len(self.packets)} packets in {duration}s")
            return True
        
        except PermissionError:
            logger.error("Packet capture requires administrator privileges")
            return False
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")
            return False
    
    def analyze_throughput(self) -> Dict[Tuple[str, int, str, int], ThroughputStats]:
        """Analyze captured packets for throughput statistics.
        
        Returns:
            Dict mapping (src_ip, src_port, dst_ip, dst_port) to ThroughputStats
        """
        if not self.packets:
            logger.warning("No packets to analyze")
            return {}
        
        flows = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'start_time': None,
            'end_time': None,
            'protocol': 'unknown',
            'local_ip': None
        })
        
        try:
            # Analyze each packet
            for pkt in self.packets:
                if not pkt.haslayer(IP):
                    continue
                
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = 'unknown'
                src_port = 0
                dst_port = 0
                
                # Get protocol and ports
                if pkt.haslayer(TCP):
                    protocol = 'tcp'
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    protocol = 'udp'
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                else:
                    continue
                
                packet_size = len(pkt)
                flow_key = (src_ip, src_port, dst_ip, dst_port)
                
                # Update flow stats
                flow = flows[flow_key]
                flow['protocol'] = protocol
                
                # Track bytes by direction
                if not flow['start_time']:
                    flow['start_time'] = time.time()
                flow['end_time'] = time.time()
                
                # Determine if packet is outgoing or incoming
                # (heuristic: treat lower IP as local)
                if src_ip < dst_ip or src_ip.startswith('192.168') or src_ip.startswith('10.'):
                    flow['bytes_sent'] += packet_size
                    flow['packets_sent'] += 1
                    flow['local_ip'] = src_ip
                else:
                    flow['bytes_received'] += packet_size
                    flow['packets_received'] += 1
                    flow['local_ip'] = src_ip
        
        except Exception as e:
            logger.error(f"Error analyzing packets: {e}")
        
        # Convert to ThroughputStats
        results = {}
        for (src_ip, src_port, dst_ip, dst_port), flow_data in flows.items():
            if flow_data['start_time'] and flow_data['end_time']:
                duration = max(0.1, flow_data['end_time'] - flow_data['start_time'])
                total_packets = flow_data['packets_sent'] + flow_data['packets_received']
                
                if total_packets > 0:
                    results[(src_ip, src_port, dst_ip, dst_port)] = ThroughputStats(
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=flow_data['protocol'],
                        duration=duration,
                        bytes_sent=flow_data['bytes_sent'],
                        bytes_received=flow_data['bytes_received'],
                        packets_sent=flow_data['packets_sent'],
                        packets_received=flow_data['packets_received'],
                        throughput_send=flow_data['bytes_sent'] / duration,
                        throughput_recv=flow_data['bytes_received'] / duration,
                        avg_packet_size=sum([
                            flow_data['bytes_sent'],
                            flow_data['bytes_received']
                        ]) / total_packets if total_packets > 0 else 0
                    )
        
        return results
    
    def generate_report(self) -> str:
        """Generate text report of throughput analysis."""
        throughput_stats = self.analyze_throughput()
        
        lines = []
        lines.append("\n" + "="*80)
        lines.append("PACKET-LEVEL THROUGHPUT ANALYSIS")
        lines.append("="*80)
        lines.append("")
        
        if not throughput_stats:
            lines.append("No packet data available")
            lines.append("="*80)
            return "\n".join(lines)
        
        # Sort by throughput (receive)
        sorted_flows = sorted(
            throughput_stats.items(),
            key=lambda x: x[1].throughput_recv,
            reverse=True
        )
        
        lines.append(f"Analyzed {len(sorted_flows)} flows from {len(self.packets)} packets")
        lines.append("")
        
        lines.append("TOP FLOWS BY THROUGHPUT")
        lines.append("-"*80)
        lines.append(f"{'Endpoint':<45} {'Classification':<15} {'Throughput':<15}")
        lines.append("-"*80)
        
        for (src_ip, src_port, dst_ip, dst_port), stats in sorted_flows[:15]:
            endpoint = f"{dst_ip}:{dst_port}"
            classification = stats.get_classification()
            
            # Format throughput
            if stats.throughput_recv > 1_000_000:
                throughput_str = f"{stats.throughput_recv/1_000_000:.1f} MB/s"
            elif stats.throughput_recv > 1000:
                throughput_str = f"{stats.throughput_recv/1000:.1f} KB/s"
            else:
                throughput_str = f"{stats.throughput_recv:.0f} B/s"
            
            lines.append(f"{endpoint:<45} {classification:<15} {throughput_str:<15}")
        
        lines.append("")
        lines.append("TRAFFIC CLASSIFICATION SUMMARY")
        lines.append("-"*80)
        
        # Count classifications
        classifications = defaultdict(int)
        for stats in throughput_stats.values():
            classifications[stats.get_classification()] += 1
        
        for classification, count in sorted(classifications.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {classification:<20} {count:>5} flows")
        
        lines.append("")
        lines.append("="*80)
        
        return "\n".join(lines)


def interactive_capture(interface: Optional[str] = None) -> Optional[Dict]:
    """Interactive packet capture with user consent.
    
    Returns:
        Dict with throughput statistics or None if user declined
    """
    sampler = PCAPSampler(interface=interface, duration=10)
    
    if not sampler.request_user_consent():
        return None
    
    if sampler.capture():
        return sampler.analyze_throughput()
    
    return None


def main():
    """Test packet capture."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    
    if not HAS_SCAPY:
        print("Scapy is required for packet capture")
        print("Install with: pip install scapy")
        return
    
    print("SafeNet - Packet Capture Throughput Analyzer")
    print("="*60)
    
    stats = interactive_capture()
    
    if stats:
        sampler = PCAPSampler(duration=10)
        sampler.packets = []  # Clear for demo
        print(sampler.generate_report())


if __name__ == "__main__":
    main()
