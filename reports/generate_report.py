"""Report generation module for privacy audit results.

Exports network scan results, privacy risk analysis, mitigation
recommendations, router data, and throughput analysis to a timestamped 
human-readable text file.

Functions:
    - generate_report: Create comprehensive privacy audit report
"""

from datetime import datetime
from typing import Optional, Dict, Any
import os


def generate_report(devices: list, 
                   local_connection_analysis: Optional[Dict[str, Any]] = None,
                   router_data: Optional[Dict[str, Any]] = None,
                   throughput_stats: Optional[Dict[str, Any]] = None) -> str:
    """Generate a privacy audit report file from scan and analysis results.
    
    Creates a timestamped text report containing device details, risk
    assessments, recommended mitigations, local connection analysis,
    router data, and throughput statistics.
    
    Args:
        devices: List of device dicts enriched with:
            - risk_analysis: Result from analyze_privacy_risk()
            - mitigations: Result from suggest_mitigations()
        local_connection_analysis: Optional result from connection_analyzer.analyze_connections()
        router_data: Optional result from router_monitor.merge_with_local_connections()
        throughput_stats: Optional result from pcap_sampler.analyze_throughput()
    
    Returns:
        Path to the generated report file
    """

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = f"reports/privacy_report_{timestamp}.txt"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("SAFENET – PRIVACY AUDIT REPORT\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Scan Time: {datetime.now()}\n")
        f.write(f"Total Devices Detected: {len(devices)}\n\n")

        # -------------------------
        # Summary
        # -------------------------
        high = sum(1 for d in devices if d["risk_analysis"]["risk_level"] == "HIGH")
        med = sum(1 for d in devices if d["risk_analysis"]["risk_level"] == "MEDIUM")
        low = sum(1 for d in devices if d["risk_analysis"]["risk_level"] == "LOW")

        f.write("RISK SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"HIGH   : {high}\n")
        f.write(f"MEDIUM : {med}\n")
        f.write(f"LOW    : {low}\n\n")

        # -------------------------
        # LOCAL MACHINE CONNECTIONS (if available)
        # -------------------------
        if local_connection_analysis:
            f.write("=" * 80 + "\n")
            f.write("THIS MACHINE'S NETWORK ACTIVITY\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("ACTIVE CONNECTIONS SUMMARY\n")
            f.write("-" * 40 + "\n")
            summary = local_connection_analysis.get('summary', {})
            f.write(f"Total Connections: {local_connection_analysis.get('total_connections', 0)}\n")
            f.write(f"Established: {summary.get('established', 0)}\n")
            f.write(f"Unique Remote IPs: {summary.get('unique_remote_ips', 0)}\n\n")
            
            # Vendor breakdown
            vendor_summary = {}
            for conn in local_connection_analysis.get('analyzed_connections', []):
                vendor = conn.get('vendor', 'Unknown')
                vendor_summary[vendor] = vendor_summary.get(vendor, 0) + 1
            
            if vendor_summary:
                f.write("VENDORS CONTACTED:\n")
                for vendor, count in sorted(vendor_summary.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  - {vendor}: {count} connections\n")
                f.write("\n")
            
            # Category breakdown
            category_summary = {}
            for conn in local_connection_analysis.get('analyzed_connections', []):
                category = conn.get('category', 'UNKNOWN')
                category_summary[category] = category_summary.get(category, 0) + 1
            
            if category_summary:
                f.write("CONNECTION CATEGORIES:\n")
                for category in ['FUNCTIONAL', 'CLOUD', 'TELEMETRY', 'ADVERTISING', 'INFRASTRUCTURE', 'UNKNOWN']:
                    if category in category_summary:
                        f.write(f"  - {category}: {category_summary[category]} connections\n")
                f.write("\n")
            
            # Privacy assessment
            privacy_risks = {}
            tracking_conns = [c for c in local_connection_analysis.get('analyzed_connections', [])
                            if c.get('category') in ['TELEMETRY', 'ADVERTISING']]
            
            if tracking_conns:
                f.write("PRIVACY TRACKING DETECTED:\n")
                f.write(f"  ⚠️  {len(tracking_conns)} connections for tracking/analytics\n")
                
                # Group by vendor
                tracking_by_vendor = {}
                for conn in tracking_conns:
                    vendor = conn.get('vendor', 'Unknown')
                    tracking_by_vendor[vendor] = tracking_by_vendor.get(vendor, 0) + 1
                
                for vendor, count in sorted(tracking_by_vendor.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"    - {vendor}: {count} tracking connections\n")
                f.write("\n")
            else:
                f.write("✓ No obvious tracking networks detected\n\n")
            
            # Safe to block recommendations
            blocking_recs = [c for c in local_connection_analysis.get('analyzed_connections', [])
                           if c.get('safe_to_block')]
            
            if blocking_recs:
                f.write("SAFE TO BLOCK (No Functional Impact):\n")
                for rec in blocking_recs[:10]:
                    f.write(f"  ✓ {rec.get('endpoint', 'Unknown')} - {rec.get('vendor', 'Unknown')} ({rec.get('category', 'Unknown')})\n")
                if len(blocking_recs) > 10:
                    f.write(f"  ... and {len(blocking_recs) - 10} more\n")
                f.write("\n")
            
            # Process-level breakdown
            process_summary = local_connection_analysis.get('process_summary', {})
            if process_summary:
                f.write("CONNECTIONS BY APPLICATION:\n")
                for category in ['Browser', 'Cloud Storage', 'Messaging', 'Media', 'OS Service', 'Development', 'Other']:
                    if category in process_summary:
                        processes = process_summary[category]
                        f.write(f"  {category}:\n")
                        for proc in processes:
                            f.write(f"    - {proc['process']} ({proc['connection_count']} connections)\n")
                f.write("\n")
            
            f.write("\n")

        # -------------------------
        # ROUTER-WIDE ANALYSIS (if available)
        # -------------------------
        if router_data and router_data.get('connected'):
            f.write("=" * 80 + "\n")
            f.write("NETWORK-WIDE ANALYSIS (Router Integration)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Router OS: {router_data.get('router_os', 'Unknown')}\n\n")
            
            summary = router_data.get('summary', {})
            f.write("NETWORK SUMMARY:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Devices: {summary.get('total_devices', 0)}\n")
            f.write(f"Total Network Connections: {summary.get('total_network_connections', 0)}\n")
            f.write(f"Devices with Tracking: {summary.get('devices_with_tracking', 0)}\n")
            f.write(f"Devices with Ads: {summary.get('devices_with_ads', 0)}\n")
            f.write(f"Network Telemetry Connections: {summary.get('network_telemetry', 0)}\n")
            f.write(f"Network Advertising Connections: {summary.get('network_advertising', 0)}\n\n")
            
            # Per-device network analysis
            network_devices = router_data.get('network_devices', {})
            if network_devices:
                f.write("PER-DEVICE NETWORK ACTIVITY:\n")
                f.write("-" * 40 + "\n")
                for device_ip, device_analysis in network_devices.items():
                    device_info = device_analysis.get('device_info', {})
                    hostname = device_info.get('hostname', 'Unknown')
                    mac = device_info.get('mac', 'Unknown')
                    
                    f.write(f"\n  {hostname} ({device_ip})\n")
                    f.write(f"    MAC: {mac}\n")
                    f.write(f"    Connections: {device_analysis.get('total_connections', 0)}\n")
                    f.write(f"    Bytes Sent: {device_analysis.get('bytes_sent', 0):,}\n")
                    f.write(f"    Bytes Received: {device_analysis.get('bytes_received', 0):,}\n")
                    
                    # DNS queries
                    dns_queries = device_analysis.get('dns_queries', [])
                    if dns_queries:
                        unique_domains = list(set(dns_queries))
                        f.write(f"    DNS Queries: {', '.join(unique_domains[:5])}")
                        if len(unique_domains) > 5:
                            f.write(f" ... and {len(unique_domains) - 5} more")
                        f.write("\n")
            f.write("\n")

        # -------------------------
        # THROUGHPUT ANALYSIS (if available)
        # -------------------------
        if throughput_stats:
            f.write("=" * 80 + "\n")
            f.write("TRAFFIC THROUGHPUT ANALYSIS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("TOP FLOWS BY THROUGHPUT:\n")
            f.write("-" * 40 + "\n")
            
            # Sort flows by throughput
            sorted_flows = sorted(
                throughput_stats.items(),
                key=lambda x: getattr(x[1], 'throughput_recv', 0),
                reverse=True
            )
            
            for (src_ip, src_port, dst_ip, dst_port), stats in sorted_flows[:15]:
                classification = getattr(stats, 'get_classification', lambda: 'OTHER')()
                
                if stats.throughput_recv > 1_000_000:
                    throughput_str = f"{stats.throughput_recv/1_000_000:.1f} MB/s"
                elif stats.throughput_recv > 1000:
                    throughput_str = f"{stats.throughput_recv/1000:.1f} KB/s"
                else:
                    throughput_str = f"{stats.throughput_recv:.0f} B/s"
                
                f.write(f"  {dst_ip}:{dst_port:<5} {classification:<12} {throughput_str:>12}\n")
            
            # Classification summary
            classifications = {}
            for stats in throughput_stats.values():
                classification = getattr(stats, 'get_classification', lambda: 'OTHER')()
                classifications[classification] = classifications.get(classification, 0) + 1
            
            f.write("\nTRAFFIC CLASSIFICATION:\n")
            f.write("-" * 40 + "\n")
            for classification, count in sorted(classifications.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {classification:<15} {count:>5} flows\n")
            f.write("\n")

        # -------------------------
        # Per Device Details
        # -------------------------
        for idx, device in enumerate(devices, start=1):
            risk = device["risk_analysis"]
            mitigations_obj = device.get("mitigations", {})
            mitigations = mitigations_obj.get("actions", []) if isinstance(mitigations_obj, dict) else mitigations_obj

            f.write("=" * 80 + "\n")
            f.write(f"DEVICE {idx}\n")
            f.write("=" * 80 + "\n")

            f.write(f"IP Address : {device['IP']}\n")
            f.write(f"MAC        : {device['MAC']}\n")
            f.write(f"Vendor     : {device['Vendor']}\n")
            f.write(f"Type       : {device['Type']}\n")
            f.write(f"Confidence : {device['Confidence']}\n")
            f.write(f"Open Ports : {device.get('Open Ports', [])}\n\n")

            f.write(f"RISK LEVEL : {risk['risk_level']}\n")
            f.write(f"REASONING  : {risk['reasoning']}\n\n")

            f.write("DETECTED RISKS:\n")
            if risk["risks"]:
                for r in risk["risks"]:
                    f.write(f"  - {r}\n")
            else:
                f.write("  None detected\n")

            # AI Explanation Section
            ai_explanation = device.get("ai_explanation", "")
            if ai_explanation:
                f.write("\nAI EXPLANATION:\n")
                f.write(f"{ai_explanation}\n")

            f.write("\nMITIGATION ACTIONS:\n")
            if mitigations:
                for m in mitigations:
                    f.write(f"  - {m['title']} [{m['difficulty']}]\n")
            else:
                f.write("  No mitigation required\n")

            f.write("\n")

        # -------------------------
        # BLOCKING RECOMMENDATIONS (from mitigation suggestions)
        # -------------------------
        if local_connection_analysis and local_connection_analysis.get('blocking_rules'):
            f.write("=" * 80 + "\n")
            f.write("BLOCKING RECOMMENDATIONS\n")
            f.write("=" * 80 + "\n\n")
            
            blocking_rules = local_connection_analysis.get('blocking_rules', [])
            domain_blocking = local_connection_analysis.get('domain_blocking_rules', [])
            
            if blocking_rules:
                f.write("CONNECTION-LEVEL BLOCKING (by IP:Port):\n")
                f.write("-" * 40 + "\n")
                
                for rule in blocking_rules[:20]:  # Limit to top 20
                    endpoint = rule.get('endpoint', 'Unknown')
                    vendor = rule.get('vendor', 'Unknown')
                    category = rule.get('category', 'Unknown')
                    reason = rule.get('reason', 'Unknown')
                    
                    f.write(f"\n{endpoint} ({vendor})\n")
                    f.write(f"  Category: {category}\n")
                    f.write(f"  Reason:   {reason}\n")
                    
                    # Show platform-specific rules if available
                    if 'windows_rule' in rule:
                        f.write(f"  Windows:  {rule['windows_rule']}\n")
                    if 'linux_rule' in rule:
                        f.write(f"  Linux:    {rule['linux_rule']}\n")
                
                if len(blocking_rules) > 20:
                    f.write(f"\n... and {len(blocking_rules) - 20} more blocking rules\n")
                f.write("\n")
            
            if domain_blocking:
                f.write("DOMAIN-LEVEL BLOCKING (DNS):\n")
                f.write("-" * 40 + "\n")
                
                for rule in domain_blocking[:20]:  # Limit to top 20
                    domain = rule.get('domain', 'Unknown')
                    category = rule.get('category', 'Unknown')
                    
                    f.write(f"\n{domain}\n")
                    f.write(f"  Category: {category}\n")
                    
                    # Show DNS blocking methods
                    if 'pihole_rule' in rule:
                        f.write(f"  PiHole:   {rule['pihole_rule']}\n")
                    if 'hosts_rule' in rule:
                        f.write(f"  Hosts:    {rule['hosts_rule']}\n")
                    if 'dnsmasq_rule' in rule:
                        f.write(f"  dnsmasq:  {rule['dnsmasq_rule']}\n")
                
                if len(domain_blocking) > 20:
                    f.write(f"\n... and {len(domain_blocking) - 20} more domain blocking rules\n")
                f.write("\n")
        
        f.write("=" * 80 + "\n")
        f.write("END OF REPORT\n")

    return report_path
