from discovery.network_scan import scan_network, display_devices
from analysis.privacy_risk_enhanced import analyze_privacy_risk
from mitigation.suggestions import suggest_mitigations
from reports.generate_report import generate_report
from monitoring.connection_analyzer import (
    analyze_connections, get_vendor_summary, get_category_breakdown,
    merge_router_data
)
from monitoring.router_monitor import RouterMonitor
from monitoring.pcap_sampler import PCAPSampler
from profiling.identify import DeviceProfiler, assign_privacy_risks
from tabulate import tabulate
from ai.explainer import generate_ai_explanation
from colorama import Fore, Back, Style, init
import logging

# Initialize colorama for Windows color support
init(autoreset=True)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


def colorize_risk(risk_level):
    """Return colored risk level string."""
    if risk_level == "HIGH":
        return f"{Fore.RED}{Back.WHITE}{risk_level}{Style.RESET_ALL}"
    elif risk_level == "MEDIUM":
        return f"{Fore.YELLOW}{Back.WHITE}{risk_level}{Style.RESET_ALL}"
    elif risk_level == "LOW":
        return f"{Fore.GREEN}{Back.WHITE}{risk_level}{Style.RESET_ALL}"
    return risk_level


def main(enable_ai: bool = False, enable_router: bool = False, 
         enable_pcap: bool = False, router_ip: str = None):
    """Main entry point for the SafeNet privacy audit tool.
    
    Args:
        enable_ai: If True, generate AI explanations
        enable_router: If True, attempt router integration
        enable_pcap: If True, enable packet capture sampling
        router_ip: Router IP address (default: 192.168.1.1)
    """
    print("\n" + "=" * 80)
    print("SAFENET - LOCAL PRIVACY AND CONSENT AUDITOR")
    print("=" * 80)
    
    flags = []
    if not enable_ai:
        flags.append("AI disabled (use --ai for AI explanations)")
    if enable_router:
        flags.append("Router integration enabled")
    if enable_pcap:
        flags.append("Packet capture enabled")
    
    if flags:
        print(f"[Flags: {', '.join(flags)}]")
    print()

    # Router integration (optional)
    router_data = None
    if enable_router:
        print("[OPTIONAL] Router Integration - Attempting to collect network-wide data...")
        router_monitor = RouterMonitor(router_ip=router_ip or "192.168.1.1")
        if router_monitor.connect(interactive=True):
            router_data = router_monitor.merge_with_local_connections([])
            print(f"  ✓ Connected to router ({router_monitor.router_os})")
            print(f"  ✓ Found {router_data['summary']['total_devices']} network devices")
            if router_data['summary']['network_telemetry'] > 0:
                print(f"  ⚠ Network telemetry: {router_data['summary']['network_telemetry']} connections")
            router_monitor.disconnect()
        else:
            print("  ✗ Router integration failed - continuing with local-only analysis")
        print()

    # Packet capture (optional)
    throughput_stats = None
    if enable_pcap:
        sampler = PCAPSampler(duration=10)
        if sampler.request_user_consent():
            if sampler.capture():
                throughput_stats = sampler.analyze_throughput()
                print(f"  ✓ Captured and analyzed {len(sampler.packets)} packets")
                print(f"  ✓ Found {len(throughput_stats)} traffic flows")
            else:
                print("  ✗ Packet capture failed")
        print()
    
    # Device profiling enhancement (mDNS)
    profiler = DeviceProfiler()
    print("[OPTIONAL] Starting mDNS discovery for enhanced device profiling...")
    if profiler.start_mdns_discovery(timeout=2):
        print(f"  ✓ mDNS discovered {len(profiler.mdns_devices)} devices")
    else:
        print("  ℹ mDNS unavailable (not a critical issue)")
    print()

    # Step 1: Network Discovery and Profiling
    print("\n[Step 1/5] Discovering devices on local network...\n")

    devices = scan_network()

    if not devices:
        print("No devices discovered. Exiting.")
        return

    print(f"\nDiscovered {len(devices)} device(s)\n")
    
    # Classify devices using advanced profiler
    print("[Profiling] Classifying devices using multi-signal analysis...\n")
    for device in devices:
        ip = device["IP"]
        mac = device["MAC"]
        open_ports = device["Open Ports"]
        
        # Get mDNS info if available
        mdns_info = profiler.mdns_devices.get(ip)
        
        # Classify device with confidence scoring
        device_type, confidence = profiler.infer_device_type(
            ip, mac, open_ports, mdns_info
        )
        
        # Update device with classification
        device["Type"] = device_type
        device["Confidence"] = f"{confidence:.0%}"
        
        # Assign privacy risks based on device type
        device["Privacy"] = assign_privacy_risks(device_type)
    
    display_devices(devices)

    # Step 2: LOCAL CONNECTION MONITORING (This Machine)
    print("\n[Step 2/5] Analyzing this machine's network connections...\n")
    
    try:
        local_connection_analysis = analyze_connections(include_process_info=True)
        
        vendor_summary = get_vendor_summary(local_connection_analysis)
        category_breakdown = get_category_breakdown(local_connection_analysis)
        privacy_risks = get_privacy_risks(local_connection_analysis)
        blocking_recs = get_blocking_recommendations(local_connection_analysis)
        
        print(f"Active Connections: {local_connection_analysis['total_connections']}")
        print(f"Established: {local_connection_analysis['summary']['established']}")
        print(f"Unique Remote IPs: {local_connection_analysis['summary']['unique_remote_ips']}")
        print()
        
        if vendor_summary:
            print("Top Vendors Contacted:")
            for vendor, count in list(vendor_summary.items())[:5]:
                print(f"  • {vendor}: {count} connections")
        print()
        
        if privacy_risks['total_tracking'] > 0:
            print(f"WARNING: Privacy Tracking Detected: {privacy_risks['total_tracking']} connections")
            if privacy_risks['telemetry_vendors']:
                print(f"   Telemetry from: {', '.join(privacy_risks['telemetry_vendors'][:3])}")
            if privacy_risks['advertising_vendors']:
                print(f"   Ads from: {', '.join(privacy_risks['advertising_vendors'][:3])}")
        else:
            print("OK: No tracking networks detected on this machine")
        print()
        
        if blocking_recs:
            print(f"Safe to Block: {len(blocking_recs)} connections (no functionality loss)")
        print()
        
    except Exception as e:
        print(f"WARNING: Connection monitoring skipped: {str(e)}")
        print("   (This is normal if DNS monitoring is not available)")
        local_connection_analysis = None
        print()

    # Step 3: Privacy Risk Analysis
    print("\n[Step 3/5] Analyzing privacy risks...\n")

    for device in devices:
        # Use enhanced analysis if we have connection data
        if local_connection_analysis:
            from analysis.privacy_risk_enhanced import analyze_privacy_risk_with_throughput
            risk_result = analyze_privacy_risk_with_throughput(
                device,
                connection_analysis=local_connection_analysis,
                throughput_stats=throughput_stats
            )
        else:
            risk_result = analyze_privacy_risk(device)
        
        device["risk_analysis"] = risk_result
        
        # Generate AI explanation only if enabled (can be slow)
        if enable_ai:
            ai_explanation = generate_ai_explanation(device, risk_result)
        else:
            ai_explanation = "(AI explanations disabled - enable with --ai flag for detailed insights)"
        device["ai_explanation"] = ai_explanation

    # Step 4: Mitigation Suggestions
    print("\n[Step 4/5] Generating mitigation plans...\n")

    for device in devices:
        mitigations_obj = suggest_mitigations(
            device,
            device["risk_analysis"],
            connection_analysis=local_connection_analysis
        )
        device["mitigations"] = mitigations_obj

    # Step 4: Summary Table
    print("\n" + "=" * 80)
    print("PRIVACY RISK SUMMARY")
    print("=" * 80 + "\n")

    summary_table = [
        [
            d["IP"],
            d["Vendor"][:28],
            d["Type"],
            colorize_risk(d["risk_analysis"]["risk_level"]),
            len(d["risk_analysis"]["risks"]),
            len(d["mitigations"].get("actions", []))
        ]
        for d in devices
    ]

    print(tabulate(
        summary_table,
        headers=[
            "IP Address",
            "Vendor",
            "Device Type",
            "Risk Level",
            "# Risks",
            "# Mitigations"
        ],
        tablefmt="grid"
    ))

    # Step 5: Generate Report
    print("\n[Step 5/5] Generating privacy audit report...\n")

    report_path = generate_report(
        devices, 
        local_connection_analysis,
        router_data=router_data,
        throughput_stats=throughput_stats
    )

    print(f"Report saved to: {report_path}")
    
    # Cleanup
    if profiler.mdns_zeroconf:
        profiler.stop_mdns_discovery()

    print("\n" + "=" * 80)
    print("AUDIT COMPLETE")
    print("=" * 80)
    print("- All analysis performed locally")
    print("- No data sent to cloud")
    print("- User remains in control\n")


if __name__ == "__main__":
    # Check for optional flags
    enable_ai = "--ai" in sys.argv
    enable_router = "--router" in sys.argv
    enable_pcap = "--pcap" in sys.argv
    
    # Extract router IP if provided
    router_ip = None
    for i, arg in enumerate(sys.argv):
        if arg == "--router-ip" and i + 1 < len(sys.argv):
            router_ip = sys.argv[i + 1]
            break
    
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                         SAFENET PRIVACY AUDITOR                           ║
║                                                                            ║
║ Usage:  python main.py [options]                                         ║
║                                                                            ║
║ Options:                                                                   ║
║   --ai              Enable AI explanations (slower, more detailed)        ║
║   --router          Enable router integration (prompts for credentials)   ║
║   --router-ip IP    Specify router IP (default: 192.168.1.1)             ║
║   --pcap            Enable packet capture sampling (requires admin)       ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
""")
    
    main(
        enable_ai=enable_ai,
        enable_router=enable_router,
        enable_pcap=enable_pcap,
        router_ip=router_ip
    )
