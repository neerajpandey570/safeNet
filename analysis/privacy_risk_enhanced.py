"""Enhanced privacy risk analysis with connection data and throughput integration.

Combines deterministic port/vendor analysis with actual connection data
from the local machine and throughput measurements to provide comprehensive
risk assessment.

Functions:
    - analyze_privacy_risk: Base risk analysis (ports/vendor only)
    - analyze_privacy_risk_enhanced: Risk analysis with connection data
    - analyze_privacy_risk_with_throughput: Risk analysis including throughput metrics
    - calculate_connection_risk_score: Score based on actual connections
"""

from typing import Dict, List, Any, Optional


def analyze_privacy_risk(device: dict) -> dict:
    """Original risk analysis (based on ports/vendor only).
    
    Kept for backward compatibility.
    """
    risks = []
    score = 0

    vendor = device.get("Vendor", "").lower()
    device_type = device.get("Type", "").lower()
    ports = device.get("Open Ports", [])
    confidence = device.get("Confidence", "Low")

    # Signal 1: Cloud Traffic & Suspicious Services
    if 443 in ports and 80 not in ports:
        risks.append("Encrypted HTTPS traffic (likely cloud communication)")
        score += 2
    
    if 8883 in ports:
        risks.append("MQTT over TLS detected (IoT cloud messaging)")
        score += 3
    
    if 22 in ports or 5900 in ports or 3389 in ports:
        risks.append("Remote access service detected (SSH/VNC/RDP)")
        score += 2

    # Signal 2: Vendor Behavior
    cloud_vendors = [
        "amazon",
        "google",
        "apple",
        "xiaomi",
        "samsung"
    ]

    if any(v in vendor for v in cloud_vendors):
        risks.append("Vendor known for cloud-based services")
        score += 2

    # Signal 3: Device Type
    if "camera" in device_type:
        risks.append("Camera device may collect video/audio data")
        score += 4

    if "iot" in device_type:
        risks.append("IoT device often communicates continuously with cloud")
        score += 3

    if "unknown" in device_type:
        risks.append("Device identity unclear")
        score += 2

    # Signal 4: Confidence Modifier
    if confidence.lower() == "low":
        risks.append("Low identification confidence - analysis less reliable")
        score += 2

    # Determine Risk Level
    if score >= 7:
        risk_level = "HIGH"
    elif score >= 4:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    reasoning = (
        f"Risk score {score} based on "
        f"{len(risks)} observed privacy-related signals."
    )

    return {
        "risks": risks,
        "risk_level": risk_level,
        "reasoning": reasoning,
        "score": score
    }


def analyze_privacy_risk_enhanced(device: dict, 
                                 connection_analysis: Optional[Dict[str, Any]] = None) -> dict:
    """Enhanced risk analysis that incorporates actual connection data.
    
    Args:
        device: Device dict from network scan
        connection_analysis: Optional connection analysis from monitoring (if this machine)
    
    Returns:
        Enhanced risk assessment dict
    """
    # Start with base analysis
    base_analysis = analyze_privacy_risk(device)
    base_score = base_analysis.get("score", 0)
    
    # If this is not the local machine or no connection data, return base
    if not connection_analysis:
        return base_analysis
    
    # Integrate connection data signals
    enhanced_risks = list(base_analysis["risks"])
    connection_score_bonus = 0
    
    # Signal 1: Active tracking connections detected
    tracking_connections = connection_analysis.get("by_category", {}).get("TELEMETRY", [])
    if tracking_connections:
        tracking_vendors = list(set(c["vendor"] for c in tracking_connections))
        enhanced_risks.append(
            f"Active telemetry detected to {len(tracking_vendors)} vendors: {', '.join(tracking_vendors[:3])}"
        )
        connection_score_bonus += min(len(tracking_connections) * 0.5, 2)
    
    # Signal 2: Active advertising networks
    ad_connections = connection_analysis.get("by_category", {}).get("ADVERTISING", [])
    if ad_connections:
        ad_vendors = list(set(c["vendor"] for c in ad_connections))
        enhanced_risks.append(
            f"Active advertising networks ({len(ad_vendors)} vendors)"
        )
        connection_score_bonus += min(len(ad_connections), 2)
    
    # Signal 3: Cloud data connections
    cloud_connections = connection_analysis.get("by_category", {}).get("CLOUD", [])
    if cloud_connections:
        cloud_vendors = list(set(c["vendor"] for c in cloud_connections))
        enhanced_risks.append(
            f"Cloud sync/backup to: {', '.join(cloud_vendors[:3])}"
        )
        connection_score_bonus += min(len(cloud_connections) * 0.3, 1)
    
    # Signal 4: High number of connections (potential data exfiltration)
    total_connections = connection_analysis.get("total_connections", 0)
    if total_connections > 20:
        enhanced_risks.append(
            f"High connection count ({total_connections}) - potential excessive data transfer"
        )
        connection_score_bonus += 1
    
    # Recalculate risk level with connection bonus
    enhanced_score = base_score + connection_score_bonus
    
    if enhanced_score >= 8:
        enhanced_risk_level = "HIGH"
    elif enhanced_score >= 5:
        enhanced_risk_level = "MEDIUM"
    else:
        enhanced_risk_level = "LOW"
    
    # Create enhanced reasoning
    enhanced_reasoning = (
        f"Risk score {enhanced_score:.1f} based on "
        f"{len(enhanced_risks)} signals "
        f"(base: {base_score}, from connections: +{connection_score_bonus:.1f})"
    )
    
    return {
        "risks": enhanced_risks,
        "risk_level": enhanced_risk_level,
        "reasoning": enhanced_reasoning,
        "score": enhanced_score,
        "base_score": base_score,
        "connection_bonus": connection_score_bonus,
        "has_tracking": bool(tracking_connections),
        "has_ads": bool(ad_connections),
        "has_cloud": bool(cloud_connections)
    }


def analyze_privacy_risk_with_throughput(device: dict, 
                                         connection_analysis: Optional[Dict[str, Any]] = None,
                                         throughput_stats: Optional[Dict[str, Any]] = None) -> dict:
    """Risk analysis including throughput and traffic classification metrics.
    
    Args:
        device: Device dict from network scan
        connection_analysis: Connection analysis with domain and category data
        throughput_stats: Dict of throughput measurements per flow {(src, dst): ThroughputStats}
    
    Returns:
        Enhanced risk assessment with throughput signals
    """
    # Start with enhanced analysis
    result = analyze_privacy_risk_enhanced(device, connection_analysis)
    
    if not throughput_stats:
        return result
    
    # Analyze throughput patterns for privacy signals
    throughput_bonus = 0
    throughput_risks = []
    
    # Classify flows by throughput behavior
    streaming_flows = []  # High sustained throughput
    upload_flows = []  # High outgoing throughput
    telemetry_flows = []  # Small frequent packets
    
    for flow_key, stats in throughput_stats.items():
        throughput_recv = getattr(stats, 'throughput_recv', 0)
        throughput_send = getattr(stats, 'throughput_send', 0)
        packets_recv = getattr(stats, 'packets_received', 0)
        
        classification = getattr(stats, 'get_classification', lambda: 'OTHER')()
        
        if classification == 'STREAMING':
            streaming_flows.append(stats)
        elif classification == 'UPLOAD':
            upload_flows.append(stats)
        elif classification == 'TELEMETRY':
            telemetry_flows.append(stats)
    
    # Signal 1: Streaming data (video/music)
    if streaming_flows:
        throughput_risks.append(
            f"Streaming traffic detected ({len(streaming_flows)} flows) - potential video/audio upload"
        )
        throughput_bonus += min(len(streaming_flows), 2)
    
    # Signal 2: High outgoing upload rates
    if upload_flows:
        total_upload = sum(getattr(s, 'bytes_sent', 0) for s in upload_flows) / (1024*1024)  # MB
        throughput_risks.append(
            f"High upload rate detected ({total_upload:.1f}MB) - potential data exfiltration"
        )
        throughput_bonus += min(2, int(total_upload / 100) + 1)  # Score based on MB uploaded
    
    # Signal 3: Excessive telemetry patterns
    if len(telemetry_flows) > 10:
        throughput_risks.append(
            f"Frequent telemetry-like packets ({len(telemetry_flows)} flows) - continuous monitoring detected"
        )
        throughput_bonus += 1
    
    # Update result with throughput findings
    result['risks'].extend(throughput_risks)
    result['score'] += throughput_bonus
    
    # Recalculate risk level
    if result['score'] >= 8:
        result['risk_level'] = "HIGH"
    elif result['score'] >= 5:
        result['risk_level'] = "MEDIUM"
    else:
        result['risk_level'] = "LOW"
    
    # Update reasoning
    result['reasoning'] = (
        f"Risk score {result['score']:.1f} based on "
        f"{len(result['risks'])} signals "
        f"(base: {result.get('base_score', 0)}, "
        f"connections: +{result.get('connection_bonus', 0):.1f}, "
        f"throughput: +{throughput_bonus})"
    )
    
    result['throughput_bonus'] = throughput_bonus
    result['traffic_types'] = {
        'streaming': len(streaming_flows),
        'upload': len(upload_flows),
        'telemetry': len(telemetry_flows),
    }
    
    return result


def calculate_connection_risk_score(connections: List[Dict[str, Any]],
                                    domains: Optional[List[str]] = None) -> float:
    """Calculate risk score based on connection characteristics.
    
    Args:
        connections: List of connection analysis dicts
        domains: List of queried domains (optional)
    
    Returns:
        Risk score (0-10)
    """
    if not connections:
        return 0.0
    
    score = 0.0
    
    # Count connections by category
    categories = {}
    for conn in connections:
        cat = conn.get('category', 'UNKNOWN')
        categories[cat] = categories.get(cat, 0) + 1
    
    # Scoring rules
    score += categories.get('TELEMETRY', 0) * 0.5  # Each telemetry = +0.5
    score += categories.get('ADVERTISING', 0) * 1.0  # Each ad = +1.0
    score += categories.get('CLOUD', 0) * 0.3  # Each cloud = +0.3
    
    # Bonus for many connections (potential data exfiltration)
    if len(connections) > 20:
        score += 1.0
    if len(connections) > 50:
        score += 2.0
    
    # Bonus for known tracking domains
    if domains:
        tracking_domains = [d for d in domains if any(
            tracker in d.lower() 
            for tracker in ['tracking', 'analytics', 'telemetry', 'facebook.com', 'google-analytics']
        )]
        score += len(tracking_domains) * 0.5
    
    return min(10.0, score)


def print_privacy_report(device: dict) -> None:
    """Display privacy risk analysis report for a device.
    
    Args:
        device: Device dict from network scan
    """
    result = analyze_privacy_risk(device)

    print("\nPrivacy Risks Detected:")
    for r in result["risks"]:
        print(f"  - {r}")

    print(f"\nRisk Level: {result['risk_level']}")
    print(f"Reasoning: {result['reasoning']}")


if __name__ == "__main__":
    # Test enhanced analysis
    sample_device = {
        "IP": "192.168.1.43",
        "Vendor": "Intel",
        "Type": "Laptop / PC",
        "Confidence": "High",
        "Open Ports": [443, 22]
    }
    
    print("Base Analysis:")
    result = analyze_privacy_risk(sample_device)
    print(f"  Risk Level: {result['risk_level']}")
    print(f"  Score: {result['score']}")
    print(f"  Risks: {result['risks']}")
