"""AI explanation module for privacy risks.

Uses a local LLM (via Ollama) to generate human-readable explanations
of privacy risks in simple, non-technical language.

Note: The AI is used ONLY for explanation. Risk analysis and scoring
are performed by deterministic analysis functions - not by the LLM.

Requires:
    - Ollama installed and running (ollama serve)
    - phi3:mini model pulled (ollama pull phi3:mini)
"""

import subprocess
from typing import Dict, Any

MODEL = "phi3:mini"


def generate_ai_explanation(device: Dict[str, Any], risk_analysis: Dict[str, Any]) -> str:
    """Generate human-readable explanation of privacy risks using local LLM.
    
    Args:
        device: Device dict from network scan
        risk_analysis: Result from analyze_privacy_risk()
        
    Returns:
        String explanation from LLM, or fallback message if unavailable
    """

    prompt = f"""
You are a professional cybersecurity analyst writing a technical assessment.

Provide a concise, professional analysis of the following privacy risks.
Use technical language. Be direct and factual. Avoid analogies or simplifications.

Device Information:
- Device Type: {device.get('Type')}
- Vendor: {device.get('Vendor')}
- Open Ports: {device.get('Open Ports')}
- Detection Confidence: {device.get('Confidence')}

Privacy Risk Assessment:
- Risk Classification: {risk_analysis['risk_level']}
- Risk Reasoning: {risk_analysis['reasoning']}
- Identified Risks:
{chr(10).join('  * ' + r for r in risk_analysis['risks'])}

Provide:
1. Technical Impact Assessment: Explain the security implications
2. Attack Surface Analysis: What vulnerabilities are exposed
3. Mitigation Priority: Recommended action priority level
"""

    try:
        result = subprocess.run(
            ["ollama", "run", MODEL],
            input=prompt,
            text=True,
            encoding='utf-8',
            errors='replace',
            capture_output=True,
            timeout=300
        )
        return result.stdout.strip() if result.stdout else "No explanation generated."
    except FileNotFoundError:
        return "Ollama not installed or not in PATH. Install from https://ollama.ai"
    except subprocess.TimeoutExpired:
        return "LLM response timeout - request took too long."
    except Exception as e:
        return f"AI explanation unavailable: {str(e)}"
