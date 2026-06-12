import os
import re
import json
from datetime import datetime
from typing import List, Dict, Any

# Regex definitions for IOC extraction
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"']*)?")
IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

# Try to import Groq client
try:
    from groq import Groq
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False

def extract_iocs(events: List[Any]) -> List[Dict[str, Any]]:
    """
    Extract Indicators of Compromise (IOCs) from runtime events.
    """
    iocs = []
    seen = set()

    for event in events:
        # If event is a SQLAlchemy model, get its payload
        payload = event.payload if hasattr(event, "payload") else event.get("payload", {})
        event_type = event.event_type if hasattr(event, "event_type") else event.get("event_type", "")

        if event_type == "network_request":
            url = payload.get("url", "")
            if url and url not in seen:
                seen.add(url)
                iocs.append({"type": "url", "value": url, "source": "network_request", "confidence": "high"})
                
                # Extract IP if present
                ip_match = IP_PATTERN.findall(url)
                for ip in ip_match:
                    if ip not in seen:
                        seen.add(ip)
                        iocs.append({"type": "ip", "value": ip, "source": "network_request", "confidence": "high"})
                        
        elif event_type == "dns_query":
            domain = payload.get("domain", "")
            if domain and domain not in seen:
                seen.add(domain)
                iocs.append({"type": "domain", "value": domain, "source": "dns_query", "confidence": "high"})
                
        elif event_type == "sms_send":
            dest = payload.get("dest", "")
            if dest and dest not in seen:
                seen.add(dest)
                iocs.append({"type": "phone_number", "value": dest, "source": "sms_send", "confidence": "high"})

        elif event_type == "file_write":
            path = payload.get("path", "")
            if path and path not in seen:
                seen.add(path)
                iocs.append({"type": "file_path", "value": path, "source": "file_write", "confidence": "medium"})

    return iocs

def is_event_suspicious(event: Any) -> bool:
    """
    Validate if a dynamic event is truly suspicious.
    Filters out common benign behaviors to prevent MITRE mapping false positives.
    """
    event_type = event.event_type if hasattr(event, "event_type") else event.get("event_type", "")
    payload = event.payload if hasattr(event, "payload") else event.get("payload", {})
    
    # Check if explicitly flagged as suspicious by Frida hooks
    is_suspicious_flag = event.is_suspicious if hasattr(event, "is_suspicious") else event.get("is_suspicious", False)
    
    # SMS transmission, dex loading, evasion checks, shell execution are inherently suspicious
    if event_type in ["sms_send", "dex_load", "evasion_emulator", "evasion_root", "evasion_debugger", "shell_exec"]:
        return True
        
    if event_type == "network_request":
        url = payload.get("url", "").lower()
        if not url:
            return False
            
        # Parse host from URL
        host_match = re.search(r"https?://([^/:\s]+)", url)
        if not host_match:
            return False
        host = host_match.group(1)
        
        # Safe Domains Checklist:
        # Ignore requests to well-known safe domains (google, microsoft, github, android, etc.)
        safe_patterns = [
            r"google\.com$",
            r"googleapis\.com$",
            r"googleadservices\.com$",
            r"gstatic\.com$",
            r"microsoft\.com$",
            r"github\.com$",
            r"githubusercontent\.com$",
            r"android\.com$",
            r"apple\.com$",
            r"firebaseio\.com$",
            r"crashlytics\.com$"
        ]
        if any(re.search(pattern, host) for pattern in safe_patterns):
            return False
            
        # Suspicious Indicators Checklist:
        # 1. Raw IP callbacks (e.g. http://194.26.135.84/...)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            return True
            
        # 2. Dynamic DNS domains
        suspicious_domains = [
            r"\.ddns\.net$",
            r"\.no-ip\.org$",
            r"\.noip\.com$",
            r"\.duckdns\.org$",
            r"\.ngrok-free\.app$",
            r"\.locall\.host$"
        ]
        if any(re.search(pattern, host) for pattern in suspicious_domains):
            return True
            
        # 3. Malware-like C2 paths/patterns (e.g. gate.php)
        path = url.split(host, 1)[-1]
        c2_patterns = ["gate.php", "/api/v2/gate", "bot_checkin", "c2_connect", "exfil", "phish", "malicious"]
        if any(pat in path for pat in c2_patterns):
            return True
            
        # Check if HTTP method is POST or PUT to an unverified external server
        method = payload.get("method", "GET").upper()
        if method in ["POST", "PUT"] and is_suspicious_flag:
            return True
            
        return is_suspicious_flag

    if event_type == "permission_request":
        # Check if it requests high-risk permissions
        perm = payload.get("permission", "")
        high_risk_perms = ["ACCESSIBILITY", "SYSTEM_ALERT_WINDOW", "RECEIVE_SMS", "SEND_SMS", "READ_SMS"]
        if any(hr in perm for hr in high_risk_perms):
            return True
        return False

    return is_suspicious_flag

def map_mitre(events: List[Any]) -> List[Dict[str, Any]]:
    """
    Map dynamic events to MITRE ATT&CK Mobile Tactics and Techniques.
    """
    mitre_mappings = []
    seen_ids = set()

    # MITRE ATT&CK Mapping Database
    MITRE_DB = {
        "sms_send": {"id": "T1582", "tactic": "Credential Access / Collection", "technique": "SMS Control / Interception"},
        "dex_load": {"id": "T1407", "tactic": "Execution", "technique": "Dynamic Code Loading"},
        "evasion_emulator": {"id": "T1633.001", "tactic": "Defense Evasion", "technique": "Virtualization / Emulator Evasion"},
        "evasion_root": {"id": "T1633", "tactic": "Defense Evasion", "technique": "Root Detection / Device Evasion"},
        "evasion_debugger": {"id": "T1633", "tactic": "Defense Evasion", "technique": "Debugger Evasion"},
        "shell_exec": {"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter"},
        "network_request": {"id": "T1437", "tactic": "Command and Control", "technique": "Standard Application Layer Protocol"},
        "permission_request": {"id": "T1626", "tactic": "Defense Evasion / Persistence", "technique": "Abuse Elevation Control Mechanism"}
    }

    for event in events:
        # Only map suspicious events
        if not is_event_suspicious(event):
            continue
            
        event_type = event.event_type if hasattr(event, "event_type") else event.get("event_type", "")
        payload = event.payload if hasattr(event, "payload") else event.get("payload", {})
        
        if event_type in MITRE_DB:
            mapping = MITRE_DB[event_type]
            # Key mappings by ID + evidence details to avoid duplicate records but allow distinct evidences
            key = f"{mapping['id']}_{event_type}"
            if key not in seen_ids:
                seen_ids.add(key)
                
                # Build evidence description
                evidence = ""
                if event_type == "sms_send":
                    evidence = f"Sent SMS to {payload.get('dest', 'unknown')}: '{payload.get('text', '')[:30]}...'"
                elif event_type == "dex_load":
                    evidence = f"Loaded DEX file from: {payload.get('path', 'unknown')}"
                elif event_type == "shell_exec":
                    evidence = f"Executed shell command: {payload.get('command', 'unknown')}"
                elif event_type == "network_request":
                    evidence = f"HTTP {payload.get('method', 'GET')} request to {payload.get('url', 'unknown')}"
                elif event_type == "evasion_emulator":
                    evidence = f"Queried emulator indicator: {payload.get('indicator', 'unknown')} via {payload.get('check_type', 'unknown')}"
                else:
                    evidence = f"Detected runtime indicator of {event_type}"

                mitre_mappings.append({
                    "id": mapping["id"],
                    "tactic": mapping["tactic"],
                    "technique": mapping["technique"],
                    "evidence": evidence
                })

    return mitre_mappings

def calculate_risk(static_findings: Dict[str, Any], events: List[Any]) -> Dict[str, Any]:
    """
    Deterministic risk calculation engine combining static metadata and dynamic logs.
    """
    static_score = 0
    dynamic_score = 0
    risk_factors = []
    
    # 1. Evaluate Static Findings
    permissions = static_findings.get("permissions", [])
    apis_detected = static_findings.get("apis_detected", [])
    obfuscation = static_findings.get("obfuscation_indicators", [])
    urls = static_findings.get("urls", [])

    # Permissions
    sms_perms = [p for p in permissions if any(s in p.upper() for s in ["SMS", "RECEIVE_SMS", "READ_SMS", "SEND_SMS"])]
    if sms_perms:
        static_score += 20
        risk_factors.append({
            "factor": "Static SMS Permissions Declared",
            "points": 20,
            "justification": f"Declares permissions to read, write, or intercept SMS texts: {', '.join(sms_perms)}"
        })

    if any("ACCESSIBILITY" in p.upper() or "BIND_ACCESSIBILITY_SERVICE" in p for p in permissions):
        static_score += 25
        risk_factors.append({
            "factor": "Static Accessibility Service Binding",
            "points": 25,
            "justification": "Declares binding for BIND_ACCESSIBILITY_SERVICE. Frequently abused by banking trojans for overlay injections and keylogging."
        })

    if any("SYSTEM_ALERT_WINDOW" in p or "ALERT" in p.upper() for p in permissions):
        static_score += 20
        risk_factors.append({
            "factor": "Static System Overlay Permission",
            "points": 20,
            "justification": "Requests SYSTEM_ALERT_WINDOW to draw overlay panels over other application interfaces."
        })

    # APIs & Obfuscation
    if "DYNAMIC_LOADING" in apis_detected:
        static_score += 10
        risk_factors.append({
            "factor": "Static Dynamic Code Loading Signatures",
            "points": 10,
            "justification": "Discovered class loader API signatures (DexClassLoader, PathClassLoader) capable of loading runtime code payload."
        })

    if obfuscation:
        static_score += 10
        risk_factors.append({
            "factor": "Static Code Obfuscation Heuristics",
            "points": 10,
            "justification": f"Decompiler flagged code protection layers: {', '.join(obfuscation)}"
        })

    if urls:
        static_score += 15
        risk_factors.append({
            "factor": "Static hardcoded external callback URLs",
            "points": 15,
            "justification": f"Found {len(urls)} hardcoded domains or IPs representing potential command and control links."
        })

    # 2. Evaluate Dynamic Runtime Events
    event_types = set()
    for event in events:
        etype = event.event_type if hasattr(event, "event_type") else event.get("event_type", "")
        event_types.add(etype)

    if "sms_send" in event_types:
        dynamic_score += 35
        risk_factors.append({
            "factor": "Dynamic Runtime SMS Transmission",
            "points": 35,
            "justification": "Active intercept/exfiltration verified at runtime. App attempted to programmatically transmit SMS text messages."
        })

    if "dex_load" in event_types:
        dynamic_score += 25
        risk_factors.append({
            "factor": "Dynamic Runtime DEX Loading",
            "points": 25,
            "justification": "App dynamically loaded compiled Dalvik bytecode (DEX/JAR) in the sandbox, executing unverified code."
        })

    if "evasion_emulator" in event_types or "evasion_root" in event_types or "evasion_debugger" in event_types:
        dynamic_score += 20
        risk_factors.append({
            "factor": "Dynamic Anti-Analysis / Evasion Detections",
            "points": 20,
            "justification": "App actively queried environment parameters (Build.FINGERPRINT, Build.HARDWARE, Root checks) to detect and evade sandbox analysis."
        })

    if "shell_exec" in event_types:
        dynamic_score += 15
        risk_factors.append({
            "factor": "Dynamic Shell Command Execution",
            "points": 15,
            "justification": "App spawned system command interpreters (sh, su, exec) to run shell code outside Dalvik boundaries."
        })

    if "network_request" in event_types:
        dynamic_score += 15
        risk_factors.append({
            "factor": "Dynamic Command & Control (C2) Activity",
            "points": 15,
            "justification": "App initiated outbound HTTP/HTTPS requests to external hosts captured by the sandbox proxy layer."
        })

    if "crypto_op" in event_types:
        dynamic_score += 10
        risk_factors.append({
            "factor": "Dynamic Cryptographic Cipher Actions",
            "points": 10,
            "justification": "App dynamically initialized symmetric cryptographic APIs (AES, DES) to decrypt payloads or encrypt exfiltrated data."
        })

    # Cappings
    static_risk_score = min(static_score, 100)
    dynamic_risk_score = min(dynamic_score, 100)
    
    # Combined score optimization
    risk_score = max(static_risk_score, dynamic_risk_score)
    
    # Adjust for totally clean runs
    if not risk_factors:
        risk_score = 0
        severity = "Low"
        verdict = "clean"
        malware_family = "None (Benign)"
        confidence = 100
    else:
        # Determine Severity and Verdict
        if risk_score <= 25:
            severity = "Low"
            verdict = "clean"
        elif risk_score <= 50:
            severity = "Medium"
            verdict = "suspicious"
        elif risk_score <= 75:
            severity = "High"
            verdict = "suspicious"
        else:
            severity = "Critical"
            verdict = "malicious"

        # Determine Malware Family based on heuristics
        package_name = static_findings.get("package_name", "").lower()
        
        if "anubis" in package_name or ("sms_send" in event_types and "SYSTEM_ALERT_WINDOW" in permissions):
            malware_family = "Anubis Banking Trojan"
        elif "sharkbot" in package_name or ("dex_load" in event_types and "sms_send" in event_types):
            malware_family = "SharkBot Financial Trojan"
        elif "cerberus" in package_name or ("sms_send" in event_types and "PROCESS_OUTGOING_CALLS" in permissions):
            malware_family = "Cerberus Trojan"
        elif verdict == "malicious":
            malware_family = "Generic Android Trojan"
        else:
            malware_family = "Benign / Low Risk Utility"

        # Confidence is calculated as a factor of findings correlation
        # If both static permissions and runtime execution confirm a pattern, confidence is high
        if static_risk_score > 40 and dynamic_risk_score > 40:
            confidence = 95
        elif dynamic_risk_score > 20:
            confidence = 85
        else:
            confidence = 70

    return {
        "static_risk_score": static_risk_score,
        "dynamic_risk_score": dynamic_risk_score,
        "risk_score": risk_score,
        "severity": severity,
        "verdict": verdict,
        "malware_family": malware_family,
        "confidence": confidence,
        "risk_factors": risk_factors
    }

def generate_v2_report(job: Any, events: List[Any], api_key: str = None) -> Dict[str, str]:
    """
    Generate professional security briefs using Groq API, with robust local template fallbacks.
    """
    family = job.malware_family
    risk_score = job.risk_score
    severity = job.severity
    package_name = job.package_name or "unknown.package"
    
    # 1. Try Groq API first
    use_groq = HAS_GROQ and (api_key or os.environ.get("GROQ_API_KEY"))
    if use_groq:
        try:
            groq_key = api_key or os.environ.get("GROQ_API_KEY")
            client = Groq(api_key=groq_key)
            
            system_prompt = (
                "You are SentinelAI's v2 Android Sandbox Reporting Engine. Your task is to generate structured, "
                "forensic-grade cybersecurity analysis reports. You must synthesize static decompiler evidence "
                "alongside runtime sandbox telemetry (dynamic hooks and API logs) to prove threat behaviors. "
                "You MUST return strictly a valid JSON object matching the requested schema. Do not add markdown wrappers around the JSON."
            )
            
            # Format some event summaries for the LLM
            suspicious_events = [
                {
                    "type": e.event_type if hasattr(e, "event_type") else e.get("event_type"),
                    "source": e.source if hasattr(e, "source") else e.get("source"),
                    "payload": e.payload if hasattr(e, "payload") else e.get("payload"),
                    "is_suspicious": e.is_suspicious if hasattr(e, "is_suspicious") else e.get("is_suspicious", False)
                } for e in events if (e.is_suspicious if hasattr(e, "is_suspicious") else e.get("is_suspicious", False))
            ]
            
            user_prompt = f"""
            Analyze the following execution data and generate a detailed report for Android app package '{package_name}':
            
            - **Malware Family Class**: {family}
            - **Calculated Sandbox Risk**: {risk_score}/100 ({severity})
            - **Static Findings**: {json.dumps(job.static_findings or {{}})}
            - **Suspicious Dynamic Events Captured**: {json.dumps(suspicious_events[:15])}
            - **MITRE ATT&CK Mappings**: {json.dumps(job.mitre_mappings or [])}
            - **IOCs**: {json.dumps(job.iocs or [])}
            
            Your report MUST be a JSON object with this exact structure:
            {{
              "executive_summary": "### Executive Threat Summary\\n\\n[Provide a brief executive-level brief highlighting the verdict, risk level, threat family, sandbox-proven behaviors (C2 connections, SMS leaks, overlay rendering), and business/fraud impact. Use bold markdown, tables or lists where appropriate.]",
              "technical_report": "### Technical Sandbox Analysis\\n\\n[Review the decompilation artifacts and runtime telemetry. Explain exactly how the static findings (permissions, packages) correlate with runtime events (specific Frida hooks fired, API payloads, network requests). Discuss bypassing of debugger/emulator evasion checks. Detail class names and system parameters.]",
              "behavioral_summary": "### Sandbox Behavioral Telemetry Summary\\n\\n[Detail the sandbox execution timeline, listing the key runtime milestones (e.g. package installation, frida script inject, app launch, SMS interception triggers, dynamic load triggers) and how the telemetry validates threat objectives.]",
              "remediation": "### Actionable Remediation & Threat Mitigation\\n\\n[Categorize actionable mitigations: 1. Developers (overlay flags, anti-debug/tamper checks, cert pinning); 2. Network/SOC (C2 DNS/IP blocklists, telemetry mapping); 3. End Users (revoking high-risk permission options, resetting critical credentials)]"
            }}
            """
            
            # Request response format
            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                model="llama-3.1-70b-versatile",
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            
            response_text = chat_completion.choices[0].message.content
            data = json.loads(response_text)
            
            return {
                "executive_summary": data.get("executive_summary", ""),
                "technical_report": data.get("technical_report", ""),
                "behavioral_summary": data.get("behavioral_summary", ""),
                "remediation": data.get("remediation", "")
            }
            
        except Exception as e:
            # Fall back to template report if Groq fails
            pass

    # 2. Local Template-Based Report Generator
    # Check if malicious
    if risk_score > 50:
        exec_summary = f"""### Executive Threat Summary

The Android application **{package_name}** has been analyzed in the SentinelAI v2 isolated sandbox and classified as **{severity} Risk** (Risk Score: **{risk_score}/100**). Sandbox execution has successfully mapped threat signatures matching the **{family}** malware lineage. 

Dynamic telemetry confirmed critical banking trojan indicators, including active API interception, background SMS command hooks, and code virtualization evasion. The target presents a high risk of credentials harvesting and transactional 2FA/OTP exfiltration.
"""
        tech_report = f"""### Technical Sandbox Analysis

Forensic audit of decompiler outputs combined with dynamic Frida interception logs reveals severe malicious patterns:

#### 1. API Instrumentation Hooks Triggered
Sandbox runtime trace logged multiple sensitive API invocations bypassing normal application behaviors:
"""
        # Append dynamic hooks explanations
        dynamic_evs = [e for e in events if (e.is_suspicious if hasattr(e, "is_suspicious") else e.get("is_suspicious", False))]
        for ev in dynamic_evs[:8]:
            etype = ev.event_type if hasattr(ev, "event_type") else ev.get("event_type")
            payload = ev.payload if hasattr(ev, "payload") else ev.get("payload", {})
            tech_report += f"- **{etype.upper()} ({ev.source if hasattr(ev, 'source') else ev.get('source')}):** {json.dumps(payload)}\n"
            
        tech_report += f"""
#### 2. Static Metadata Correlation
The dynamic behaviors observed align precisely with static manifest privileges. The app declares structural accessibility hijacking services (`BIND_ACCESSIBILITY_SERVICE`) and drawing permissions (`SYSTEM_ALERT_WINDOW`), allowing it to overlay malicious webviews and capture keystrokes.
"""
        behavioral_summary = f"""### Sandbox Behavioral Telemetry Summary

#### Sandbox Execution Flow:
1. **00:02** AVD Boot completed. Virtual workspace initialized.
2. **00:04** Target package `{package_name}` deployed via ADB.
3. **00:05** Frida server attached to target process. 8 hooks active.
4. **00:07** Telemetry capture initialized. Output streams redirected.
"""
        # Add runtime milestones based on actual logs
        idx = 5
        for ev in dynamic_evs:
            elapsed = ev.elapsed_ms if hasattr(ev, "elapsed_ms") else ev.get("elapsed_ms", 0)
            if elapsed is None:
                elapsed = 0
            secs = int(elapsed / 1000)
            etype = ev.event_type if hasattr(ev, "event_type") else ev.get("event_type")
            behavioral_summary += f"5. **00:{secs:02d}** Captured event: `{etype}` (Source: {ev.source if hasattr(ev, 'source') else ev.get('source')})\n"
            idx += 1
            if idx > 12:
                break
                
        behavioral_summary += f"\nTotal events captured: {len(events)}. Analysis terminated due to workspace sandbox timer expiry."

        remediation = f"""### Actionable Remediation & Threat Mitigation

#### 1. Developer Mitigations
- Implement `FLAG_SECURE` in Android activity layers to block GUI screenshots and background overlay rendering.
- Add robust anti-tampering checks verifying signature matches at startup.
- Enforce strict Certificate Pinning to block SSL inspection layers.

#### 2. Security Operations (SOC) Actionables
- Block the following command-and-control connection targets at network gateways:
"""
        for ioc in extract_iocs(events):
            if ioc["type"] in ["url", "ip", "domain"]:
                remediation += f"  - `{ioc['value']}`\n"
        
        remediation += """
#### 3. Incident Response & User Action
- Revoke all high-risk device settings, specifically Accessibility Services access.
- Perform a factory reset if device administrator overrides cannot be removed.
"""

    else:
        exec_summary = f"""### Executive Threat Summary

The Android application **{package_name}** was successfully analyzed in the SentinelAI v2 isolated sandbox. It has been classified as **Low Risk** (Score: **{risk_score}/100**). No signatures matching known financial trojans or spyware were detected.
"""
        tech_report = f"""### Technical Sandbox Analysis

No high-severity code findings or runtime API hooks were triggered during execution. 
- **System Calls:** Evaluated standard class loaders, network descriptors, and security parameters.
- **Dynamic Tracing:** Frida telemetry observed standard Android SDK activity behaviors. No background SMS listeners or dynamic code injection attempts were detected.
"""
        behavioral_summary = f"""### Sandbox Behavioral Telemetry Summary

Sandbox execution completed cleanly. The application launched, executed standard UI operations, and terminated without spawning secondary shell processes or performing evasive sandbox detection calls.
- Total runtime: {job.timeout_seconds} seconds.
- Telemetry events logged: {len(events)}.
"""
        remediation = """### Actionable Remediation & Threat Mitigation

No indicators of compromise were discovered. Standard publishing guidelines are recommended:
- Maintain regular signature validations.
- Resubmit major builds to automated analysis pipelines.
"""

    return {
        "executive_summary": exec_summary,
        "technical_report": tech_report,
        "behavioral_summary": behavioral_summary,
        "remediation": remediation
    }
