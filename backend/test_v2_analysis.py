import os
import sys

# Ensure backend folder is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from v2.analysis import calculate_risk, extract_iocs, map_mitre, generate_v2_report
from v2.models import V2Job, V2Event

def test_analysis_pipeline():
    print("========================================")
    print(" SENTINELAI v2: Analysis Pipeline Test")
    print("========================================")

    # 1. Mock Static Findings
    static_findings = {
        "package_name": "com.banking.trojan.anubis",
        "permissions": [
            "android.permission.RECEIVE_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET"
        ],
        "apis_detected": ["ACCESSIBILITY_ABUSE", "SMS_RECEIVE", "DYNAMIC_LOADING"],
        "urls": ["http://194.26.135.84/api/v2/gate.php"],
        "obfuscation_indicators": ["Reflection dynamic API invocation"]
    }

    # 2. Mock Dynamic Telemetry Events
    mock_events = [
        V2Event(
            event_type="evasion_emulator",
            source="frida",
            payload={"check_type": "Build.HARDWARE", "indicator": "goldfish"},
            is_suspicious=True
        ),
        V2Event(
            event_type="dex_load",
            source="frida",
            payload={"path": "/sdcard/Download/payload.dex"},
            is_suspicious=True
        ),
        V2Event(
            event_type="network_request",
            source="frida",
            payload={"url": "http://194.26.135.84/api/v2/gate.php", "method": "POST"},
            is_suspicious=True
        ),
        V2Event(
            event_type="sms_send",
            source="frida",
            payload={"dest": "+1-555-0199", "text": "SMS exfiltration content"},
            is_suspicious=True
        )
    ]

    # 3. Test Risk Scorer
    print("\n[*] Evaluating Combined Risk Scorer...")
    risk = calculate_risk(static_findings, mock_events)
    
    print(f"  - Static Risk Score: {risk['static_risk_score']}/100")
    print(f"  - Dynamic Risk Score: {risk['dynamic_risk_score']}/100")
    print(f"  - Combined Risk Score: {risk['risk_score']}/100")
    print(f"  - Severity Verdict: {risk['severity']}")
    print(f"  - Verdict Class: {risk['verdict']}")
    print(f"  - Malware Family: {risk['malware_family']}")
    print(f"  - Confidence: {risk['confidence']}%")
    print("\n  - Risk Factors:")
    for f in risk["risk_factors"]:
        print(f"    * [{f['points']} pts] {f['factor']}: {f['justification']}")

    # 4. Test IOC Extractor
    print("\n[*] Running IOC Extractor...")
    iocs = extract_iocs(mock_events)
    for ioc in iocs:
        print(f"  - Extracted {ioc['type'].upper()}: {ioc['value']} (Source: {ioc['source']})")

    # 5. Test MITRE Mapper
    print("\n[*] Running MITRE ATT&CK Mapper...")
    mitre = map_mitre(mock_events)
    for m in mitre:
        print(f"  - Mapped {m['id']} ({m['technique']}) -> Tactic: {m['tactic']}")
        print(f"    Evidence: {m['evidence']}")

    # 6. Test Local Template Report Generation
    print("\n[*] Generating Security Brief Report...")
    # Initialize a mock Job model
    mock_job = V2Job(
        package_name=static_findings["package_name"],
        malware_family=risk["malware_family"],
        risk_score=risk["risk_score"],
        severity=risk["severity"],
        static_findings=static_findings,
        mitre_mappings=mitre,
        iocs=iocs,
        risk_factors=risk["risk_factors"]
    )
    report = generate_v2_report(mock_job, mock_events)
    
    print("\n[+] Report Generation Complete.")
    print("\n--- EXECUTIVE SUMMARY PREVIEW ---")
    print(report["executive_summary"][:300] + "...")
    print("\n--- REMEDIATION PREVIEW ---")
    print(report["remediation"][:300] + "...")
    
    print("\n========================================")
    print(" TEST SUCCESSFUL!")
    print("========================================")

if __name__ == "__main__":
    test_analysis_pipeline()
