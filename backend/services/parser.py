import os
import re
import zipfile
import string
import subprocess
import shutil
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

# Try to import Androguard safely with multi-version imports
try:
    from androguard.core.bytecoded.apk import APK
    HAS_ANDROGUARD = True
except ImportError:
    try:
        from androguard.core.apk import APK
        HAS_ANDROGUARD = True
    except ImportError:
        HAS_ANDROGUARD = False

# Regex definitions for static analysis
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"']*)?")
IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# Sensitive API signatures to scan in java code / bytecode strings
SENSITIVE_APIS = {
    "SMS_RECEIVE": [
        "android.provider.Telephony.SMS_RECEIVED",
        "SMS_RECEIVED_ACTION",
        "RECEIVE_SMS",
        "smsReceiver"
    ],
    "SMS_SEND": [
        "SmsManager",
        "sendTextMessage",
        "sendMultipartTextMessage"
    ],
    "ACCESSIBILITY_ABUSE": [
        "AccessibilityService",
        "AccessibilityServiceInfo",
        "onAccessibilityEvent",
        "performGlobalAction"
    ],
    "OVERLAY_ATTACK": [
        "WindowManager.LayoutParams",
        "TYPE_APPLICATION_OVERLAY",
        "TYPE_SYSTEM_ALERT",
        "SYSTEM_ALERT_WINDOW"
    ],
    "DEVICE_ADMIN": [
        "DeviceAdminReceiver",
        "DevicePolicyManager"
    ],
    "DYNAMIC_LOADING": [
        "DexClassLoader",
        "PathClassLoader",
        "Method.invoke",
        "Class.forName"
    ],
    "PROCESS_CREATION": [
        "Runtime.getRuntime().exec",
        "ProcessBuilder"
    ]
}

def extract_strings_from_binary(binary_data: bytes) -> str:
    """Helper to extract ASCII strings from binary files (e.g. dex)."""
    printable = set(string.printable.encode('ascii'))
    result = []
    current = []
    for char in binary_data:
        if char in printable:
            current.append(chr(char))
        else:
            if len(current) >= 4:
                result.append("".join(current))
            current = []
    if len(current) >= 4:
        result.append("".join(current))
    return "\n".join(result)

def scan_file_content(content: str, file_path: str) -> List[Dict[str, Any]]:
    """Scans text content for sensitive APIs and extracts them as findings."""
    detected = []
    for api_name, signatures in SENSITIVE_APIS.items():
        for sig in signatures:
            if sig in content:
                # Find matching line snippet
                lines = content.splitlines()
                snippet = ""
                for line in lines:
                    if sig in line:
                        snippet = line.strip()[:120]
                        break
                detected.append({
                    "name": api_name,
                    "class": os.path.basename(file_path),
                    "method": sig,
                    "snippet": snippet
                })
                break  # Log once per API category per file
    return detected

def parse_apk(apk_path: str, package_only: bool = False) -> Dict[str, Any]:
    """
    Main APK Analysis Engine.
    Uses: Androguard, APKTool, and JADX to decompile and extract evidence.
    Gracefully falls back to pure-Python parsing if external tools are missing.
    """
    evidence = {
        "package_name": "unknown.package",
        "manifest": {
            "package": "unknown.package",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": []
        },
        "permissions": [],
        "apis_detected": [],
        "apis": [],
        "urls": [],
        "services": [],
        "activities": [],
        "certificate_info": {
            "issuer": "unknown",
            "subject": "unknown",
            "serial_number": "unknown",
            "hash_algorithm": "unknown"
        },
        "obfuscation_indicators": [],
        "file_tree": []
    }

    # High-fidelity simulated APK analysis reports
    if "simulated_" in apk_path:
        filename = os.path.basename(apk_path).lower()
        if "anubis" in filename:
            evidence.update({
                "package_name": "com.banking.trojan.anubis",
                "manifest": {
                    "package": "com.banking.trojan.anubis",
                    "permissions": [
                        "android.permission.RECEIVE_SMS",
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.INTERNET"
                    ],
                    "activities": ["com.banking.trojan.anubis.MainActivity"],
                    "services": ["com.banking.trojan.anubis.AccessibilityServiceHijacker"],
                    "receivers": ["com.banking.trojan.anubis.SMSReceiver"]
                },
                "permissions": [
                    "android.permission.RECEIVE_SMS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.INTERNET"
                ],
                "apis_detected": ["ACCESSIBILITY_ABUSE", "SMS_RECEIVE"],
                "urls": ["http://194.26.135.84/api/v2"],
                "services": ["com.banking.trojan.anubis.AccessibilityServiceHijacker"],
                "activities": ["com.banking.trojan.anubis.MainActivity"],
                "certificate_info": {
                    "issuer": "CN=Anubis Developer",
                    "subject": "CN=Anubis Developer",
                    "serial_number": "987654321",
                    "hash_algorithm": "sha256"
                },
                "obfuscation_indicators": ["Reflection dynamic API invocation"],
                "file_tree": ["AndroidManifest.xml", "classes.dex"]
            })
        elif "sharkbot" in filename:
            evidence.update({
                "package_name": "com.helper.update.utility",
                "manifest": {
                    "package": "com.helper.update.utility",
                    "permissions": [
                        "android.permission.READ_SMS",
                        "android.permission.RECEIVE_SMS",
                        "android.permission.SYSTEM_ALERT_WINDOW",
                        "android.permission.INTERNET"
                    ],
                    "activities": ["com.helper.update.utility.UpdateActivity"],
                    "services": ["com.helper.update.utility.OverlayLoader"],
                    "receivers": ["com.helper.update.utility.BootReceiver"]
                },
                "permissions": [
                    "android.permission.READ_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.INTERNET"
                ],
                "apis_detected": ["SMS_RECEIVE", "DYNAMIC_LOADING"],
                "urls": ["fast-update-bank.online"],
                "services": ["com.helper.update.utility.OverlayLoader"],
                "activities": ["com.helper.update.utility.UpdateActivity"],
                "certificate_info": {
                    "issuer": "CN=Android Signer",
                    "subject": "CN=Android Signer",
                    "serial_number": "123456789",
                    "hash_algorithm": "sha256"
                },
                "obfuscation_indicators": ["Dynamic Code Loading (DexClassLoader) usage"],
                "file_tree": ["AndroidManifest.xml", "classes.dex"]
            })
        elif "cerberus" in filename:
            evidence.update({
                "package_name": "com.flash.utility.service",
                "manifest": {
                    "package": "com.flash.utility.service",
                    "permissions": [
                        "android.permission.RECEIVE_SMS",
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",
                        "android.permission.PROCESS_OUTGOING_CALLS",
                        "android.permission.INTERNET"
                    ],
                    "activities": ["com.flash.utility.service.MainActivity"],
                    "services": ["com.flash.utility.service.KeylogService"],
                    "receivers": ["com.flash.utility.service.SmsHook"]
                },
                "permissions": [
                    "android.permission.RECEIVE_SMS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.PROCESS_OUTGOING_CALLS",
                    "android.permission.INTERNET"
                ],
                "apis_detected": ["ACCESSIBILITY_ABUSE", "SMS_RECEIVE"],
                "urls": ["http://phish-guard-portal.xyz"],
                "services": ["com.flash.utility.service.KeylogService"],
                "activities": ["com.flash.utility.service.MainActivity"],
                "certificate_info": {
                    "issuer": "CN=System Signer",
                    "subject": "CN=System Signer",
                    "serial_number": "456789012",
                    "hash_algorithm": "sha256"
                },
                "obfuscation_indicators": ["Reflection dynamic API invocation"],
                "file_tree": ["AndroidManifest.xml", "classes.dex"]
            })
        
        if package_only:
            return {
                "package_name": evidence["package_name"],
                "manifest": {"package": evidence["package_name"]},
                "permissions": [],
                "apis_detected": [],
                "apis": [],
                "urls": [],
                "services": [],
                "activities": [],
                "certificate_info": {},
                "obfuscation_indicators": [],
                "file_tree": []
            }
        return evidence
            
    if not zipfile.is_zipfile(apk_path):
        raise ValueError("Invalid file format. File is not a valid ZIP/APK archive.")
        
    if package_only:
        if HAS_ANDROGUARD:
            try:
                apk_obj = APK(apk_path)
                evidence["package_name"] = apk_obj.get_package()
                evidence["manifest"]["package"] = apk_obj.get_package()
            except Exception:
                pass
        return evidence
        
    temp_dir = tempfile.mkdtemp(prefix="sentinel_analysis_")
    
    try:
        # --- 1. ANDROGUARD PARSING (Primary Metadata) ---
        if HAS_ANDROGUARD:
            try:
                apk_obj = APK(apk_path)
                evidence["package_name"] = apk_obj.get_package()
                evidence["manifest"]["package"] = apk_obj.get_package()
                evidence["permissions"] = apk_obj.get_permissions()
                evidence["manifest"]["permissions"] = apk_obj.get_permissions()
                
                # Component extraction
                evidence["activities"] = apk_obj.get_activities()
                evidence["manifest"]["activities"] = apk_obj.get_activities()
                evidence["services"] = apk_obj.get_services()
                evidence["manifest"]["services"] = apk_obj.get_services()
                
                receivers = apk_obj.get_receivers()
                evidence["manifest"]["receivers"] = receivers
                
                # Check certificates
                certs = apk_obj.get_certificates()
                if certs:
                    c = certs[0]
                    evidence["certificate_info"] = {
                        "issuer": str(c.issuer),
                        "subject": str(c.subject),
                        "serial_number": str(c.serial_number),
                        "hash_algorithm": c.signature_hash_algorithm
                    }
            except Exception as e:
                print(f"[Androguard Warning] Failed to parse: {str(e)}")
                
        # --- 2. APKTOOL DECOMPILATION (Resource & Manifest Extraction) ---
        apktool_dir = os.path.join(temp_dir, "apktool")
        apktool_success = False
        try:
            # Run apktool shell command
            res = subprocess.run(
                ["apktool", "d", "-f", "-o", apktool_dir, apk_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=180
            )
            if res.returncode == 0 and os.path.exists(apktool_dir):
                apktool_success = True
                # Read decoded manifest
                manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    tree = ET.parse(manifest_path)
                    root = tree.getroot()
                    evidence["manifest"]["package"] = root.attrib.get("package", evidence["package_name"])
                    
                    # Read permissions declared in XML
                    xml_perms = []
                    for child in root.findall("uses-permission"):
                        name = child.attrib.get("{http://schemas.android.com/apk/res/android}name")
                        if name:
                            xml_perms.append(name)
                    if xml_perms:
                        evidence["permissions"] = sorted(list(set(evidence["permissions"] + xml_perms)))
                        evidence["manifest"]["permissions"] = evidence["permissions"]
        except Exception as e:
            print(f"[APKTool Skip] Command execution skipped/failed: {str(e)}")
            
        # --- 3. JADX DECOMPILATION (Java Source Extraction & Scan) ---
        jadx_dir = os.path.join(temp_dir, "jadx")
        jadx_success = False
        try:
            res = subprocess.run(
                ["jadx", "-d", jadx_dir, "--no-res", apk_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            if res.returncode == 0 and os.path.exists(jadx_dir):
                jadx_success = True
                
                # Scan Java files recursively for APIs & URLs
                detected_apis = []
                detected_urls = set()
                
                for root_dir, _, files in os.walk(jadx_dir):
                    for file in files:
                        if file.endswith(".java"):
                            file_path = os.path.join(root_dir, file)
                            try:
                                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()
                                    
                                # Scan for sensitive API signatures
                                findings = scan_file_content(content, file_path)
                                if findings:
                                    detected_apis.extend(findings)
                                    
                                # Scan for domains & IPs
                                urls = URL_PATTERN.findall(content)
                                ips = IP_PATTERN.findall(content)
                                for u in urls:
                                    if not any(x in u for x in ["schema.android.com", "w3.org", "android.support"]):
                                        detected_urls.add(u)
                                for ip in ips:
                                    detected_urls.add(f"http://{ip}")
                            except Exception:
                                continue
                                
                evidence["apis"] = detected_apis
                evidence["urls"] = sorted(list(detected_urls))[:40]
        except Exception as e:
            print(f"[JADX Skip] Command execution skipped/failed: {str(e)}")
            
        # --- 4. FALLBACK STATIC SCANNER (Pure Python Zip Analysis) ---
        # Runs if JADX failed or wasn't available, scanning binary DEX data directly.
        if not jadx_success:
            evidence["obfuscation_indicators"].append("Pure-Python dex scan fallback (JADX unavailable)")
            try:
                with zipfile.ZipFile(apk_path, 'r') as zf:
                    file_list = zf.namelist()
                    evidence["file_tree"] = file_list[:80]
                    
                    # Scan raw DEX files
                    dex_files = [f for f in file_list if f.startswith("classes") and f.endswith(".dex")]
                    fallback_apis = set()
                    fallback_urls = set()
                    
                    for dex in dex_files:
                        dex_data = zf.read(dex)
                        dex_text = extract_strings_from_binary(dex_data)
                        
                        # Find URLs
                        urls = URL_PATTERN.findall(dex_text)
                        ips = IP_PATTERN.findall(dex_text)
                        for u in urls:
                            if not any(x in u for x in ["schema.android.com", "w3.org", "android.support"]):
                                fallback_urls.add(u)
                        for ip in ips:
                            fallback_urls.add(f"http://{ip}")
                            
                        # Scan APIs
                        for api_name, signatures in SENSITIVE_APIS.items():
                            for sig in signatures:
                                if sig in dex_text:
                                    fallback_apis.add(api_name)
                                    break
                                    
                        # Check basic packing/obfuscation flags
                        if "DexClassLoader" in dex_text:
                            evidence["obfuscation_indicators"].append("Dynamic Code Loading (DexClassLoader) usage")
                        if "Method.invoke" in dex_text or "Method;->invoke" in dex_text:
                            evidence["obfuscation_indicators"].append("Reflection dynamic API invocation")
                            
                    # Convert to structured list format
                    structured_apis = []
                    for api in fallback_apis:
                        structured_apis.append({
                            "name": api,
                            "class": "classes.dex",
                            "method": "Bytecode signature",
                            "snippet": "Signature found inside Dalvik Executable."
                        })
                    evidence["apis"] = structured_apis
                    evidence["urls"] = sorted(list(fallback_urls))[:40]
            except Exception as e:
                print(f"[Fallback Parser Error] Failed to scan zip files: {str(e)}")
                
    finally:
        # Cleanup temporary files
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    return evidence
