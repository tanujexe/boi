import requests
import time
import os
import sys

BASE_URL = "http://127.0.0.1:8000"
TEST_APKS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_apks")

def upload_and_test(file_name, is_sample=False, sample_key=None):
    print(f"\n[-] Testing file: {file_name}")
    
    # Trigger upload
    if is_sample:
        url = f"{BASE_URL}/api/upload-sample?sample_key={sample_key}"
        res = requests.post(url)
    else:
        file_path = os.path.join(TEST_APKS_DIR, file_name)
        if not os.path.exists(file_path):
            print(f"[!] Error: Test file not found at {file_path}")
            return None
            
        url = f"{BASE_URL}/api/jobs/upload"
        with open(file_path, "rb") as f:
            res = requests.post(url, files={"file": f})
            
    if res.status_code not in [200, 202]:
        print(f"[!] Upload failed with code {res.status_code}: {res.text}")
        return None
        
    job_id = res.json()["id"]
    print(f"[+] Uploaded successfully. Job ID: {job_id}. Polling status...")
    
    # Poll status
    attempts = 0
    max_attempts = 30
    while attempts < max_attempts:
        job_res = requests.get(f"{BASE_URL}/api/jobs/{job_id}")
        if job_res.status_code == 200:
            job_data = job_res.json()["job"]
            status = job_data["status"]
            if status == "COMPLETED":
                print(f"[+] Job Completed. Risk Score: {job_data['risk_score']}%, Severity: {job_data['severity']}")
                return {
                    "filename": file_name,
                    "status": status,
                    "risk_score": job_data["risk_score"],
                    "severity": job_data["severity"],
                    "family": job_data["malware_family"] or "Clean/Benign"
                }
            elif status == "FAILED":
                print("[!] Job Failed on server.")
                return {"filename": file_name, "status": "FAILED", "risk_score": 0, "severity": "Unknown", "family": "Unknown"}
        else:
            print(f"[!] Polling failed: {job_res.status_code}")
            
        time.sleep(1.5)
        attempts += 1
        
    print("[!] Polling timed out.")
    return None

def main():
    print("==========================================================")
    print("      SentinelAI Multi-Case Automated Test Suite")
    print("==========================================================")
    
    results = []
    
    # Case 1: Upload Clean App (test_clean.apk) via REST Multipart Form
    res = upload_and_test("test_clean.apk")
    if res:
        results.append(res)
        
    # Case 2: Upload Simulated Anubis App (simulated_anubis.apk) via REST Multipart Form
    res = upload_and_test("simulated_anubis.apk")
    if res:
        results.append(res)
        
    # Case 3: Upload Simulated SharkBot App (simulated_sharkbot.apk) via REST Multipart Form
    res = upload_and_test("simulated_sharkbot.apk")
    if res:
        results.append(res)
        
    print("\n" + "="*70)
    print("                  TEST VALIDATION SUMMARY")
    print("="*70)
    print(f"{'Target Filename':<24} | {'Status':<10} | {'Risk Score':<10} | {'Severity':<10} | {'Family':<20}")
    print("-"*70)
    for r in results:
        print(f"{r['filename']:<24} | {r['status']:<10} | {str(r['risk_score'])+'%':<10} | {r['severity']:<10} | {r['family']:<20}")
    print("==========================================================\n")

if __name__ == "__main__":
    main()
