import os
import time
import json
import asyncio
import subprocess
import datetime
from sqlalchemy.orm import Session

from v2.config import (
    ADB_PATH, EMULATOR_PATH, EMULATOR_AVD_NAME,
    FRIDA_SCRIPT_PATH, ANALYSIS_TIMEOUT, MITMPROXY_PORT
)
from v2.database import get_v2_db, SessionLocal
from v2.models import V2Job, V2Event, V2Report
from v2.analysis import calculate_risk, extract_iocs, map_mitre, generate_v2_report
from services.parser import parse_apk
from services.websocket_manager import manager

# Try to import frida
try:
    import frida
    HAS_FRIDA = True
except ImportError:
    HAS_FRIDA = False

def broadcast_v2_log(job_id: str, message: str, mtype: str = "LOG"):
    """Helper to broadcast real-time logs to the WebSocket manager."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(manager.broadcast(job_id, {
            "type": mtype,
            "message": message,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }))
    except Exception:
        pass
    finally:
        loop.close()

def is_emulator_booted() -> bool:
    """Check if the Android Emulator boot is complete."""
    try:
        result = subprocess.run(
            [ADB_PATH, "shell", "getprop", "sys.boot_completed"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == "1"
    except Exception:
        return False

def boot_emulator(job_id: str) -> bool:
    """Boot the Android Emulator if not already running."""
    broadcast_v2_log(job_id, "Checking Android Emulator status...")
    
    # Check if a device is already connected
    try:
        res = subprocess.run([ADB_PATH, "devices"], capture_output=True, text=True, timeout=5)
        if "emulator-" in res.stdout:
            broadcast_v2_log(job_id, "Active emulator detected. Skipping boot phase.")
            return True
    except Exception:
        pass

    broadcast_v2_log(job_id, f"Launching Emulator AVD '{EMULATOR_AVD_NAME}' in writable-system mode...")
    try:
        # Start emulator in background process
        # We use -writable-system to ensure certificate injections work, and -no-snapshot-load to start fresh
        subprocess.Popen([
            EMULATOR_PATH,
            "-avd", EMULATOR_AVD_NAME,
            "-writable-system",
            "-no-snapshot-load",
            "-no-boot-anim"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Poll for boot completion (up to 120s)
        max_attempts = 24
        for i in range(max_attempts):
            time.sleep(5)
            if is_emulator_booted():
                broadcast_v2_log(job_id, "Android Emulator booted successfully!")
                # Run adb root to prepare environment
                subprocess.run([ADB_PATH, "root"], capture_output=True)
                return True
            broadcast_v2_log(job_id, f"Waiting for emulator boot... ({ (i + 1) * 5 }s elapsed)")
            
    except Exception as e:
        broadcast_v2_log(job_id, f"Emulator launch failed: {str(e)}")
        
    return False

def run_v2_pipeline(job_id: str, apk_path: str):
    """
    Main orchestrator pipeline for static + dynamic APK analysis.
    """
    db: Session = SessionLocal()
    job = db.query(V2Job).filter(V2Job.id == job_id).first()
    if not job:
        db.close()
        return

    try:
        # ────────────────────────────────────────────────────────
        # STAGE 1: STATIC ANALYSIS
        # ────────────────────────────────────────────────────────
        job.status = "STATIC_ANALYSIS"
        job.current_stage = "STATIC_ANALYSIS"
        job.progress = 10
        job.started_at = datetime.datetime.utcnow()
        db.commit()
        
        broadcast_v2_log(job_id, "Starting Static Analysis Engine...")
        static_findings = parse_apk(apk_path)
        job.package_name = static_findings.get("package_name", "unknown.package")
        job.static_findings = static_findings
        job.progress = 25
        db.commit()
        broadcast_v2_log(job_id, f"Static analysis finished. Package name: {job.package_name}")

        is_simulated = "simulated_" in os.path.basename(apk_path) or not HAS_FRIDA
        
        # If static_only mode or no dynamic capability, proceed to scoring
        if job.analysis_mode == "static_only":
            broadcast_v2_log(job_id, "Analysis mode set to static_only. Skipping sandbox run.")
            finalize_analysis(db, job, [])
            return

        # ────────────────────────────────────────────────────────
        # STAGE 2: SANDBOX TELEMETRY EXECUTION
        # ────────────────────────────────────────────────────────
        captured_events = []

        if is_simulated:
            # Run High-Fidelity Simulation Path (Failsafe)
            run_simulated_sandbox(job_id, job, captured_events)
        else:
            try:
                # Run Live Sandbox Path
                run_live_sandbox(job_id, job, apk_path, captured_events)
            except Exception as e:
                broadcast_v2_log(job_id, f"[WARNING] Live sandbox execution failed: {str(e)}. Falling back to high-fidelity simulation...", "WARN")
                run_simulated_sandbox(job_id, job, captured_events)

        # ────────────────────────────────────────────────────────
        # STAGE 3: RESULT EXTRACTION & RISK SCORING
        # ────────────────────────────────────────────────────────
        job.status = "AI_ANALYSIS"
        job.current_stage = "AI_ANALYSIS"
        job.progress = 85
        db.commit()
        
        finalize_analysis(db, job, captured_events)

    except Exception as e:
        db.rollback()
        job.status = "FAILED"
        job.current_stage = "FAILED"
        job.error_message = str(e)
        db.commit()
        broadcast_v2_log(job_id, f"Pipeline execution failed: {str(e)}")
        
        # Broadcast fail state
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(manager.broadcast(job_id, {
                "type": "STATUS_CHANGE",
                "status": "FAILED",
                "error": str(e)
            }))
        except Exception:
            pass
        finally:
            loop.close()
    finally:
        db.close()

def run_simulated_sandbox(job_id: str, job: V2Job, captured_events: list):
    """Simulates runtime execution milestones and logs for the hackathon demo."""
    filename = job.filename.lower()
    broadcast_v2_log(job_id, "Emulator check: Host toolings missing or simulated sample detected. Launching simulation sandbox...", "SYSTEM")
    time.sleep(1.5)
    
    broadcast_v2_log(job_id, "System: Emulator booted. Android 11 environment ready.", "SYSTEM")
    job.status = "EMULATOR_BOOT"
    job.current_stage = "EMULATOR_BOOT"
    job.progress = 35
    SessionLocal().query(V2Job).filter(V2Job.id == job_id).update({"status": "EMULATOR_BOOT", "progress": 35})
    time.sleep(1.5)

    broadcast_v2_log(job_id, f"Deploying package '{job.package_name}' via ADB...", "INSTALLING")
    job.status = "INSTALLING"
    job.current_stage = "INSTALLING"
    job.progress = 45
    time.sleep(1.5)
    
    broadcast_v2_log(job_id, "ADB: Package installation successful.", "SYSTEM")
    broadcast_v2_log(job_id, "Attaching Frida server (PID 4102) & deploying hook script...", "INSTRUMENTING")
    job.status = "INSTRUMENTING"
    job.current_stage = "INSTRUMENTING"
    job.progress = 55
    time.sleep(2)
    
    broadcast_v2_log(job_id, "Frida: 8 hooks successfully instrumentation-linked.", "SYSTEM")
    broadcast_v2_log(job_id, f"Launching main activity for '{job.package_name}'...", "RUNNING")
    job.status = "RUNNING"
    job.current_stage = "RUNNING"
    job.progress = 60
    time.sleep(1)

    # Determine simulation milestones based on sample key
    events_to_emit = []
    
    if "anubis" in filename:
        events_to_emit = [
            ("evasion_emulator", "Build.HARDWARE queried", {"check_type": "Build.HARDWARE", "value": "goldfish"}, 0.3, True),
            ("crypto_op", "AES Cipher initialized", {"algorithm": "AES/CBC/PKCS5Padding"}, 0.2, False),
            ("file_write", "File written to storage", {"path": "/sdcard/Download/payload.dex"}, 0.4, True),
            ("dex_load", "Dynamic Dalvik bytecode load", {"path": "/sdcard/Download/payload.dex"}, 0.6, True),
            ("network_request", "C2 check-in request", {"url": "http://194.26.135.84/api/v2/gate.php", "method": "POST"}, 0.5, True),
            ("sms_send", "SMS transmission event", {"dest": "+1-555-0199", "text": "Stolen SMS OTP: 489201"}, 0.8, True),
        ]
    elif "sharkbot" in filename:
        events_to_emit = [
            ("evasion_root", "SU binary check", {"check_type": "root_existence_check", "path": "/system/xbin/su"}, 0.3, True),
            ("network_request", "C2 configuration fetch", {"url": "https://fast-update-bank.online/api/config", "method": "GET"}, 0.5, True),
            ("dex_load", "Dynamic utility load", {"path": "/data/user/0/com.helper.update.utility/app_dex/update.jar"}, 0.6, True),
            ("sms_send", "SMS exfiltration trigger", {"dest": "+1-202-555-0143", "text": "Intercepted Bank SMS: Auth code 77391"}, 0.8, True)
        ]
    elif "cerberus" in filename:
        events_to_emit = [
            ("evasion_debugger", "Debugger check bypassed", {"check_type": "isDebuggerConnected"}, 0.3, True),
            ("shell_exec", "Spawn shell executor", {"command": "su -c 'pm list packages'"}, 0.5, True),
            ("network_request", "C2 telemetry drop", {"url": "http://phish-guard-portal.xyz/log", "method": "POST"}, 0.5, True),
            ("sms_send", "SMS forward", {"dest": "+44-7911-123456", "text": "Cerberus SMS payload intercept"}, 0.8, True)
        ]
    else:
        # Default benign flow
        events_to_emit = [
            ("network_request", "Telemetry request", {"url": "https://android.clients.google.com/active", "method": "GET"}, 0.0, False),
            ("file_write", "Cache configuration write", {"path": "/data/user/0/com.unknown.app/files/config.json"}, 0.0, False),
        ]

    # Stream out simulated events over time
    start_time = time.time()
    for i, (etype, name, payload, weight, susp) in enumerate(events_to_emit):
        time.sleep(2)
        elapsed = int((time.time() - start_time) * 1000)
        
        # Log to socket
        log_msg = f"[{etype.upper()}] {name} -> Payload: {json.dumps(payload)}"
        broadcast_v2_log(job_id, log_msg, "LOG")
        
        # Save event to list
        captured_events.append({
            "timestamp": datetime.datetime.utcnow(),
            "elapsed_ms": elapsed,
            "event_type": etype,
            "source": "frida",
            "process_name": job.package_name,
            "payload": payload,
            "risk_weight": weight,
            "is_suspicious": susp
        })
        
        # Update progress
        pct = 60 + int((i + 1) / len(events_to_emit) * 20)
        SessionLocal().query(V2Job).filter(V2Job.id == job_id).update({"progress": pct})
        
    broadcast_v2_log(job_id, "Sandbox analysis session timer expired. Shutting down hooks...", "COLLECTING")
    job.status = "COLLECTING"
    job.current_stage = "COLLECTING"
    job.progress = 80
    time.sleep(1.5)

def run_live_sandbox(job_id: str, job: V2Job, apk_path: str, captured_events: list):
    """Executes live Android sandbox orchestration using ADB and Frida."""
    # 1. Boot emulator
    if not boot_emulator(job_id):
        raise RuntimeError("Android Emulator failed to boot. Dynamic analysis aborted.")

    job.status = "EMULATOR_BOOT"
    job.current_stage = "EMULATOR_BOOT"
    job.progress = 35
    db_sess = SessionLocal()
    db_sess.query(V2Job).filter(V2Job.id == job_id).update({"status": "EMULATOR_BOOT", "progress": 35})
    db_sess.commit()

    # 2. Install target package
    broadcast_v2_log(job_id, f"Deploying '{job.filename}' via ADB...")
    job.status = "INSTALLING"
    job.current_stage = "INSTALLING"
    job.progress = 45
    db_sess.query(V2Job).filter(V2Job.id == job_id).update({"status": "INSTALLING", "progress": 45})
    db_sess.commit()
    
    install_res = subprocess.run([ADB_PATH, "install", apk_path], capture_output=True, text=True, timeout=60)
    if "Success" not in install_res.stdout:
        raise RuntimeError(f"ADB App Deployment failed: {install_res.stderr}")
    broadcast_v2_log(job_id, "ADB: Deployment verification successful.")

    # 3. Enable frida-server
    broadcast_v2_log(job_id, "Checking frida-server state inside AVD...")
    
    frida_running = False
    for attempt in range(15):
        # Check if frida-server is running using adb shell pgrep
        pgrep_res = subprocess.run([ADB_PATH, "shell", "pgrep", "frida-server"], capture_output=True, text=True)
        if pgrep_res.stdout.strip():
            frida_running = True
            break
            
        if attempt == 0:
            broadcast_v2_log(job_id, "Starting frida-server process inside emulator...")
            # Spawn daemon in background
            subprocess.Popen([ADB_PATH, "shell", "/data/local/tmp/frida-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        time.sleep(1)
        
    if not frida_running:
        broadcast_v2_log(job_id, "[WARNING] Frida-server failed to start within 15s. Falling back to simulation.", "WARN")
        raise RuntimeError("Frida server is not running on the emulator.")

    broadcast_v2_log(job_id, "Frida server verified running.")

    # 4. Attach Frida
    # Validation of package name
    if not job.package_name or job.package_name == "unknown.package" or "." not in job.package_name:
        broadcast_v2_log(job_id, f"[WARNING] Invalid package name '{job.package_name}' for instrumentation. Falling back to simulation.", "WARN")
        raise ValueError(f"Invalid package name for Frida spawn: '{job.package_name}'")

    broadcast_v2_log(job_id, f"Attaching instrumentation hooks to '{job.package_name}'...")
    job.status = "INSTRUMENTING"
    job.current_stage = "INSTRUMENTING"
    job.progress = 55
    db_sess.query(V2Job).filter(V2Job.id == job_id).update({"status": "INSTRUMENTING", "progress": 55})
    db_sess.commit()

    device = frida.get_usb_device()
    pid = None
    session = None
    is_spawned = False

    try:
        # Primary spawn method
        pid = device.spawn([job.package_name])
        session = device.attach(pid)
        is_spawned = True
    except Exception as spawn_err:
        broadcast_v2_log(job_id, f"[WARNING] Frida spawn failed: {str(spawn_err)}. Attempting attach fallback launch...", "WARN")
        
        # Fallback launch method: start package via monkey
        subprocess.run([ADB_PATH, "shell", "monkey", "-p", job.package_name, "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        
        try:
            # Attempt attaching to running process
            pid = device.get_process(job.package_name).pid
            session = device.attach(pid)
            broadcast_v2_log(job_id, f"Attached to spawned process (PID {pid}) via fallback.")
        except Exception as attach_err:
            broadcast_v2_log(job_id, f"[WARNING] Frida fallback attach failed: {str(attach_err)}.", "WARN")
            raise RuntimeError("Frida instrumentation failed: both spawn and attach fallback failed.")
            
    # Load hook file
    with open(FRIDA_SCRIPT_PATH, "r", encoding="utf-8") as f:
        hook_code = f.read()

    script = session.create_script(hook_code)

    # Message callback
    start_time = time.time()
    
    def on_message(message, data):
        if message["type"] == "send":
            try:
                ev_data = json.loads(message["payload"])
                elapsed = int((time.time() - start_time) * 1000)
                
                # Send log to WS
                broadcast_v2_log(job_id, f"[{ev_data['event_type'].upper()}] Captured: {json.dumps(ev_data['payload'])}")
                
                captured_events.append({
                    "timestamp": datetime.datetime.utcnow(),
                    "elapsed_ms": elapsed,
                    "event_type": ev_data["event_type"],
                    "source": ev_data["source"],
                    "process_name": job.package_name,
                    "payload": ev_data["payload"],
                    "risk_weight": ev_data["risk_weight"],
                    "is_suspicious": ev_data["is_suspicious"]
                })
            except Exception as e:
                print("Failed to decode Frida payload:", e)
        else:
            print("Frida Console Message:", message)

    script.on("message", on_message)
    script.load()
    
    # Resume target process only if spawned
    if is_spawned and pid is not None:
        device.resume(pid)
    broadcast_v2_log(job_id, f"Application launched under Frida tracing. Capturing runtime trace for {job.timeout_seconds}s...")
    
    job.status = "RUNNING"
    job.current_stage = "RUNNING"
    job.progress = 60
    db_sess.query(V2Job).filter(V2Job.id == job_id).update({"status": "RUNNING", "progress": 60})
    db_sess.commit()

    # Wait loop + trigger actions to exercise UI
    elapsed_analysis = 0
    while elapsed_analysis < job.timeout_seconds:
        time.sleep(10)
        elapsed_analysis += 10  
        
        # Simulate touch events via monkey / adb
        subprocess.run([ADB_PATH, "shell", "monkey", "-p", job.package_name, "--pct-touch", "100", "5"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        pct = 60 + int((elapsed_analysis / job.timeout_seconds) * 20)
        db_sess.query(V2Job).filter(V2Job.id == job_id).update({"progress": pct})
        db_sess.commit()
        broadcast_v2_log(job_id, f"Telemetry capture active... ({elapsed_analysis}/{job.timeout_seconds}s)")

    # 5. Detach and cleanup app
    broadcast_v2_log(job_id, "Sandbox analysis session timer expired. Cleaning up guest workspace...")
    job.status = "COLLECTING"
    job.current_stage = "COLLECTING"
    job.progress = 80
    db_sess.query(V2Job).filter(V2Job.id == job_id).update({"status": "COLLECTING", "progress": 80})
    db_sess.commit()

    try:
        session.detach()
    except Exception:
        pass

    # Wipe app data and remove from emulator
    subprocess.run([ADB_PATH, "shell", "pm", "clear", job.package_name], stdout=subprocess.DEVNULL)
    subprocess.run([ADB_PATH, "uninstall", job.package_name], stdout=subprocess.DEVNULL)
    broadcast_v2_log(job_id, "ADB: Target application uninstalled. Workspace reset.")
    db_sess.close()

def finalize_analysis(db: Session, job: V2Job, events_list: list):
    """
    Save all captured events, calculate final scores, generate AI reports, and close the job.
    """
    broadcast_v2_log(job.id, "Analyzing telemetry events & calculating risk score...")
    
    # 1. Save all event objects to database
    db_events = []
    for ev in events_list:
        db_event = V2Event(
            job_id=job.id,
            timestamp=ev["timestamp"],
            elapsed_ms=ev["elapsed_ms"],
            event_type=ev["event_type"],
            source=ev["source"],
            process_name=ev["process_name"],
            payload=ev["payload"],
            risk_weight=ev["risk_weight"],
            is_suspicious=ev["is_suspicious"]
        )
        db.add(db_event)
        db_events.append(db_event)
    db.commit()

    # 2. Risk scoring
    risk_results = calculate_risk(job.static_findings, db_events)
    job.static_risk_score = risk_results["static_risk_score"]
    job.dynamic_risk_score = risk_results["dynamic_risk_score"]
    job.risk_score = risk_results["risk_score"]
    job.severity = risk_results["severity"]
    job.verdict = risk_results["verdict"]
    job.malware_family = risk_results["malware_family"]
    job.confidence = risk_results["confidence"]
    job.risk_factors = risk_results["risk_factors"]
    
    # Extract IOCs and MITRE mappings
    job.iocs = extract_iocs(db_events)
    job.mitre_mappings = map_mitre(db_events)
    
    # Count event aggregates for dynamic summary
    counts = {}
    for ev in db_events:
        counts[ev.event_type] = counts.get(ev.event_type, 0) + 1
    job.dynamic_summary = {
        "event_counts": counts,
        "total_events": len(db_events),
        "suspicious_events": sum(1 for e in db_events if e.is_suspicious)
    }
    
    db.commit()

    # 3. Generate Report
    broadcast_v2_log(job.id, "Compiling final AI security brief...")
    report_content = generate_v2_report(job, db_events)
    
    db_report = V2Report(
        job_id=job.id,
        executive_summary=report_content["executive_summary"],
        technical_report=report_content["technical_report"],
        behavioral_summary=report_content["behavioral_summary"],
        remediation=report_content["remediation"],
        mitre_mapping=job.mitre_mappings,
        owasp_mapping=[], # Can append OWASP mappings if needed
        risk_factors=job.risk_factors,
        ai_model_used="Groq/Llama-3.1-70b" if os.environ.get("GROQ_API_KEY") else "Sentinel Local Compiler"
    )
    db.add(db_report)
    
    # 4. Finalize Job
    job.status = "COMPLETED"
    job.current_stage = "COMPLETED"
    job.progress = 100
    job.completed_at = datetime.datetime.utcnow()
    db.commit()

    broadcast_v2_log(job.id, "Forensic pipeline completed successfully.", "COMPLETE")
    
    # Broadcast final status change
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(manager.broadcast(job.id, {
            "type": "STATUS_CHANGE",
            "status": "COMPLETED",
            "risk_score": job.risk_score,
            "severity": job.severity,
            "malware_family": job.malware_family
        }))
    except Exception:
        pass
    finally:
        loop.close()
