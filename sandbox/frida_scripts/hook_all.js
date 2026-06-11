// hook_all.js - SentinelAI v2 Frida Hooks (8 Hooks in 1 File)
// Emits JSON string logs via send() callback.

Java.perform(function () {
    console.log("[Sentinel_Frida] Injecting 8 security instrumentation hooks...");

    function safeSend(hookName, eventType, data, riskWeight, isSuspicious) {
        try {
            send(JSON.stringify({
                hook: hookName,
                event_type: eventType,
                timestamp: new Date().getTime(),
                payload: data,
                risk_weight: riskWeight,
                is_suspicious: isSuspicious
            }));
        } catch (e) {
            console.error("[Sentinel_Frida] Failed to send log for " + hookName + ": " + e.message);
        }
    }

    // ═══════════════════════════════════════════════
    // HOOK 1: URL openConnection (Java HTTP Connections)
    // ═══════════════════════════════════════════════
    try {
        var URLClass = Java.use("java.net.URL");
        URLClass.openConnection.overload().implementation = function () {
            var connection = this.openConnection();
            var urlStr = this.toString();
            safeSend("URL.openConnection", "network_request", {
                url: urlStr,
                method: "GET" // Default assumption, connect() might specify POST later
            }, 0.2, urlStr.indexOf("http://127.0.0.1") === -1 && urlStr.indexOf("localhost") === -1);
            return connection;
        };
        console.log("[Sentinel_Frida] Hook 1: java.net.URL.openConnection attached.");
    } catch (e) {
        console.warn("[Sentinel_Frida] Hook 1 binding failed: " + e.message);
    }

    // ═══════════════════════════════════════════════
    // HOOK 2: HTTPS Connection connect
    // ═══════════════════════════════════════════════
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.connect.implementation = function () {
            var urlStr = this.getURL().toString();
            safeSend("HttpsURLConnection.connect", "network_request", {
                url: urlStr,
                method: this.getRequestMethod()
            }, 0.2, true);
            this.connect();
        };
        console.log("[Sentinel_Frida] Hook 2: javax.net.ssl.HttpsURLConnection.connect attached.");
    } catch (e) {
        console.warn("[Sentinel_Frida] Hook 2 binding failed: " + e.message);
    }

    // ═══════════════════════════════════════════════
    // HOOK 3: SMS Transmission (SmsManager)
    // ═══════════════════════════════════════════════
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String", 
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (dest, sc, text, sentIntent, deliveryIntent) {
            safeSend("SmsManager.sendTextMessage", "sms_send", {
                dest: dest,
                text: text
            }, 0.8, true);
            this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent);
        };
        console.log("[Sentinel_Frida] Hook 3: android.telephony.SmsManager.sendTextMessage attached.");
    } catch (e) {
        console.warn("[Sentinel_Frida] Hook 3 binding failed: " + e.message);
    }

    // ═══════════════════════════════════════════════
    // HOOK 4: Dynamic Code Loading (DexClassLoader)
    // ═══════════════════════════════════════════════
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            safeSend("DexClassLoader.init", "dex_load", {
                path: dexPath,
                optDir: optimizedDirectory,
                libs: librarySearchPath
            }, 0.6, true);
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
        console.log("[Sentinel_Frida] Hook 4: dalvik.system.DexClassLoader attached.");
    } catch (e) {
        console.warn("[Sentinel_Frida] Hook 4 binding failed: " + e.message);
    }

    // ═══════════════════════════════════════════════
    // HOOK 5: File System Writes (FileOutputStream)
    // ═══════════════════════════════════════════════
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function (file, append) {
            var filePath = file.getAbsolutePath();
            // Ignore standard system app logs/temp files
            var isSuspicious = filePath.indexOf(".apk") !== -1 || filePath.indexOf(".dex") !== -1 || filePath.indexOf(".jar") !== -1;
            safeSend("FileOutputStream.init", "file_write", {
                path: filePath,
                append: append
            }, isSuspicious ? 0.4 : 0.0, isSuspicious);
            return this.$init(file, append);
        };
        console.log("[Sentinel_Frida] Hook 5: java.io.FileOutputStream attached.");
    } catch (e) {
        console.warn("[Sentinel_Frida] Hook 5 binding failed: " + e.message);
    }

    // ═══════════════════════════════════════════════
    // HOOK 6: Debugger Evasion Bypass (Debug.isDebuggerConnected)
    // ═══════════════════════════════════════════════
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            safeSend("Debug.isDebuggerConnected", "evasion_debugger", {
                check_type: "isDebuggerConnected"
            }, 0.3, true);
            console.log("[Sentinel_Frida] Evasion Bypass: isDebuggerConnected queried. Returning false.");
            return false; // Bypass debugger check
        };
        console.log("[Sentinel_Frida] Hook 6: android.os.Debug.isDebuggerConnected attached (Bypass Active).");
    } catch (e) {
        console.warn("[Sentinel_Frida] Hook 6 binding failed: " + e.message);
    }

    // ═══════════════════════════════════════════════
    // HOOK 7: Shell Command Execution (Runtime.exec)
    // ═══════════════════════════════════════════════
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (command) {
            safeSend("Runtime.exec", "shell_exec", {
                command: command
            }, 0.5, true);
            return this.exec(command);
        };
        
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
            var cmdStr = "";
            for (var i = 0; i < cmdArray.length; i++) {
                cmdStr += cmdArray[i] + " ";
            }
            safeSend("Runtime.exec", "shell_exec", {
                command: cmdStr.trim()
            }, 0.5, true);
            return this.exec(cmdArray);
        };
        console.log("[Sentinel_Frida] Hook 7: java.lang.Runtime.exec attached.");
    } catch (e) {
        console.warn("[Sentinel_Frida] Hook 7 binding failed: " + e.message);
    }

    // ═══════════════════════════════════════════════
    // HOOK 8: Device ID Harvesting (TelephonyManager)
    // ═══════════════════════════════════════════════
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.overload().implementation = function () {
            safeSend("TelephonyManager.getDeviceId", "device_info", {
                property: "deviceId"
            }, 0.3, true);
            return "867530900000000"; // Return simulated device ID
        };
        TelephonyManager.getSubscriberId.overload().implementation = function () {
            safeSend("TelephonyManager.getSubscriberId", "device_info", {
                property: "subscriberId"
            }, 0.3, true);
            return "310260000000000"; // Return simulated IMSI
        };
        console.log("[Sentinel_Frida] Hook 8: android.telephony.TelephonyManager (deviceId/subscriberId) attached.");
    } catch (e) {
        console.warn("[Sentinel_Frida] Hook 8 binding failed: " + e.message);
    }
});
