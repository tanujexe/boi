// hook_all.js - Upgraded SentinelAI V2 Dynamic Instrumentation Script
// Intercepts sensitive Android APIs, performs evasion mock bypasses, and emits logs.

Java.perform(function () {
    console.log("[Sentinel_Frida] Upgraded core instrumentation attached.");

    function safeSend(hookName, eventType, data, riskWeight, isSuspicious) {
        try {
            send(JSON.stringify({
                hook: hookName,
                event_type: eventType,
                timestamp: new Date().getTime(),
                source: "frida",
                payload: data,
                risk_weight: riskWeight,
                is_suspicious: isSuspicious
            }));
        } catch (e) {
            console.error("[Sentinel_Frida] Failed to send JSON payload: " + e.message);
        }
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 1: SMS & TELEPHONY PIPELINES
    // ────────────────────────────────────────────────────────
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        
        // sendTextMessage overload
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String", 
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (dest, sc, text, sentIntent, deliveryIntent) {
            safeSend("SmsManager.sendTextMessage", "sms_send", { dest: dest, text: text }, 0.8, true);
            this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent);
        };
        
        // sendMultipartTextMessage overload
        SmsManager.sendMultipartTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.util.ArrayList", 
            "java.util.ArrayList", "java.util.ArrayList"
        ).implementation = function (dest, sc, parts, sentIntents, deliveryIntents) {
            var text = "";
            if (parts != null) {
                for (var i = 0; i < parts.size(); i++) {
                    text += parts.get(i);
                }
            }
            safeSend("SmsManager.sendMultipartTextMessage", "sms_send", { dest: dest, text: text }, 0.8, true);
            this.sendMultipartTextMessage(dest, sc, parts, sentIntents, deliveryIntents);
        };

        // sendDataMessage overload
        SmsManager.sendDataMessage.overload(
            "java.lang.String", "java.lang.String", "short", "[B", 
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (dest, sc, port, data, sentIntent, deliveryIntent) {
            var hexText = "";
            if (data != null) {
                for (var i = 0; i < data.length; i++) {
                    var hex = (data[i] & 0xff).toString(16);
                    hexText += (hex.length === 1 ? '0' : '') + hex;
                }
            }
            safeSend("SmsManager.sendDataMessage", "sms_send", { dest: dest, port: port, raw_hex: hexText }, 0.8, true);
            this.sendDataMessage(dest, sc, port, data, sentIntent, deliveryIntent);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] SmsManager hooks error: " + e.message);
    }

    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.overload().implementation = function () {
            safeSend("TelephonyManager.getDeviceId", "device_info", { property: "deviceId" }, 0.3, true);
            return "867530900000000"; // Return simulated device ID
        };
        TelephonyManager.getSubscriberId.overload().implementation = function () {
            safeSend("TelephonyManager.getSubscriberId", "device_info", { property: "subscriberId" }, 0.3, true);
            return "310260000000000"; // Return simulated IMSI
        };
        TelephonyManager.getLine1Number.overload().implementation = function () {
            safeSend("TelephonyManager.getLine1Number", "device_info", { property: "phoneNumber" }, 0.4, true);
            return "+15555215554"; // Mock phone number
        };
        TelephonyManager.getSimOperator.overload().implementation = function () {
            safeSend("TelephonyManager.getSimOperator", "telephony_query", { property: "simOperator" }, 0.1, false);
            return "310260";
        };
        TelephonyManager.getSimOperatorName.overload().implementation = function () {
            safeSend("TelephonyManager.getSimOperatorName", "telephony_query", { property: "simOperatorName" }, 0.1, false);
            return "Sentinel Mobile Network";
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] TelephonyManager hooks error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 2: CLIPBOARD & CONTACTS HARVESTING
    // ────────────────────────────────────────────────────────
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.getPrimaryClip.implementation = function () {
            safeSend("ClipboardManager.getPrimaryClip", "clipboard_access", { action: "read" }, 0.3, true);
            return this.getPrimaryClip();
        };
        ClipboardManager.setPrimaryClip.implementation = function (clipData) {
            var text = "";
            try {
                text = clipData.getItemAt(0).coerceToText(Java.use("android.content.Context")).toString();
            } catch (ex) {}
            safeSend("ClipboardManager.setPrimaryClip", "clipboard_access", { action: "write", content: text }, 0.3, true);
            this.setPrimaryClip(clipData);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] ClipboardManager hooks error: " + e.message);
    }

    try {
        var ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri", "[Ljava.lang.String;", "java.lang.String", 
            "[Ljava.lang.String;", "java.lang.String"
        ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            var uriStr = uri.toString();
            if (uriStr.indexOf("contacts") !== -1 || uriStr.indexOf("sms") !== -1) {
                safeSend("ContentResolver.query", "contacts_read", { uri: uriStr }, 0.5, true);
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] ContentResolver query hooks error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 3: WINDOW OVERLAYS & ACCESSIBILITY HIJACKING
    // ────────────────────────────────────────────────────────
    try {
        var WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
        WindowManagerImpl.addView.implementation = function (view, params) {
            var layoutParamsClass = Java.use("android.view.WindowManager$LayoutParams");
            var lp = Java.cast(params, layoutParamsClass);
            var type = lp.type.value;
            // Overlay Window layouts check
            var isOverlay = (type === 2038 || type === 2003 || type === 2006);
            if (isOverlay) {
                safeSend("WindowManager.addView", "overlay_created", { type: type, flags: lp.flags.value }, 0.7, true);
            }
            this.addView(view, params);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] WindowManager addView hook error: " + e.message);
    }

    try {
        var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        AccessibilityNodeInfo.performAction.overload("int").implementation = function (action) {
            safeSend("AccessibilityNodeInfo.performAction", "accessibility_action", { action: action }, 0.5, true);
            return this.performAction(action);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] AccessibilityNodeInfo hook error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 4: PROCESS SPAWNING & DYNAMIC bytecode loaders
    // ────────────────────────────────────────────────────────
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

        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function (dexPath, parent) {
            safeSend("PathClassLoader.init", "dex_load", { path: dexPath }, 0.6, true);
            return this.$init(dexPath, parent);
        };

        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function (buffer, parent) {
            safeSend("InMemoryDexClassLoader.init", "dex_load", { path: "InMemory (ByteBuffer)" }, 0.6, true);
            return this.$init(buffer, parent);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Dynamic loading hooks error: " + e.message);
    }

    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (command) {
            safeSend("Runtime.exec", "shell_exec", { command: command }, 0.5, true);
            return this.exec(command);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
            var cmdStr = "";
            for (var i = 0; i < cmdArray.length; i++) {
                cmdStr += cmdArray[i] + " ";
            }
            safeSend("Runtime.exec", "shell_exec", { command: cmdStr.trim() }, 0.5, true);
            return this.exec(cmdArray);
        };

        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            var commandList = this.command();
            var cmdStr = "";
            for (var i = 0; i < commandList.size(); i++) {
                cmdStr += commandList.get(i) + " ";
            }
            safeSend("ProcessBuilder.start", "shell_exec", { command: cmdStr.trim() }, 0.5, true);
            return this.start();
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Shell executions hooks error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 5: REFLECTION, CRYPTO KEYS & FILE CHANNELS
    // ────────────────────────────────────────────────────────
    try {
        var reflectMethod = Java.use("java.lang.reflect.Method");
        var lastReflectTime = 0;
        reflectMethod.invoke.implementation = function (obj, args) {
            var now = new Date().getTime();
            if (now - lastReflectTime > 2000) {  // Throttling reflection notifications
                lastReflectTime = now;
                var methodName = this.getName();
                var declClass = this.getDeclaringClass().getName();
                
                // Exclude system classes spam
                if (declClass.indexOf("android.") === -1 && declClass.indexOf("java.") === -1) {
                    safeSend("Method.invoke", "reflection_usage", { class: declClass, method: methodName }, 0.1, false);
                }
            }
            return this.invoke(obj, args);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Reflection hooks error: " + e.message);
    }

    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.io.File").implementation = function (file) {
            var path = file.getAbsolutePath();
            // Flag file reads pointing to sensitive databases, configs, or keys
            if (path.indexOf("/etc/") !== -1 || path.indexOf("shared_prefs") !== -1 || path.indexOf("database") !== -1) {
                safeSend("FileInputStream.init", "file_read", { path: path }, 0.2, true);
            }
            return this.$init(file);
        };

        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function (file, append) {
            var filePath = file.getAbsolutePath();
            var isSuspicious = filePath.indexOf(".apk") !== -1 || filePath.indexOf(".dex") !== -1 || filePath.indexOf(".jar") !== -1;
            safeSend("FileOutputStream.init", "file_write", { path: filePath, append: append }, isSuspicious ? 0.4 : 0.0, isSuspicious);
            return this.$init(file, append);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] File stream hooks error: " + e.message);
    }

    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function (algo) {
            safeSend("Cipher.getInstance", "crypto_op", { algorithm: algo }, 0.2, false);
            return this.getInstance(algo);
        };
        
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            var keyHex = "";
            if (key != null) {
                for (var i = 0; i < key.length; i++) {
                    var hex = (key[i] & 0xff).toString(16);
                    keyHex += (hex.length === 1 ? '0' : '') + hex;
                }
            }
            safeSend("SecretKeySpec.init", "crypto_key", { algorithm: algo, key_bytes: keyHex }, 0.4, true);
            return this.$init(key, algo);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Cipher hooks error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 6: NETWORK DNS RESOLUTIONS & SOCKET TARGETS
    // ────────────────────────────────────────────────────────
    try {
        var InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getAllByName.implementation = function (host) {
            safeSend("InetAddress.getAllByName", "dns_query", { domain: host }, 0.2, true);
            return this.getAllByName(host);
        };
        InetAddress.getByName.implementation = function (host) {
            safeSend("InetAddress.getByName", "dns_query", { domain: host }, 0.2, true);
            return this.getByName(host);
        };
        
        var Socket = Java.use("java.net.Socket");
        Socket.connect.overload("java.net.SocketAddress", "int").implementation = function (endpoint, timeout) {
            var epStr = endpoint.toString();
            var parts = epStr.split("/");
            var hostPart = parts[0] || "";
            var ipAndPort = parts[1] || parts[0];
            var hostIp = ipAndPort.split(":")[0];
            var port = ipAndPort.split(":")[1] || "0";
            
            safeSend("Socket.connect", "network_request", { url: hostPart || hostIp, method: "TCP_CONNECT", ip: hostIp, port: parseInt(port) }, 0.3, true);
            this.connect(endpoint, timeout);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Socket hooks error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 7: BYPASSES & EVASIONS (ROOT, SSL PINNING, EMULATORS)
    // ────────────────────────────────────────────────────────
    
    // SSL Pinning Bypass (Conscrypt TrustManager)
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.checkTrustedRecursive.implementation = function (certs, host, clientAuth, keyStore, alpnProtocols, tolerance) {
            console.log("[Sentinel_Frida] SSL Pinning Bypass: TrustManagerImpl.checkTrustedRecursive for " + host);
            return certs;
        };
    } catch (e) {
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            X509TrustManager.checkServerTrusted.implementation = function (chain, authType) {
                console.log("[Sentinel_Frida] SSL Pinning Bypass: X509TrustManager.checkServerTrusted bypassed.");
            };
        } catch (ex) {}
    }

    // Root detection bypass
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("Superuser") !== -1 || path.indexOf("BusyBox") !== -1 || path.indexOf("magisk") !== -1) {
                safeSend("File.exists", "evasion_root", { check_type: "su_existence_check", path: path }, 0.3, true);
                console.log("[Sentinel_Frida] Root bypass: File.exists check on " + path + " mock-returning false.");
                return false;
            }
            return this.exists();
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Root evasion bypass hooks error: " + e.message);
    }

    // Debugger check bypass
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            safeSend("Debug.isDebuggerConnected", "evasion_debugger", { check_type: "isDebuggerConnected" }, 0.3, true);
            console.log("[Sentinel_Frida] Debugger bypass: isDebuggerConnected queried. Mock-returning false.");
            return false;
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Debugger evasion hooks error: " + e.message);
    }

    // Emulator detection bypass
    try {
        var BuildClass = Java.use("android.os.Build");
        var fields = ["FINGERPRINT", "HARDWARE", "BOARD", "DEVICE", "PRODUCT", "MODEL", "MANUFACTURER", "BRAND"];
        var mockValues = {
            "FINGERPRINT": "google/nexus/nexus:10/QQ3A.200805.001/6584839:user/release-keys",
            "HARDWARE": "nexus",
            "BOARD": "nexus",
            "DEVICE": "nexus",
            "PRODUCT": "nexus",
            "MODEL": "Nexus 5X",
            "MANUFACTURER": "Google",
            "BRAND": "google"
        };
        
        for (var i = 0; i < fields.length; i++) {
            try {
                var fieldName = fields[i];
                var field = BuildClass.class.getDeclaredField(fieldName);
                field.setAccessible(true);
                
                safeSend("Build." + fieldName, "evasion_emulator", { check_type: "Build." + fieldName, value: field.get(null) }, 0.2, true);
                field.set(null, mockValues[fieldName]);
            } catch (field_err) {}
        }
        console.log("[Sentinel_Frida] Emulator device Build fields mocked.");
    } catch (e) {
        console.warn("[Sentinel_Frida] Emulator evasion bypass hooks error: " + e.message);
    }

    // Native System Property Hooking (libc.so) to bypass native emulator checks
    try {
        var system_property_get = Module.findExportByName("libc.so", "__system_property_get");
        if (system_property_get) {
            Interceptor.attach(system_property_get, {
                onEnter: function (args) {
                    this.name = args[0].readCString();
                    this.value_ptr = args[1];
                },
                onLeave: function (retval) {
                    var name = this.name;
                    if (name) {
                        var mockValues = {
                            "ro.hardware": "nexus",
                            "ro.product.board": "nexus",
                            "ro.product.device": "nexus",
                            "ro.product.name": "nexus",
                            "ro.product.model": "Nexus 5X",
                            "ro.product.manufacturer": "Google",
                            "ro.product.brand": "google",
                            "ro.build.fingerprint": "google/nexus/nexus:10/QQ3A.200805.001/6584839:user/release-keys",
                            "ro.kernel.qemu": "0",
                            "init.svc.goldfish-logcat": "",
                            "ro.boot.hardware": "nexus"
                        };
                        if (mockValues.hasOwnProperty(name)) {
                            var mockVal = mockValues[name];
                            this.value_ptr.writeUtf8String(mockVal);
                            retval.replace(mockVal.length);
                            console.log("[Sentinel_Frida] Native Libc property bypass: " + name + " -> " + mockVal);
                        }
                    }
                }
            });
            console.log("[Sentinel_Frida] Native system property hooks attached.");
        }
    } catch (e) {
        console.warn("[Sentinel_Frida] Native system property hooks error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 8: NATIVE LIBRARY & WEBVIEW HOOKS
    // ────────────────────────────────────────────────────────

    // System.loadLibrary - detects native library loading (packed malware, JNI payloads)
    try {
        var SystemClass = Java.use("java.lang.System");
        SystemClass.loadLibrary.overload("java.lang.String").implementation = function (libName) {
            safeSend("System.loadLibrary", "native_lib_load", { library: libName }, 0.4, true);
            console.log("[Sentinel_Frida] Native library loaded: " + libName);
            this.loadLibrary(libName);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] System.loadLibrary hook error: " + e.message);
    }

    // System.load - loads native library from absolute path
    try {
        var SystemClass2 = Java.use("java.lang.System");
        SystemClass2.load.overload("java.lang.String").implementation = function (libPath) {
            safeSend("System.load", "native_lib_load", { path: libPath }, 0.5, true);
            console.log("[Sentinel_Frida] Native library loaded from path: " + libPath);
            this.load(libPath);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] System.load hook error: " + e.message);
    }

    // WebView.loadUrl - catches phishing page injections
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            safeSend("WebView.loadUrl", "webview_load", { url: url }, 0.5, true);
            console.log("[Sentinel_Frida] WebView loading URL: " + url);
            this.loadUrl(url);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] WebView.loadUrl hook error: " + e.message);
    }

    // WebViewClient.shouldOverrideUrlLoading - catches URL redirects in WebViews
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.shouldOverrideUrlLoading.overload("android.webkit.WebView", "java.lang.String").implementation = function (view, url) {
            safeSend("WebViewClient.shouldOverrideUrlLoading", "webview_load", { url: url }, 0.4, true);
            console.log("[Sentinel_Frida] WebView URL redirect intercepted: " + url);
            return this.shouldOverrideUrlLoading(view, url);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] WebViewClient.shouldOverrideUrlLoading hook error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 9: OkHttp SSL PINNING BYPASS
    // ────────────────────────────────────────────────────────

    // OkHttp CertificatePinner.check bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
            safeSend("CertificatePinner.check", "ssl_bypass", { hostname: hostname }, 0.6, true);
            console.log("[Sentinel_Frida] OkHttp SSL Pinning Bypass: CertificatePinner.check for " + hostname);
            // Return without throwing to bypass pin verification
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] OkHttp CertificatePinner.check hook error: " + e.message);
    }

    // OkHttp CertificatePinner.check$okhttp bypass (Kotlin variant)
    try {
        var CertificatePinnerKt = Java.use("okhttp3.CertificatePinner");
        CertificatePinnerKt["check$okhttp"].overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function (hostname, peerCertificatesFn) {
            safeSend("CertificatePinner.check$okhttp", "ssl_bypass", { hostname: hostname }, 0.6, true);
            console.log("[Sentinel_Frida] OkHttp SSL Pinning Bypass (Kotlin): check$okhttp for " + hostname);
            // Return without throwing to bypass pin verification
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] OkHttp CertificatePinner.check$okhttp hook error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 10: ANTI-FRIDA & PROC MAPS EVASION
    // ────────────────────────────────────────────────────────
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        BufferedReader.readLine.overload().implementation = function () {
            var line = this.readLine();
            if (line !== null) {
                var lineStr = line.toString();
                if (lineStr.indexOf("frida-agent") !== -1 ||
                    lineStr.indexOf("frida-gadget") !== -1 ||
                    lineStr.indexOf("linjector") !== -1) {
                    safeSend("BufferedReader.readLine", "anti_frida_evasion", { original_line: lineStr }, 0.9, true);
                    console.log("[Sentinel_Frida] Anti-Frida evasion: stripped Frida reference from readLine output.");
                    return "";
                }
            }
            return line;
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Anti-Frida proc maps evasion hook error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 11: INTENT & SERVICE TRACING
    // ────────────────────────────────────────────────────────

    // ContextWrapper.startService - intercepts background service launches
    try {
        var ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.startService.overload("android.content.Intent").implementation = function (intent) {
            var componentName = "";
            try {
                var comp = intent.getComponent();
                if (comp !== null) {
                    componentName = comp.getClassName();
                }
            } catch (ex) {}
            safeSend("ContextWrapper.startService", "service_start", { component: componentName, action: intent.getAction() || "" }, 0.4, true);
            console.log("[Sentinel_Frida] Service started: " + componentName);
            return this.startService(intent);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] ContextWrapper.startService hook error: " + e.message);
    }

    // ContextWrapper.sendBroadcast - intercepts broadcast sends
    try {
        var ContextWrapper2 = Java.use("android.content.ContextWrapper");
        ContextWrapper2.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
            var action = "";
            try {
                action = intent.getAction() || "";
            } catch (ex) {}
            safeSend("ContextWrapper.sendBroadcast", "broadcast_send", { action: action }, 0.3, true);
            console.log("[Sentinel_Frida] Broadcast sent with action: " + action);
            this.sendBroadcast(intent);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] ContextWrapper.sendBroadcast hook error: " + e.message);
    }

    // ────────────────────────────────────────────────────────
    // CATEGORY 12: SLEEP/TIME ACCELERATION
    // ────────────────────────────────────────────────────────

    // Thread.sleep - accelerate long sleeps to bypass delayed execution time bombs
    try {
        var ThreadClass = Java.use("java.lang.Thread");
        ThreadClass.sleep.overload("long").implementation = function (millis) {
            if (millis > 5000) {
                safeSend("Thread.sleep", "sleep_accelerated", { original_ms: millis, reduced_ms: 100 }, 0.5, true);
                console.log("[Sentinel_Frida] Sleep acceleration: Thread.sleep(" + millis + "ms) reduced to 100ms.");
                return this.sleep(100);
            }
            return this.sleep(millis);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] Thread.sleep hook error: " + e.message);
    }

    // SystemClock.sleep - accelerate long sleeps on SystemClock
    try {
        var SystemClock = Java.use("android.os.SystemClock");
        SystemClock.sleep.overload("long").implementation = function (millis) {
            if (millis > 5000) {
                safeSend("SystemClock.sleep", "sleep_accelerated", { original_ms: millis, reduced_ms: 100 }, 0.5, true);
                console.log("[Sentinel_Frida] Sleep acceleration: SystemClock.sleep(" + millis + "ms) reduced to 100ms.");
                return this.sleep(100);
            }
            return this.sleep(millis);
        };
    } catch (e) {
        console.warn("[Sentinel_Frida] SystemClock.sleep hook error: " + e.message);
    }
});
