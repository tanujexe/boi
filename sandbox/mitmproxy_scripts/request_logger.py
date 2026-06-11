import json
import os
import time

class RequestLogger:
    def __init__(self):
        self.output_file = os.environ.get("MITMPROXY_LOG_PATH", "mitmproxy_events.jsonl")
        # Ensure log file is clean on start
        if os.path.exists(self.output_file):
            try:
                os.remove(self.output_file)
            except Exception:
                pass

    def request(self, flow):
        # Log HTTP requests
        event = {
            "timestamp": int(time.time() * 1000),
            "event_type": "network_request",
            "source": "mitmproxy",
            "payload": {
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "headers": dict(flow.request.headers),
                "host": flow.request.host,
                "port": flow.request.port,
                "scheme": flow.request.scheme,
            },
            "risk_weight": 0.2,
            "is_suspicious": flow.request.host not in ["127.0.0.1", "localhost", "android.clients.google.com"]
        }
        try:
            with open(self.output_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

addons = [
    RequestLogger()
]
