import re #real expression to check for specific text patterns
import json #converts the python data into json string
import time #track when failure happens
import collections
import logging
from logging.handlers import SysLogHandler

log_file = "/var/log/auth.log"
siem_ip = "127.0.0.1" 
siem_port = 514
threshold = 5 #limit: 5 failed attempts will trigger an alert
window = 120 #timeframe: 5 attempts must happen in 120 seconds

failed_pattern = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\S+)") #looks for the exact phrase "failed password for..."
failure_tracker = collections.defaultdict(list)

def send_to_siem(alert_data):
    logger = logging.getLogger('SIEM_FORWARDER')
    logger.setLevel(logging.INFO)

    handler = SysLogHandler(address=(siem_ip, siem_port)) #opens a network connection to SIEM
    logger.addHandler(handler)
    
    alert_json = json.dumps(alert_data) 
    
    logger.info(alert_json) 
    print(f"[!] Alert Sent: {alert_json}")

    logger.removeHandler(handler)

def monitor_logs():
    print(f"[*] Monitoring {log_file} for brute force patterns...")
    
    try:
        with open(log_file, "r") as f:
            f.seek(0, 2)  # Start at end of file so it processes only new events

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                match = failed_pattern.search(line)
                if match: 
                    ip = match.group("ip")
                    user = match.group("user")
                    now = time.time()

                    failure_tracker[ip].append(now) #if failure records current time

                    failure_tracker[ip] = [t for t in failure_tracker[ip] if now - t < window] #sliding window deletes any records older than 120 seconds

                    if len(failure_tracker[ip]) >= threshold: #brute force attack is happening
                        alert = {
                            "event": "Brute Force Detected",
                            "source_ip": ip,
                            "target_user": user,
                            "attempt_count": len(failure_tracker[ip]),
                            "window_seconds": window,
                            "severity": "high"
                        }
                        send_to_siem(alert)
                        failure_tracker[ip] = [] #resets the counter
    except PermissionError:
        print("[X] Error: Run with 'sudo' to access log files.")

if __name__ == "__main__": 
    monitor_logs()