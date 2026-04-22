import random
import time
from datetime import datetime

# Real-world user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Outlook-iOS/2.0", 
    "Python-urllib/3.9", # Suspicious for web, normal for scripts
    "Kali-Linux/2024.1"  # Red Flag
]

# 1. WEB & NETWORK ATTACKS (The classics)
WEB_ATTACKS = [
    {"sig": "SQL Injection Attempt", "payload": "' OR 1=1 --", "risk": "CRITICAL", "source": "Firewall"},
    {"sig": "Path Traversal", "payload": "GET /../../etc/passwd", "risk": "CRITICAL", "source": "WAF"},
    {"sig": "XSS Probe", "payload": "<script>alert(document.cookie)</script>", "risk": "WARNING", "source": "WAF"},
]

# 2. IDENTITY & MFA ATTACKS (What you see in EntraID/Okta/0365)
IDENTITY_ATTACKS = [
    {"sig": "Brute Force: Multiple Failed Logins", "payload": "User: admin | Fail Count: 15", "risk": "CRITICAL", "source": "Identity_Provider"},
    {"sig": "MFA Fatigue Attack", "payload": "MFA Push Denied (Attempt 10/10)", "risk": "CRITICAL", "source": "MFA_Service"},
    {"sig": "Impossible Travel Detected", "payload": "Login: NY (10:00) -> London (10:05)", "risk": "CRITICAL", "source": "Identity_Provider"},
    {"sig": "Suspicious Login: New Device", "payload": "User: jdoe | Device: Unrecognized Android", "risk": "WARNING", "source": "Identity_Provider"},
]

# 3. PHISHING & EMAIL (What you see in Defender for Office)
PHISHING_ATTACKS = [
    {"sig": "Malicious Link Clicked", "payload": "URL: http://update-microsoft-security.com/login", "risk": "CRITICAL", "source": "Email_Gateway"},
    {"sig": "Suspicious Attachment Detected", "payload": "File: invoice_2024.pdf.exe", "risk": "CRITICAL", "source": "Endpoint_Protection"},
    {"sig": "Email Reported as Phishing", "payload": "Subject: 'Urgent Action Required'", "risk": "INFO", "source": "User_Report"},
]

def generate_log():
    timestamp = datetime.now().isoformat()
    
    # 90% Normal Traffic
    if random.random() > 0.10:
        log_type = "NORMAL"
        signature = "Standard Operation"
        actions = ["Login Success", "Page View", "Email Synced", "File Accessed"]
        payload = f"Action: {random.choice(actions)}"
        severity = "INFO"
        
        # CHANGE 1: Use "Corporate" IPs (10.x.x.x) instead of Home IPs (192.168.x.x)
        # This ensures it looks nothing like your home wifi
        ip = f"10.55.{random.randint(1, 20)}.{random.randint(2, 250)}"
        source = "Internal_Audit"
        status_code = 200
        
    else:
        # 10% Malicious
        category = random.choice([WEB_ATTACKS, IDENTITY_ATTACKS, PHISHING_ATTACKS])
        scenario = random.choice(category)
        
        log_type = "THREAT"
        signature = scenario["sig"]
        payload = scenario["payload"]
        severity = scenario["risk"]
        source = scenario["source"]
        
        # Attackers come from "Public" IPs (Random 40.x, 100.x, etc)
        ip = f"{random.randint(40, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        status_code = 403 if severity == "CRITICAL" else 200

    return {
        "timestamp": timestamp,
        "source_ip": ip,
        "user_agent": random.choice(USER_AGENTS),
        "signature": signature,
        "payload": payload,
        "severity": severity,
        "source_module": source, 
        "status_code": status_code
    }