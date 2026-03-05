"""
CTI Platform - Simulated Threat Feeds Generator
Generates realistic cyber threat intelligence data for demo
"""

import json
import random
import csv
from datetime import datetime, timedelta

random.seed(42)

# ─── Threat Types ───────────────────────────────────────────
THREAT_TYPES = ["Phishing", "Ransomware", "DDoS", "APT", "Malware",
                "Data Breach", "Credential Stuffing", "Supply Chain Attack",
                "Zero-Day Exploit", "Insider Threat"]

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_WEIGHTS = [0.10, 0.25, 0.40, 0.25]

COUNTRIES = ["India", "China", "Russia", "North Korea", "Iran",
             "USA", "Ukraine", "Brazil", "Nigeria", "Romania"]

SECTORS = ["Banking", "Healthcare", "Government", "Education",
           "Telecom", "Energy", "IT/Software", "Defence", "Retail", "Finance"]

THREAT_ACTORS = ["APT28", "Lazarus Group", "APT41", "Sandworm", "Cobalt Group",
                 "FIN7", "REvil", "DarkSide", "LockBit", "BlackCat"]

PROTOCOLS = ["HTTP", "HTTPS", "FTP", "SSH", "DNS", "SMTP", "TCP", "UDP"]

TAGS = ["nation-state", "cybercrime", "hacktivism", "espionage",
        "financial", "ransomware", "phishing", "zero-day", "botnet", "trojan"]

# ─── IOC Generation ─────────────────────────────────────────
def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

def random_domain():
    tlds = [".com", ".net", ".ru", ".cn", ".io", ".xyz", ".top", ".tk"]
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    name = ''.join(random.choices(chars, k=random.randint(5, 12)))
    return name + random.choice(tlds)

def random_hash():
    return ''.join(random.choices("abcdef0123456789", k=64))

def random_url(domain):
    paths = ["/login", "/admin", "/update", "/download", "/verify",
             "/secure/banking", "/account/reset", "/malware/payload"]
    return f"http://{domain}{random.choice(paths)}"

def random_email():
    domains = ["gmail.com", "yahoo.com", "protonmail.com", "temp-mail.org"]
    name = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))
    return f"{name}@{random.choice(domains)}"

# ─── Generate Threat Feed ────────────────────────────────────
def generate_threat_feed(n=200):
    threats = []
    base_time = datetime.now() - timedelta(days=30)

    for i in range(n):
        threat_type = random.choice(THREAT_TYPES)
        severity = random.choices(SEVERITY_LEVELS, weights=SEVERITY_WEIGHTS)[0]
        domain = random_domain()

        # Build IOCs
        iocs = {
            "ip_addresses": [random_ip() for _ in range(random.randint(1, 3))],
            "domains": [random_domain() for _ in range(random.randint(1, 2))],
            "urls": [random_url(domain)],
            "hashes": [random_hash() for _ in range(random.randint(0, 2))],
            "emails": [random_email()] if threat_type == "Phishing" else []
        }

        # Risk score based on severity + IOC count
        risk_map = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20}
        base_risk = risk_map[severity]
        ioc_count = sum(len(v) for v in iocs.values())
        risk_score = min(100, base_risk + ioc_count * 2 + random.randint(-5, 10))

        ts = base_time + timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )

        threats.append({
            "id": f"CTI-{i+1:04d}",
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "threat_type": threat_type,
            "severity": severity,
            "risk_score": risk_score,
            "threat_actor": random.choice(THREAT_ACTORS) if random.random() > 0.4 else "Unknown",
            "origin_country": random.choice(COUNTRIES),
            "targeted_sector": random.choice(SECTORS),
            "protocol": random.choice(PROTOCOLS),
            "iocs": iocs,
            "ioc_count": ioc_count,
            "tags": random.sample(TAGS, k=random.randint(1, 3)),
            "confidence": random.randint(50, 99),
            "description": generate_description(threat_type, severity),
            "status": random.choices(
                ["Active", "Monitoring", "Mitigated", "Investigating"],
                weights=[0.3, 0.3, 0.2, 0.2]
            )[0],
            "source": random.choice(["AlienVault OTX", "VirusTotal", "Shodan",
                                      "MISP", "ThreatFox", "Abuse.ch", "Internal"])
        })

    return threats


def generate_description(threat_type, severity):
    templates = {
        "Phishing": f"Phishing campaign targeting Indian banking customers. {severity} severity credential harvesting attempt.",
        "Ransomware": f"Ransomware variant encrypting enterprise systems. {severity} impact on operations.",
        "DDoS": f"Distributed denial-of-service attack on critical infrastructure. {severity} volumetric attack detected.",
        "APT": f"Advanced Persistent Threat group conducting long-term espionage. {severity} risk to national assets.",
        "Malware": f"Malware distribution via compromised software updates. {severity} infection rate.",
        "Data Breach": f"Unauthorized access to sensitive database. {severity} data exfiltration detected.",
        "Credential Stuffing": f"Automated credential stuffing attack on login portals. {severity} account compromise risk.",
        "Supply Chain Attack": f"Supply chain compromise via third-party software vendor. {severity} downstream impact.",
        "Zero-Day Exploit": f"Zero-day vulnerability actively exploited in the wild. {severity} patch urgency.",
        "Insider Threat": f"Suspicious insider activity detected. {severity} data leakage risk."
    }
    return templates.get(threat_type, f"{threat_type} threat detected. Severity: {severity}.")


def save_data(threats):
    import os
    os.makedirs("data", exist_ok=True)

    # Save as JSON
    with open("data/threat_feed.json", "w") as f:
        json.dump(threats, f, indent=2)

    # Save as CSV (flattened)
    flat = []
    for t in threats:
        flat.append({
            "id": t["id"],
            "timestamp": t["timestamp"],
            "threat_type": t["threat_type"],
            "severity": t["severity"],
            "risk_score": t["risk_score"],
            "threat_actor": t["threat_actor"],
            "origin_country": t["origin_country"],
            "targeted_sector": t["targeted_sector"],
            "ioc_count": t["ioc_count"],
            "confidence": t["confidence"],
            "status": t["status"],
            "source": t["source"],
            "tags": ", ".join(t["tags"]),
            "ip_count": len(t["iocs"]["ip_addresses"]),
            "domain_count": len(t["iocs"]["domains"]),
            "hash_count": len(t["iocs"]["hashes"]),
        })

    with open("data/threat_feed.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=flat[0].keys())
        writer.writeheader()
        writer.writerows(flat)

    print(f"✅ Generated {len(threats)} threat records")
    print(f"   → data/threat_feed.json")
    print(f"   → data/threat_feed.csv")
    
    # Stats
    from collections import Counter
    sev_count = Counter(t["severity"] for t in threats)
    print(f"\n📊 Severity Distribution:")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"   {s}: {sev_count[s]}")


if __name__ == "__main__":
    threats = generate_threat_feed(n=200)
    save_data(threats)