"""
CTI Platform - IOC Extractor
Extracts Indicators of Compromise from raw text / threat reports
"""

import re
import json
from collections import defaultdict


# ─── Regex Patterns ─────────────────────────────────────────
PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|edu|gov|ru|cn|io|xyz|top|tk|info|biz|co\.in|in)\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'https?://[^\s<>"\']+',
        re.IGNORECASE
    ),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),
    "cve": re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE),
    "bitcoin_address": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
}

# Known benign IPs / domains to exclude
WHITELIST_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "1.1.1.1"}
WHITELIST_DOMAINS = {"google.com", "microsoft.com", "apple.com", "github.com",
                     "cloudflare.com", "amazon.com", "example.com"}


class IOCExtractor:
    def __init__(self):
        self.patterns = PATTERNS

    def extract(self, text):
        """Extract all IOCs from raw text"""
        results = defaultdict(set)

        for ioc_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            for m in matches:
                m = m.strip().rstrip('.,;:)')
                if self._is_valid(ioc_type, m):
                    results[ioc_type].add(m)

        # Convert sets to sorted lists
        return {k: sorted(list(v)) for k, v in results.items()}

    def _is_valid(self, ioc_type, value):
        if ioc_type == "ipv4":
            return value not in WHITELIST_IPS and not value.startswith("192.168") \
                   and not value.startswith("10.") and not value.startswith("172.")
        if ioc_type == "domain":
            return value.lower() not in WHITELIST_DOMAINS and len(value) > 4
        if ioc_type == "url":
            return len(value) > 10
        return bool(value)

    def enrich(self, iocs):
        """Add basic enrichment / context to IOCs"""
        enriched = {}

        for ioc_type, values in iocs.items():
            enriched[ioc_type] = []
            for val in values:
                entry = {"value": val, "type": ioc_type}

                if ioc_type == "ipv4":
                    entry["risk"] = self._ip_risk(val)
                    entry["geo"] = self._mock_geo(val)

                elif ioc_type == "domain":
                    entry["risk"] = self._domain_risk(val)
                    entry["age_days"] = self._mock_domain_age(val)

                elif ioc_type in ("md5", "sha1", "sha256"):
                    entry["malware_family"] = self._mock_malware_lookup(val)

                elif ioc_type == "cve":
                    entry["cvss_score"] = self._mock_cvss(val)

                enriched[ioc_type].append(entry)

        return enriched

    def _ip_risk(self, ip):
        # Mock risk based on first octet
        first = int(ip.split(".")[0])
        if first in range(1, 50): return "HIGH"
        if first in range(50, 150): return "MEDIUM"
        return "LOW"

    def _mock_geo(self, ip):
        countries = ["China", "Russia", "India", "USA", "Ukraine", "Iran", "Brazil"]
        idx = sum(ord(c) for c in ip) % len(countries)
        return countries[idx]

    def _domain_risk(self, domain):
        suspicious_tlds = [".tk", ".xyz", ".top", ".ru", ".cn"]
        if any(domain.endswith(t) for t in suspicious_tlds):
            return "HIGH"
        if len(domain) > 25:
            return "MEDIUM"
        return "LOW"

    def _mock_domain_age(self, domain):
        return (sum(ord(c) for c in domain) % 700) + 1

    def _mock_malware_lookup(self, hash_val):
        families = ["Emotet", "TrickBot", "Ryuk", "Cobalt Strike",
                    "Mimikatz", "Lazagne", "AgentTesla", "Unknown"]
        idx = int(hash_val[:4], 16) % len(families)
        return families[idx]

    def _mock_cvss(self, cve):
        scores = {"2023": 9.8, "2022": 8.5, "2021": 7.2, "2020": 6.5}
        year = cve.split("-")[1] if "-" in cve else "2023"
        return scores.get(year, round(5.0 + (int(year[-1]) % 5), 1))


def extract_from_report(report_text):
    """Main function to extract + enrich IOCs from threat report"""
    extractor = IOCExtractor()
    raw_iocs = extractor.extract(report_text)
    enriched = extractor.enrich(raw_iocs)

    total = sum(len(v) for v in raw_iocs.values())
    print(f"✅ Extracted {total} IOCs")
    for k, v in raw_iocs.items():
        if v:
            print(f"   {k}: {len(v)} found")

    return enriched


# ─── Sample Threat Report for Demo ──────────────────────────
SAMPLE_REPORT = """
THREAT INTELLIGENCE REPORT - CERT-IN Advisory

A sophisticated phishing campaign has been identified targeting Indian banking institutions.
The threat actor APT28 has been observed using the following infrastructure:

Malicious IPs: 185.220.101.45, 91.108.4.0, 194.165.16.158
C2 Domains: malware-updater.xyz, secure-banking-verify.top, update-microsoft-india.ru
Phishing URLs: http://secure-banking-verify.top/login, https://update-microsoft-india.ru/verify

File Hashes (SHA256):
a3f5b2c4d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3
b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5

Email: phisher123@protonmail.com, noreply-bank@temp-mail.org

Vulnerabilities exploited: CVE-2023-44487, CVE-2022-30190

Bitcoin ransom address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

Affected sectors: Banking, Finance, Government portals
"""


if __name__ == "__main__":
    print("=" * 60)
    print("IOC EXTRACTION ENGINE - CTI PLATFORM")
    print("=" * 60)
    
    result = extract_from_report(SAMPLE_REPORT)
    
    print("\n📋 Enriched IOCs:")
    print(json.dumps(result, indent=2))
    
    # Save to file
    import os
    os.makedirs("data", exist_ok=True)
    with open("data/extracted_iocs.json", "w") as f:
        json.dump(result, f, indent=2)
    print("\n✅ Saved to data/extracted_iocs.json")