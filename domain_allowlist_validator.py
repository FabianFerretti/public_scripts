import whois
import socket
import ssl
import requests
import json
import dns.resolver
from datetime import datetime
import pytz  # Required for local timezone conversion
import tzlocal  # Automatically detects the system's local timezone
from OpenSSL import crypto

# API Keys (Replace with yours)
VIRUSTOTAL_API_KEY = "<API_Key_Here>"
GOOGLE_SAFE_BROWSING_API_KEY = "<API_Key_Here>"
ABUSEIPDB_API_KEY = "<API_Key_Here>"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "Domain": domain,
            "Creation Date": str(w.creation_date),
            "Expiration Date": str(w.expiration_date),
            "Registrar": w.registrar,
            "Name Servers": w.name_servers
        }
    except Exception as e:
        return {"Error": f"WHOIS lookup failed: {str(e)}"}

def get_ip_address(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare DNS
        answers = resolver.resolve(domain, "A")
        ip_list = [answer.to_text() for answer in answers]
        return {"IP Address": ip_list}
    except Exception as e:
        return {"Error": f"Failed to resolve IP: {str(e)}"}

def categorize_abuse_score(score):
    """Categorize AbuseIPDB confidence scores based on the defined thresholds."""
    if score <= 10:
        return f"Low Risk ({score}) - Generally safe for allow-listing."
    elif 11 <= score <= 20:
        return f"Caution ({score}) - May be safe, but check domain history & reputation."
    elif 21 <= score <= 50:
        return f"Moderate Risk ({score}) - Avoid unless necessary and review carefully."
    else:  # 51-100
        return f"High Risk ({score}) - Do not allow-list. Strong evidence of abuse."

def check_abuseipdb(ip):
    """Check IP reputation on AbuseIPDB and return categorized confidence score."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        if "data" in data:
            abuse_score = data["data"]["abuseConfidenceScore"]
            total_reports = data["data"]["totalReports"]
            last_reported = data["data"]["lastReportedAt"] or "Never reported"

            return {
                "Abuse Score": abuse_score,
                "Category": categorize_abuse_score(abuse_score),
                "Reports": total_reports,
                "Last Reported": last_reported
            }
        return {"Error": "No AbuseIPDB data found"}
    except Exception as e:
        return {"Error": f"AbuseIPDB lookup failed: {str(e)}"}

def convert_unix_timestamp_to_local(timestamp):
    """Convert Unix timestamp to local timezone format: YYYY-MM-DD HH:MM:SS [TimeZone]"""
    try:
        local_timezone = tzlocal.get_localzone()
        local_time = datetime.fromtimestamp(timestamp, local_timezone)
        return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
    except Exception:
        return "Unknown"

def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        if "data" in data:
            attributes = data["data"]["attributes"]
            last_analysis_date = attributes.get("last_analysis_date", 0)
            community_score = attributes.get("reputation", None)  # Correctly extract community score

            return {
                "Last Analysis Stats": attributes.get("last_analysis_stats"),
                "Reputation Score": attributes.get("reputation"),
                "Community Score": community_score,  # Fixed: Now directly retrieves the score
                "Categories": attributes.get("categories"),
                "Last Analysis Date": convert_unix_timestamp_to_local(last_analysis_date),
            }
        return {"Error": "No VirusTotal data found"}
    except Exception as e:
        return {"Error": f"VirusTotal lookup failed: {str(e)}"}

def check_google_safe_browsing(domain):
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "security-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}"}],
        },
    }
    
    response = requests.post(url, json=payload)
    result = response.json()
    if "matches" in result:
        threats = [match["threatType"] for match in result["matches"]]
        return {"Google Safe Browsing": f"Unsafe - Categories: {', '.join(threats)}"}
    return {"Google Safe Browsing": "Safe - No threats detected"}

def run_checks():
    while True:
        domain = input("\nEnter a domain to validate (or type 'q' to quit): ").strip()
        
        if domain.lower() == "q":
            print("\nExiting. Have a great day!")
            break  

        if not domain:
            print("Invalid input. Please enter a valid domain.")
            continue  

        print("\n[+] Checking VirusTotal Reputation...")
        vt_info = check_virustotal(domain)
        print(json.dumps(vt_info, indent=4))

        print("\n[+] Checking Google Safe Browsing...")
        gs_info = check_google_safe_browsing(domain)
        print(json.dumps(gs_info, indent=4))

        print("\n[+] Resolving IP Address...")
        ip_info = get_ip_address(domain)
        print(json.dumps(ip_info, indent=4))

        abuse_info = None
        if "IP Address" in ip_info:
            print("\n[+] Checking IP Reputation on AbuseIPDB...")
            abuse_info = check_abuseipdb(ip_info["IP Address"])
            print(json.dumps(abuse_info, indent=4))

        unsafe_reasons = []

        if vt_info.get("Last Analysis Stats"):
            malicious_count = vt_info["Last Analysis Stats"].get("malicious", 0)
            if malicious_count >= 10:
                unsafe_reasons.append(f"VirusTotal detected {malicious_count} malicious reports.")

        if vt_info.get("Community Score") is not None:
            community_score = vt_info["Community Score"]
            if community_score < 0:
                unsafe_reasons.append(f"VirusTotal Community Score is {community_score} (Likely Malicious).")

        if gs_info["Google Safe Browsing"].startswith("Unsafe"):
            unsafe_reasons.append(f"Google Safe Browsing flagged this domain: {gs_info['Google Safe Browsing']}.")

        if abuse_info and "Abuse Score" in abuse_info:
            abuse_score = abuse_info["Abuse Score"]
            if abuse_score > 50:
                unsafe_reasons.append(f"AbuseIPDB Score {abuse_score} - High Risk.")

        if unsafe_reasons:
            print("\nRESULT: This domain is NOT SAFE for allow-listing.")
            print("Reasons:")
            for reason in unsafe_reasons:
                print(f"- {reason}")
        else:
            print("\nRESULT: This domain is SAFE for allow-listing.")

if __name__ == "__main__":
    run_checks()