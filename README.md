# Domain Allowlist Validator
#
# This script performs a **comprehensive security analysis** of a domain before  
# allow-listing it for safe browsing in an organization. It automates key security 
# checks to **detect malicious, phishing, or high-risk domains**.
# --------------------------------------------------------------------------------

#  **Key Features:**
# - **VirusTotal Analysis**: 
#     - Checks domain reputation, categories, last analysis date, and detection statistics.
#     - Includes **VirusTotal Community Score** to determine if the security community considers the domain malicious.
# - **AbuseIPDB Lookup**: 
#     - Retrieves IP reputation and categorizes abuse confidence based on user reports.
#     - Uses a **risk categorization system** for allow-list decisions.
# - **WHOIS Lookup**: 
#     - Fetches domain creation/expiration dates, registrar info, and name servers.
# - **Google Safe Browsing**: 
#     - Checks if the domain is blacklisted for phishing, malware, or unwanted software.
#     - **Note:** This check is **informational only** and does not impact the final decision.
# - **DNS & IP Resolution**: 
#     - Resolves the domain to an IP address using Google and Cloudflare public DNS.
# - **Automatic Timezone Detection**: 
#     - Converts timestamps to the local system time instead of UTC.
# - **Continuous Checking Mode**: 
#     - Allows multiple domain checks in one session, prompting for a new domain automatically.
# - **Risk Categorization & Decision-Making**:
#     - Flags domains as **Safe** or **Not Safe** based on **VirusTotal detections, Community Score, and AbuseIPDB reports**.
#     - Uses **clear thresholds** (e.g., 10+ malicious VirusTotal detections = unsafe).
# - **Security Header Warnings**: 
#     - Displays missing security headers (e.g., HSTS, CSP, X-XSS Protection) for awareness.
# --------------------------------------------------------------------------------

#  **How It Works:**
#  1. Run in PowerShell or Command Prompt:  
#       ```python domain_allowlist_validator.py```  
#     *(Ensure the script is in the same directory when running the command.)*
#  2. Enter a domain name to validate.
#  3. The script runs multiple security checks using VirusTotal, AbuseIPDB, WHOIS, DNS, and Google Safe Browsing.
#  4. It categorizes the domain as **Safe** or **Not Safe** based on pre-defined risk thresholds.
#  5. If needed, enter another domain or type 'q' to exit.
# --------------------------------------------------------------------------------

#  **Required Dependencies:**
# Install all dependencies using the following command:
#     pip install requests dnspython python-whois pytz tzlocal pyOpenSSL
#
#  **Dependency Descriptions:**
# - `requests`       → Makes HTTP requests (used for VirusTotal, Google Safe Browsing, AbuseIPDB).
# - `dnspython`      → Handles DNS lookups (used for resolving domain IP addresses).
# - `python-whois`   → Fetches WHOIS data (domain registration details).
# - `pytz`          → Provides timezone support (helps with datetime conversions).
# - `tzlocal`       → Automatically detects the system's local timezone.
# - `pyOpenSSL`     → Extracts SSL certificate details from websites.
#
# --------------------------------------------------------------------------------







