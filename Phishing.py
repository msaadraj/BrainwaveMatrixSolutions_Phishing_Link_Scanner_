import re
import requests
from urllib.parse import urlparse

def is_ip_address(url):
    pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    return bool(re.search(pattern, url))

def contains_suspicious_keywords(url):
    suspicious_keywords = ["login", "verify", "secure", "update", "bank", "free", "win", "prize", "account", "pay"]
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def check_url_blacklist(url):
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls", headers={"x-apikey": "YOUR_API_KEY"})
        if response.status_code == 200:
            data = response.json()
            return data.get("malicious", 0) > 0
    except Exception as e:
        print("Error checking URL blacklist:", e)
    return False

def analyze_url(url):
    parsed_url = urlparse(url)
    domain_length = len(parsed_url.netloc)
    
    ip_present = is_ip_address(url)
    suspicious_keywords = contains_suspicious_keywords(url)
    blacklisted = check_url_blacklist(url)
    
    print("\nPhishing Link Scanner Results:")
    print(f"URL: {url}")
    print(f"IP Address Present: {'Yes' if ip_present else 'No'}")
    print(f"Contains Suspicious Keywords: {'Yes' if suspicious_keywords else 'No'}")
    print(f"Domain Length: {domain_length} characters")
    print(f"Blacklisted: {'Yes' if blacklisted else 'No'}")
    
    risk_score = ip_present + suspicious_keywords + (domain_length > 20) + blacklisted
    if risk_score >= 3:
        print("⚠️ High Risk: This URL is likely phishing!")
    elif risk_score == 2:
        print("⚠️ Medium Risk: Be cautious with this link.")
    else:
        print("✅ Low Risk: This link seems safe.")

if __name__ == "__main__":
    user_url = input("Enter the URL to scan: ")
    analyze_url(user_url)
