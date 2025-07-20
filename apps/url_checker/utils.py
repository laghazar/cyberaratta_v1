import requests
from decouple import config
import time

VIRUSTOTAL_API_KEY = config("VIRUSTOTAL_API_KEY")
KASPERSKY_API_KEY = config("KASPERSKY_API_KEY")

def check_url_virustotal(url):
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}

    try:
        # 1. Submit URL for analysis
        response = requests.post(endpoint, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        analysis_id = response.json().get('data', {}).get('id')
        if not analysis_id:
            return {
                "malicious": False,
                "status": "pending",
                "details": {},
                "message": "No analysis ID returned"
            }

        # 2. Wait a bit for analysis to complete
        time.sleep(10)

        # 3. Get analysis report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_resp = requests.get(report_url, headers=headers, timeout=10)
        report_resp.raise_for_status()
        result = report_resp.json()
        status = result.get('data', {}).get('attributes', {}).get('status')
        stats = result.get('data', {}).get('attributes', {}).get('stats', {})
        malicious_count = stats.get('malicious', 0)

        # Քարտեզում status-ը
        if status == "completed":
            verdict = "malicious" if malicious_count > 0 else "safe"
            return {
                "malicious": malicious_count > 0,
                "status": verdict,
                "details": stats,
                "message": "Վտանգավոր է։" if malicious_count > 0 else "Անվտանգ է։"
            }
        elif status in ["queued", "awaiting manual review"]:
            return {
                "malicious": False,
                "status": "pending",
                "details": stats,
                "message": "Հղումը սպասում է ձեռքով մշակման։ Արդյունքը կհայտնվի 3 աշխատանքային օրվա ընթացքում։",
                "pending": True
            }
        else:
            return {
                "malicious": False,
                "status": "pending",
                "details": stats,
                "message": "Արդյունքը հասանելի չէ։"
            }

    except requests.RequestException as e:
        return {
            "malicious": False,
            "status": "pending",
            "details": {},
            "message": f"Սխալ API կապի ժամանակ: {str(e)}"
        }

def check_url_kaspersky(url):
    endpoint = "https://opentip.kaspersky.com/api/v1/search/url"
    headers = {
        "x-api-key": KASPERSKY_API_KEY,
        "Content-Type": "application/json"
    }
    data = {"url": url}

    try:
        response = requests.post(endpoint, headers=headers, json=data, timeout=10)
        response.raise_for_status()
        data = response.json()
        verdict = data.get('verdict', '').lower()
        is_malicious = verdict in ['malicious', 'phishing', 'dangerous']
        
        # pending եթե verdict չկա կամ "unknown"
        if not verdict or verdict == "unknown":
            return {
                "malicious": False,
                "status": "pending",
                "verdict": verdict,
                "raw": data,
                "message": "Հղումը սպասում է ձեռքով մշակման։",
                "pending": True
            }
        else:
            return {
                "malicious": is_malicious,
                "status": verdict,
                "verdict": verdict,
                "raw": data,
                "message": "Վտանգավոր է։" if is_malicious else "Անվտանգ է։"
            }
    except requests.RequestException as e:
        return {
            "malicious": False,
            "status": "pending",
            "verdict": None,
            "raw": {},
            "message": f"Սխալ API կապի ժամանակ: {str(e)}"
        }