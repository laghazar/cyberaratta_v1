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
            return {"malicious": False, "error": "No analysis ID returned"}

        # 2. Wait a bit for analysis to complete
        time.sleep(10)

        # 3. Get analysis report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_resp = requests.get(report_url, headers=headers, timeout=10)
        report_resp.raise_for_status()
        result = report_resp.json()
        stats = result.get('data', {}).get('attributes', {}).get('stats', {})

        malicious_count = stats.get('malicious', 0)
        return {
            "malicious": malicious_count > 0,
            "malicious_count": malicious_count,
            "details": stats
        }

    except requests.RequestException as e:
        return {"malicious": False, "error": str(e)}

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
        return {
            "malicious": is_malicious,
            "verdict": verdict,
            "raw": data
        }
    except requests.RequestException as e:
        return {"malicious": False, "error": str(e)}
