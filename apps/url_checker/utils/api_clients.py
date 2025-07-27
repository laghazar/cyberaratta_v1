"""
API Clients Module

Այս մոդուլը պարունակում է արտաքին API-ների հետ ինտեգրացիայի ֆունկցիաներ,
ինչպիսիք են VirusTotal, Kaspersky OpenTIP և Google Safe Browsing:
"""

import requests
import time
import base64
import datetime
from urllib.parse import urlparse
from decouple import config
from .validators import is_trusted_domain

# API Keys from environment variables
VIRUSTOTAL_API_KEY = config("VIRUSTOTAL_API_KEY")
KASPERSKY_API_KEY = config("KASPERSKY_API_KEY")
GOOGLE_SAFEBROWSING_API_KEY = config("GOOGLE_SAFEBROWSING_API_KEY", default="")


def check_url_virustotal(url):
    """
    VirusTotal API-ի միջոցով URL ստուգում
    
    Args:
        url (str): Ստուգման ենթակա URL-ը
        
    Returns:
        dict: VirusTotal-ի ստուգման արդյունքները հետևյալ բանալիներով՝
            - malicious (bool): True եթե URL-ը վտանգավոր է
            - status (str): 'safe', 'suspicious', 'malicious', or 'pending'
            - details (dict): Մանրամասն տվյալներ
            - message (str): Հայերեն նկարագրություն
            - pending (bool): True եթե ստուգումը դեռ չի ավարտվել
    """
    # Վստահելի դոմենների արագ ստուգում
    if is_trusted_domain(url):
        return {
            "malicious": False,
            "status": "safe",
            "details": {"trusted_domain": True, "harmless": 60, "undetected": 10, "total_engines": 70},
            "message": "Կայքը գտնվում է վստահելի դոմենների ցուցակում",
            "trusted": True
        }
    
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}

    try:
        # 1. Submit URL for analysis
        response = requests.post(endpoint, headers=headers, data=data, timeout=15)
        response.raise_for_status()
        
        analysis_id = response.json().get('data', {}).get('id')
        if not analysis_id:
            return {
                "malicious": False,
                "status": "pending",
                "details": {},
                "message": "VirusTotal վերլուծությունը հնարավոր չէ կատարել",
                "pending": True
            }

        # 2. Wait for analysis to complete
        time.sleep(12)

        # 3. Get analysis report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_resp = requests.get(report_url, headers=headers, timeout=15)
        report_resp.raise_for_status()
        
        result = report_resp.json()
        status = result.get('data', {}).get('attributes', {}).get('status')
        stats = result.get('data', {}).get('attributes', {}).get('stats', {})
        
        # Ստանալ URL-ի լրիվ ինֆորմացիան
        url_attributes = {}
        if status == "completed":
            # Ստանալ URL-ի մանրամասն տվյալները
            try:
                # Get URL report directly 
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                url_report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                url_report_resp = requests.get(url_report_url, headers=headers, timeout=15)
                if url_report_resp.status_code == 200:
                    url_data = url_report_resp.json()
                    url_attributes = url_data.get('data', {}).get('attributes', {})
            except Exception as e:
                print(f"Error getting URL details: {e}")
                
        # Լրացուցիչ մանրամասներ VirusTotal-ից
        last_analysis_date = url_attributes.get('last_analysis_date', 0)
        scan_date = 'Անհայտ'
        if last_analysis_date:
            try:
                scan_date = datetime.datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
            except:
                scan_date = str(last_analysis_date)
                
        reputation = url_attributes.get('reputation', 0)
        title = url_attributes.get('title', '')
        categories = url_attributes.get('categories', {})
        times_submitted = url_attributes.get('times_submitted', 0)
        last_final_url = url_attributes.get('last_final_url', url)
        
        # HTTP response մանրամասներ
        http_response_code = url_attributes.get('last_http_response_code', 0)
        content_length = url_attributes.get('last_http_response_content_length', 0)
        
        # Community votes
        total_votes = url_attributes.get('total_votes', {})
        harmless_votes = total_votes.get('harmless', 0)
        malicious_votes = total_votes.get('malicious', 0)
        
        # Domain տեղեկություններ
        domain_info = {}
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            domain_info['domain'] = domain
            domain_info['scheme'] = parsed_url.scheme
            domain_info['path'] = parsed_url.path
            
        except Exception as e:
            print(f"Domain parsing error: {e}")
        
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        harmless_count = stats.get('harmless', 0)
        undetected_count = stats.get('undetected', 0)
        total_engines = malicious_count + suspicious_count + harmless_count + undetected_count
        
        if status == "completed":
            is_malicious = malicious_count > 0
            is_suspicious = suspicious_count > 0
            
            detailed_result = {
                "malicious": is_malicious,
                "suspicious": is_suspicious,
                "status": "malicious" if is_malicious else ("suspicious" if is_suspicious else "safe"),
                "details": {
                    "malicious": malicious_count,
                    "suspicious": suspicious_count,
                    "harmless": harmless_count,
                    "undetected": undetected_count,
                    "total_engines": total_engines,
                    "scan_date": scan_date,
                    "reputation": reputation,
                    "title": title,
                    "categories": categories,
                    "times_submitted": times_submitted,
                    "http_response_code": http_response_code,
                    "content_length": content_length,
                    "community_votes": {
                        "harmless": harmless_votes,
                        "malicious": malicious_votes,
                        "total": harmless_votes + malicious_votes
                    },
                    "domain_info": domain_info
                }
            }
            
            if is_malicious:
                message = f"VirusTotal ստուգումը հայտնաբերել է {malicious_count} վտանգներ {total_engines} անվտանգության շարժիչներից"
            elif is_suspicious:
                message = f"VirusTotal ստուգումը հայտնաբերել է {suspicious_count} կասկածելի նշաններ {total_engines} անվտանգության շարժիչներից"
            else:
                message = f"VirusTotal ստուգումը չի հայտնաբերել վտանգներ {total_engines} անվտանգության շարժիչներից"
                
            detailed_result["message"] = message
            return detailed_result
        else:
            return {
                "malicious": False,
                "status": "pending",
                "details": {},
                "message": "VirusTotal վերլուծությունը դեռ ընթացքի մեջ է",
                "pending": True
            }
                
    except Exception as e:
        return {
            "malicious": False,
            "status": "pending",
            "details": {},
            "message": f"VirusTotal API սխալ: {str(e)[:100]}...",
            "pending": True
        }


def check_url_kaspersky(url):
    """
    Kaspersky OpenTIP API-ի միջոցով URL ստուգում
    
    Args:
        url (str): Ստուգման ենթակա URL-ը
        
    Returns:
        dict: Kaspersky-ի ստուգման արդյունքները հետևյալ բանալիներով՝
            - malicious (bool): True եթե URL-ը վտանգավոր է
            - status (str): 'safe', 'suspicious', 'malicious', or 'pending'
            - verdict (str): Kaspersky-ի վճիռը
            - message (str): Հայերեն նկարագրություն
            - confidence (str): 'high', 'medium', or 'low'
    """
    # Վստահելի դոմենների արագ ստուգում
    if is_trusted_domain(url):
        return {
            "malicious": False,
            "status": "safe", 
            "verdict": "clean",
            "message": "Կայքը գտնվում է վստահելի դոմենների ցուցակում",
            "trusted": True,
            "confidence": "high"
        }
    
    endpoint = "https://opentip.kaspersky.com/api/v1/search/url"
    headers = {
        "x-api-key": KASPERSKY_API_KEY,
        "Content-Type": "application/json"
    }
    data = {"url": url}

    try:
        response = requests.post(endpoint, headers=headers, json=data, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        verdict = data.get('verdict', '').lower() 
        zone = data.get('zone', '')
        categories = data.get('categories', [])
        
        # Լրացուցիչ տեղեկություններ
        detection_time = data.get('detection_time', '')
        threat_types = data.get('threat_types', [])
        last_seen = data.get('last_seen', '')
        
        # Մանրամասն վերլուծություն
        is_malicious = verdict in ['malicious', 'phishing', 'dangerous', 'harmful']
        is_suspicious = verdict in ['suspicious'] or zone in ['grey', 'yellow']
        
        if verdict and verdict != "unknown":
            confidence = "high" if verdict in ['clean', 'malicious', 'phishing'] else "medium"
            
            if is_malicious:
                message = f"Kaspersky-ն դասակարգել է որպես {verdict}"
            elif is_suspicious:
                message = f"Kaspersky-ն դասակարգել է որպես կասկածելի ({verdict})"
            elif verdict == 'clean':
                message = "Kaspersky-ն դասակարգել է որպես անվտանգ"
            else:
                message = f"Kaspersky գնահատական: {verdict}"
                
            return {
                "malicious": is_malicious,
                "status": "malicious" if is_malicious else ("suspicious" if is_suspicious else "safe"),
                "verdict": verdict,
                "zone": zone,
                "categories": categories,
                "threat_types": threat_types,
                "detection_time": detection_time,
                "last_seen": last_seen,
                "message": message,
                "confidence": confidence,
                "raw": data
            }
        else:
            return {
                "malicious": False,
                "status": "pending",
                "verdict": None,
                "message": "Kaspersky-ն չունի բավարար տեղեկություններ այս URL-ի մասին",
                "pending": True
            }
                
    except Exception as e:
        return {
            "malicious": False,
            "status": "pending",
            "verdict": None,
            "message": f"Kaspersky API սխալ: {str(e)[:100]}...",
            "pending": True,
            "raw": {}
        }


def check_url_safebrowsing(url):
    """
    Google Safe Browsing API-ի միջոցով URL ստուգում
    
    Args:
        url (str): Ստուգման ենթակա URL-ը
        
    Returns:
        dict: Google Safe Browsing-ի ստուգման արդյունքները հետևյալ բանալիներով՝
            - malicious (bool): True եթե URL-ը վտանգավոր է
            - status (str): 'safe', 'malicious', or 'pending'
            - verdict (str): Google Safe Browsing-ի վճիռը
            - message (str): Հայերեն նկարագրություն
            - threat_description (str): Սպառնալիքի տեսակը (եթե կա)
    """
    # Վստահելի դոմենների արագ ստուգում
    if is_trusted_domain(url):
        return {
            "malicious": False,
            "status": "safe",
            "verdict": "clean",
            "message": "Կայքը գտնվում է վստահելի դոմենների ցուցակում",
            "trusted": True,
            "confidence": "high"
        }
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFEBROWSING_API_KEY}"
    
    # Safe Browsing API request body
    request_body = {
        "client": {
            "clientId": "cyberaratta",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING", 
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(endpoint, headers=headers, json=request_body, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        
        # Ստուգում ենք արդյոք կա սպառնալիք
        matches = data.get('matches', [])
        
        if matches:
            threat_match = matches[0]
            threat_type = threat_match.get('threatType', '')
            platform_type = threat_match.get('platformType', '')
            threat_entry_type = threat_match.get('threatEntryType', '')
            
            # Սպառնալիքի նկարագրություն
            threat_descriptions = {
                'MALWARE': 'Վնասակար ծրագրային ապահովում',
                'SOCIAL_ENGINEERING': 'Սոցիալական ինժեներիա/Ֆիշինգ',
                'UNWANTED_SOFTWARE': 'Անցանկալի ծրագրային ապահովում',
                'POTENTIALLY_HARMFUL_APPLICATION': 'Պոտենցիալ վնասակար հավելված'
            }
            
            threat_description = threat_descriptions.get(threat_type, threat_type)
            
            return {
                "malicious": True,
                "status": "malicious",
                "verdict": "malicious",
                "message": f"Google Safe Browsing-ը հայտնաբերել է սպառնալիք: {threat_description}",
                "threat_type": threat_type,
                "threat_description": threat_description,
                "platform_type": platform_type,
                "threat_entry_type": threat_entry_type,
                "confidence": "high",
                "raw": data
            }
        else:
            return {
                "malicious": False,
                "status": "safe",
                "verdict": "clean",
                "message": "Google Safe Browsing-ը չի հայտնաբերել սպառնալիքներ",
                "confidence": "high"
            }
                
    except Exception as e:
        return {
            "malicious": False,
            "status": "pending",
            "verdict": None,
            "message": f"Google Safe Browsing API սխալ: {str(e)[:100]}...",
            "pending": True
        }
