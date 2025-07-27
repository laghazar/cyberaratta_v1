"""
URL Analyzer Module

Այս մոդուլը պարունակում է URL-ների վերլուծության ֆունկցիաներ, ներառյալ օրինաչափությունների
հայտնաբերում, կասկածելի հատկանիշների վերլուծություն և ընդհանուր անվտանգության վերլուծություն:
"""

import re
from urllib.parse import urlparse
from .validators import is_trusted_domain


def analyze_url_pattern(url):
    """
    Վերլուծում է URL-ի կառուցվածքը կասկածելի օրինաչափությունների համար
    
    Args:
        url (str): Վերլուծման ենթակա URL-ը
    
    Returns:
        int: Հայտնաբերված կասկածելի օրինաչափությունների քանակը
    """
    suspicious_patterns = [
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP հասցեներ
        r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.[a-z]{2,}',  # Կասկածելի subdomain-ներ
        r'[a-z0-9]{20,}\.[a-z]{2,}',  # Շատ երկար դոմեն անուններ
        r'[0-9]{4,}',  # Շատ թվեր URL-ում
        r'bit\.ly|tinyurl|short|redirect',  # URL shortener-ներ
        r'\.tk$|\.ml$|\.ga$|\.cf$',  # Անվճար TLD-ներ
    ]
    
    suspicious_count = sum(1 for pattern in suspicious_patterns if re.search(pattern, url.lower()))
    return suspicious_count


def analyze_url_safety(url, vt_result=None, kasp_result=None, safebrowsing_result=None):
    """
    Վերլուծում է URL-ի անվտանգությունը բազմաթիվ աղբյուրների հիման վրա
    
    Args:
        url (str): Վերլուծման ենթակա URL-ը
        vt_result (dict): VirusTotal API-ի արդյունքներ
        kasp_result (dict): Kaspersky API-ի արդյունքներ
        safebrowsing_result (dict): Google Safe Browsing API-ի արդյունքներ
    
    Returns:
        dict: Վերլուծության արդյունքը հետևյալ բանալիներով՝
            - status (str): 'safe', 'suspicious', 'malicious', or 'pending'
            - confidence_level (str): 'high', 'medium', or 'low'
            - sources_used (list): Օգտագործված աղբյուրների ցանկ
            - suspicious_patterns (int): Հայտնաբերված կասկածելի օրինաչափությունների քանակը
    """
    # Հիմնական կարգավիճակը
    status = determine_status(vt_result, kasp_result, safebrowsing_result, url)
    
    # Վստահության մակարդակը
    confidence_level = _determine_confidence_level(vt_result, kasp_result, safebrowsing_result)
    
    # Օգտագործված աղբյուրները
    sources_used = _get_sources_used(vt_result, kasp_result, safebrowsing_result)
    
    # Կասկածելի օրինաչափություններ
    suspicious_patterns = analyze_url_pattern(url)
    
    return {
        'url': url,
        'status': status,
        'confidence_level': confidence_level,
        'sources_used': sources_used,
        'suspicious_patterns': suspicious_patterns
    }


def determine_status(vt_result, kasp_result, safebrowsing_result, url):
    """
    Որոշում է URL-ի ընդհանուր կարգավիճակը
    
    Args:
        vt_result (dict): VirusTotal արդյունքներ
        kasp_result (dict): Kaspersky արդյունքներ
        safebrowsing_result (dict): Google Safe Browsing արդյունքներ
        url (str): Ստուգվող URL-ը
    
    Returns:
        str: 'safe', 'suspicious', 'malicious', or 'pending'
    """
    # Վստահելի դոմեն
    if is_trusted_domain(url):
        return 'safe'
    
    # VirusTotal արդյունքներ
    if vt_result and not vt_result.get('pending'):
        if vt_result.get('malicious', 0) > 0:
            return 'malicious'
        elif vt_result.get('suspicious', 0) > 0:
            return 'suspicious'
    
    # Kaspersky արդյունքներ
    if kasp_result and not kasp_result.get('pending'):
        if kasp_result.get('malicious', False):
            return 'malicious'
    
    # Google Safe Browsing արդյունքներ
    if safebrowsing_result and not safebrowsing_result.get('pending'):
        if safebrowsing_result.get('malicious', False):
            return 'malicious'
    
    # Եթե արտաքին ստուգումներ չկան կամ դրանք 'pending' են
    if (vt_result and vt_result.get('pending')) or (kasp_result and kasp_result.get('pending')) or (safebrowsing_result and safebrowsing_result.get('pending')):
        return 'pending'
    
    # Եթե կան արտաքին ստուգումներ և դրանք չեն վերադարձրել սպառնալիքներ
    if vt_result or kasp_result or safebrowsing_result:
        return 'safe'
    
    # Եթե չկան արտաքին ստուգումներ, ստուգել օրինաչափությունները
    if analyze_url_pattern(url) > 2:
        return 'suspicious'
    
    return 'pending'


def _get_sources_used(vt_result, kasp_result, safebrowsing_result=None):
    """
    Վերադարձնում է օգտագործված աղբյուրների ցանկը
    
    Args:
        vt_result (dict): VirusTotal արդյունքներ
        kasp_result (dict): Kaspersky արդյունքներ
        safebrowsing_result (dict): Google Safe Browsing արդյունքներ
    
    Returns:
        list: Օգտագործված աղբյուրների ցանկ
    """
    sources = []
    
    if vt_result and not vt_result.get('pending'):
        sources.append('VirusTotal')
    
    if kasp_result and not kasp_result.get('pending'):
        sources.append('Kaspersky')
    
    if safebrowsing_result and not safebrowsing_result.get('pending'):
        sources.append('Google Safe Browsing')
    
    # Միշտ ավելացնում ենք ներքին վերլուծությունը
    sources.append('Ներքին Վերլուծություն')
    
    return sources


def _determine_confidence_level(vt_result, kasp_result, safebrowsing_result=None):
    """
    Որոշում է վստահության մակարդակը
    
    Args:
        vt_result (dict): VirusTotal արդյունքներ
        kasp_result (dict): Kaspersky արդյունքներ
        safebrowsing_result (dict): Google Safe Browsing արդյունքներ
    
    Returns:
        str: 'high', 'medium', or 'low'
    """
    external_sources = 0
    
    if vt_result and not vt_result.get('pending'):
        external_sources += 1
    
    if kasp_result and not kasp_result.get('pending'):
        external_sources += 1
        
    if safebrowsing_result and not safebrowsing_result.get('pending'):
        external_sources += 1
    
    if external_sources >= 3:
        return 'high'
    elif external_sources >= 2:
        return 'medium'
    else:
        return 'low'
