"""
URL Validators Module

Այս մոդուլը պարունակում է URL-ների վավերացման ֆունկցիաներ, ինչպիսիք են
վստահելի դոմենների ստուգումը, URL-ների վավերականության ստուգումը և այլն:
"""

import re
from urllib.parse import urlparse

# Հայտնի անվտանգ կայքերի ցուցակ
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com',
    'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'wikipedia.org',
    'github.com', 'stackoverflow.com', 'reddit.com', 'yahoo.com', 'gmail.com',
    'outlook.com', 'whatsapp.com', 'telegram.org', 'zoom.us', 'netflix.com',
    'spotify.com', 'paypal.com', 'ebay.com', 'airbnb.com', 'uber.com',
    'gov.am', 'edu.am', 'president.am', 'mfa.am', 'police.am',
    'ysu.am', 'aua.am', 'tumo.org', 'arca.am', 'armenpress.am'
]

def is_trusted_domain(url):
    """
    Ստուգում է արդյոք դոմենը վստահելի է
    
    Args:
        url (str): Ստուգվող URL-ը
        
    Returns:
        bool: True եթե դոմենը վստահելի է, False հակառակ դեպքում
    """
    try:
        domain = urlparse(url).netloc.lower()
        
        # Հանում www. prefix-ը
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return any(trusted in domain or domain.endswith('.' + trusted) for trusted in TRUSTED_DOMAINS)
    except:
        return False

def is_valid_url(url):
    """
    Ստուգում է արդյոք URL-ը վավեր է
    
    Args:
        url (str): Ստուգվող URL-ը
        
    Returns:
        bool: True եթե URL-ը վավեր է, False հակառակ դեպքում
    """
    try:
        # URL-ի ֆորմատի ստուգում
        url_pattern = re.compile(
            r'^(?:http|https)://'  # http:// կամ https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # դոմեն
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'(?::\d+)?'  # պորտ
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(url):
            # Եթե URL-ը չի սկսվում http:// կամ https:// prefix-ով, ավելացնում ենք այն
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                if not url_pattern.match(url):
                    return False
        
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def categorize_url(url):
    """
    Դասակարգում է URL-ը ըստ տեսակի
    
    Args:
        url (str): Դասակարգվող URL-ը
        
    Returns:
        dict: URL-ի դասակարգման արդյունքը հետևյալ բանալիներով՝
            - type (str): 'normal', 'ip_address', 'shortened', 'localhost'
            - is_secure (bool): True եթե URL-ը օգտագործում է HTTPS, False հակառակ դեպքում
            - domain (str): URL-ի դոմենը
    """
    result = {
        'type': 'normal',
        'is_secure': False,
        'domain': None
    }
    
    try:
        parsed = urlparse(url)
        
        # Ստուգում ենք արդյոք HTTPS է
        result['is_secure'] = parsed.scheme == 'https'
        
        # Ստանում ենք դոմենը
        result['domain'] = parsed.netloc
        
        # Ստուգում ենք արդյոք IP հասցե է
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(parsed.netloc.split(':')[0]):
            result['type'] = 'ip_address'
        
        # Ստուգում ենք արդյոք shortened URL է
        shortened_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
        if any(parsed.netloc.endswith(sd) for sd in shortened_domains):
            result['type'] = 'shortened'
        
        # Ստուգում ենք արդյոք localhost է
        if parsed.netloc == 'localhost' or parsed.netloc.startswith('localhost:'):
            result['type'] = 'localhost'
            
        return result
    except:
        return result
