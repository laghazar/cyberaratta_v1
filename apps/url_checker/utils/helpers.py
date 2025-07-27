"""
Utility Module

Այս մոդուլը պարունակում է ընդհանուր օգտակար ֆունկցիաներ։
"""

import re
import json
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def extract_domain_from_url(url):
    """
    Ստանում է դոմենը URL-ից
    
    Args:
        url (str): URL-ը, որից պետք է ստանալ դոմենը
    
    Returns:
        str: Դոմենը առանց www-ի
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Հեռացնում ենք www-ն
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain
    except:
        return url


def clean_url(url):
    """
    Մաքրում է URL-ը հետևելու պարամետրերից
    
    Args:
        url (str): Մաքրման ենթակա URL-ը
    
    Returns:
        str: Մաքրված URL
    """
    try:
        # Եթե URL-ը չի սկսվում http:// կամ https://-ով, ավելացնում ենք
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        
        # Հեռացնում ենք հետևելու պարամետրերը
        tracking_params = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 
                          'utm_content', 'fbclid', 'gclid', 'ref', 'source']
        
        for param in tracking_params:
            if param in query:
                del query[param]
        
        # Կառուցում ենք նոր URL-ը
        new_query = urlencode(query, doseq=True)
        clean_parsed = parsed_url._replace(query=new_query)
        
        return urlunparse(clean_parsed)
    except:
        return url


def generate_unique_id():
    """
    Ստեղծում է եզակի ID
    
    Returns:
        str: Եզակի ID
    """
    return str(uuid.uuid4())


def format_json_for_display(json_data):
    """
    Ձևավորում է JSON-ը ցուցադրման համար
    
    Args:
        json_data (dict): JSON տվյալները
    
    Returns:
        str: Ձևավորված JSON
    """
    try:
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        
        formatted_json = json.dumps(json_data, indent=2, ensure_ascii=False)
        return formatted_json
    except:
        return str(json_data)


def truncate_string(text, max_length=100):
    """
    Կրճատում է տեքստը մինչև նշված երկարությունը
    
    Args:
        text (str): Կրճատվող տեքստը
        max_length (int): Առավելագույն երկարությունը
    
    Returns:
        str: Կրճատված տեքստը
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - 3] + '...'


def sanitize_filename(filename):
    """
    Մաքրում է ֆայլի անունը անվտանգ օգտագործման համար
    
    Args:
        filename (str): Ֆայլի անունը
    
    Returns:
        str: Մաքրված ֆայլի անունը
    """
    # Հեռացնում ենք անթույլատրելի նիշերը
    sanitized = re.sub(r'[\\/*?:"<>|]', '', filename)
    
    # Փոխարինում ենք բացատները underscore-ով
    sanitized = sanitized.replace(' ', '_')
    
    return sanitized
