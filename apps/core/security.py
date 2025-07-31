"""
CyberAratta անվտանգության օժանդակ գործիքներ
"""
import re
import html
import logging
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags
from django_ratelimit.decorators import ratelimit
from functools import wraps

# Logger-ի կարգավորում
logger = logging.getLogger('cyberaratta.security')

def sanitize_input(text):
    """
    Մուտքագրվող տեքստի մաքրում
    """
    if not text:
        return text
    
    # HTML tags-երի հեռացում
    text = strip_tags(text)
    
    # HTML entities-ների escape
    text = html.escape(text)
    
    # Վտանգավոր նիշերի հեռացում (բայց ոչ URL-ների համար օգտակար նիշերը)
    dangerous_chars = ['<script', '</script', 'javascript:', 'vbscript:', 'onload=', 'onerror=']
    for char in dangerous_chars:
        text = text.replace(char, '')
    
    # Երկար տող կտրում
    if len(text) > 1000:
        text = text[:1000]
    
    return text.strip()

def validate_url(url):
    """
    URL-ի վալիդացիա
    """
    if not url:
        raise ValidationError("URL չի կարող դատարկ լինել")
    
    # URL-ի համար minimal sanitization
    url = url.strip()
    
    # Հիմնական URL regex
    url_pattern = re.compile(
        r'^https?://'  # http:// կամ https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        raise ValidationError("Անվավեր URL ֆորմատ")
    
    # Վտանգավոր URL-ների ստուգում
    dangerous_patterns = [
        r'javascript:',
        r'data:',
        r'vbscript:',
        r'file://',
        r'ftp://'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            logger.warning(f"Վտանգավոր URL հայտնաբերվել է: {url}")
            raise ValidationError("Վտանգավոր URL հայտնաբերվել է")
    
    return url  # Return original URL without aggressive sanitization

def validate_email(email):
    """
    Email-ի վալիդացիա
    """
    if not email:
        raise ValidationError("Email չի կարող դատարկ լինել")
    
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    if not email_pattern.match(email):
        raise ValidationError("Անվավեր email ֆորմատ")
    
    return sanitize_input(email)

def log_security_event(event_type, user_ip, details):
    """
    Անվտանգության իրադարձությունների գրանցում
    """
    logger.warning(f"Անվտանգության իրադարձություն: {event_type} | IP: {user_ip} | Մանրամասներ: {details}")

def rate_limit_key(group, request):
    """
    Rate limiting-ի համար key generator
    """
    return f"{group}:{request.META.get('REMOTE_ADDR', 'unknown')}"

def security_rate_limit(key='default', rate='10/m', method='POST'):
    """
    Անվտանգ rate limiting decorator
    """
    def decorator(view_func):
        @wraps(view_func)
        @ratelimit(key=lambda g, r: rate_limit_key(key, r), rate=rate, method=method)
        def wrapped_view(request, *args, **kwargs):
            # Rate limit-ի ստուգում
            if getattr(request, 'limited', False):
                client_ip = request.META.get('REMOTE_ADDR', 'unknown')
                log_security_event('RATE_LIMIT_EXCEEDED', client_ip, f'Key: {key}, Rate: {rate}')
                from django.http import HttpResponseTooManyRequests
                return HttpResponseTooManyRequests("Չափազանց շատ հարցումներ: Խնդրում ենք փորձել ավելի ուշ")
            
            return view_func(request, *args, **kwargs)
        return wrapped_view
    return decorator

class SecurityMiddleware:
    """
    Անվտանգության middleware
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Կասկածելի մուտքագրումների ստուգում
        self.check_suspicious_input(request)
        
        response = self.get_response(request)
        
        # Անվտանգության headers ավելացում
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response
    
    def check_suspicious_input(self, request):
        """
        Կասկածելի մուտքագրումների ստուգում
        """
        # Simplified patterns to avoid regex issues
        suspicious_keywords = [
            '<script',
            'javascript:',
            'union select',
            'drop table',
            'exec(',
            'eval(',
            '<iframe',
            'onload=',
            'onerror=',
            'vbscript:',
        ]
        
        # POST և GET տվյալների ստուգում
        for data_dict in [request.POST, request.GET]:
            for key, value in data_dict.items():
                value_str = str(value).lower()
                for keyword in suspicious_keywords:
                    if keyword in value_str:
                        client_ip = request.META.get('REMOTE_ADDR', 'unknown')
                        log_security_event('SUSPICIOUS_INPUT', client_ip, f'Keyword: {keyword}, Value: {value[:100]}')
                        break
