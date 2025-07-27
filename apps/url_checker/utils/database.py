"""
URL Database Module

Այս մոդուլը պարունակում է տվյալների շտեմարանի հետ աշխատանքի ֆունկցիաներ:
"""

from ..models import URLCheck, UrlCheckResult
from ..models_integrations import SecurityIntegration, IntegrationResult


def save_url_check_results(url, vt_result, kasp_result, safebrowsing_result, status):
    """
    Պահպանում է URL ստուգման արդյունքները տվյալների բազայում
    
    Args:
        url (str): Ստուգված URL-ը
        vt_result (dict): VirusTotal ստուգման արդյունքներ
        kasp_result (dict): Kaspersky ստուգման արդյունքներ
        safebrowsing_result (dict): Google Safe Browsing ստուգման արդյունքներ
        status (str): URL-ի ընդհանուր կարգավիճակը ('safe', 'suspicious', 'malicious', 'pending')
        
    Returns:
        URLCheck: Ստեղծված URL ստուգման գրառումը
    """
    # Ստեղծում ենք URL ստուգման գրառում
    url_check = URLCheck.objects.create(
        input_text=url,
        status=status
    )
    
    # Պահպանում ենք մանրամասն արդյունքները
    url_check_result = UrlCheckResult.objects.create(
        url_check=url_check,
        virustotal_result=vt_result if vt_result else {},
        kaspersky_result=kasp_result if kasp_result else {},
        safebrowsing_result=safebrowsing_result if safebrowsing_result else {}
    )
    
    # Պահպանում ենք ինտեգրացիայի արդյունքները
    _save_integration_results(url_check, vt_result, kasp_result, safebrowsing_result)
    
    return url_check


def _save_integration_results(url_check, vt_result, kasp_result, safebrowsing_result):
    """
    Պահպանում է ինտեգրացիայի արդյունքները
    
    Args:
        url_check (URLCheck): URL ստուգման գրառումը
        vt_result (dict): VirusTotal ստուգման արդյունքներ
        kasp_result (dict): Kaspersky ստուգման արդյունքներ
        safebrowsing_result (dict): Google Safe Browsing ստուգման արդյունքներ
    """
    # VirusTotal արդյունքներ
    if vt_result:
        integration = SecurityIntegration.objects.get_or_create(
            name='VirusTotal',
            defaults={'api_url': 'https://www.virustotal.com/api/v3/'}
        )[0]
        
        IntegrationResult.objects.create(
            url_check=url_check,
            integration=integration,
            result_data=vt_result,
            is_malicious=vt_result.get('malicious', False)
        )
    
    # Kaspersky արդյունքներ
    if kasp_result:
        integration = SecurityIntegration.objects.get_or_create(
            name='Kaspersky',
            defaults={'api_url': 'https://opentip.kaspersky.com/api/v1/'}
        )[0]
        
        IntegrationResult.objects.create(
            url_check=url_check,
            integration=integration,
            result_data=kasp_result,
            is_malicious=kasp_result.get('malicious', False)
        )
    
    # Google Safe Browsing արդյունքներ
    if safebrowsing_result:
        integration = SecurityIntegration.objects.get_or_create(
            name='Google Safe Browsing',
            defaults={'api_url': 'https://safebrowsing.googleapis.com/v4/'}
        )[0]
        
        IntegrationResult.objects.create(
            url_check=url_check,
            integration=integration,
            result_data=safebrowsing_result,
            is_malicious=safebrowsing_result.get('malicious', False)
        )


def get_recent_url_checks(limit=10):
    """
    Ստանում է վերջին URL ստուգումները
    
    Args:
        limit (int): Վերադարձվող գրառումների առավելագույն քանակը
        
    Returns:
        QuerySet: URL ստուգումների QuerySet
    """
    return URLCheck.objects.order_by('-created_at')[:limit]


def get_url_check_statistics():
    """
    Ստանում է URL ստուգումների վիճակագրությունը
    
    Returns:
        dict: Վիճակագրական տվյալներ
    """
    total_checks = URLCheck.objects.count()
    safe_checks = URLCheck.objects.filter(status='safe').count()
    suspicious_checks = URLCheck.objects.filter(status='suspicious').count()
    malicious_checks = URLCheck.objects.filter(status='malicious').count()
    pending_checks = URLCheck.objects.filter(status='pending').count()
    
    return {
        'total_checks': total_checks,
        'safe_checks': safe_checks,
        'suspicious_checks': suspicious_checks,
        'malicious_checks': malicious_checks,
        'pending_checks': pending_checks,
        'safe_percentage': (safe_checks / total_checks * 100) if total_checks > 0 else 0,
        'suspicious_percentage': (suspicious_checks / total_checks * 100) if total_checks > 0 else 0,
        'malicious_percentage': (malicious_checks / total_checks * 100) if total_checks > 0 else 0,
        'pending_percentage': (pending_checks / total_checks * 100) if total_checks > 0 else 0
    }
