import requests
from decouple import config
import time
import re
from urllib.parse import urlparse
import json
import datetime

# Ներքին վերլուծության import
try:
    from .internal_analyzer import analyze_unknown_url
except ImportError:
    # Fallback եթե internal analyzer չի գոծարկվում
    def analyze_unknown_url(url):
        return {'risk_score': 50, 'findings': ['Ներքին վերլուծությունը հասանելի չէ'], 'recommendations': []}

VIRUSTOTAL_API_KEY = config("VIRUSTOTAL_API_KEY")
KASPERSKY_API_KEY = config("KASPERSKY_API_KEY")
GOOGLE_SAFEBROWSING_API_KEY = config("GOOGLE_SAFEBROWSING_API_KEY", default="AIzaSyDIx4XWpTDmHtXomhhEmz-CQAI91QViWr4")

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
    """Ստուգում է արդյոք դոմենը վստահելի է"""
    try:
        domain = urlparse(url).netloc.lower()
        # Հանում www. prefix-ը
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return any(trusted in domain or domain.endswith('.' + trusted) for trusted in TRUSTED_DOMAINS)
    except:
        return False

def analyze_url_pattern(url):
    """Վերլուծում է URL-ի կառուցվածքը կասկածելի օրինակների համար"""
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

def get_detailed_analysis(url, vt_result, kasp_result, safebrowsing_result=None):
    """Ստեղծում է մանրամասն վերլուծություն օգտագործելով նոր կոմպակտ ձևաչափը"""
    
    # Որոշում ենք հիմնական կարգավիճակը
    status = determine_status(vt_result, kasp_result, safebrowsing_result, url)
    
    # Ստեղծում ենք մանրամասն պատասխան
    response = format_detailed_response(status, url, vt_result, kasp_result, safebrowsing_result)
    
    # Վերադարձնում ենք համապատասխան տվյալները
    return {
        'url': url,
        'status': status,
        'result': response,
        'analysis_type': 'combined',
        'sources_used': _get_sources_used(vt_result, kasp_result, safebrowsing_result),
        'confidence_level': _determine_confidence_level(vt_result, kasp_result, safebrowsing_result)
    }

def determine_status(vt_result, kasp_result, safebrowsing_result, url):
    """Որոշում է URL-ի ընդհանուր կարգավիճակը"""
    
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
    
    # Եթե արտաքին ստուգումներ չկան, ներքին վերլուծություն
    return 'pending'

def _get_sources_used(vt_result, kasp_result, safebrowsing_result=None):
    """Վերադարձնում է օգտագործված աղբյուրների ցանկը"""
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
    """Որոշում է վստահության մակարդակը"""
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
    
    if external_sources >= 2:
        return 'high'
    elif external_sources == 1:
        return 'medium'
    else:
        return 'low'
    analysis = {
        'url': url,
        'analysis_type': 'api',
        'is_trusted': is_trusted_domain(url),
        'suspicious_patterns': analyze_url_pattern(url),
        'sources_used': [],
        'recommendations': [],
        'technical_details': {},
        'confidence_level': 'medium'
    }
    
    # VirusTotal արդյունքների վերլուծություն
    if vt_result and not vt_result.get('pending'):
        analysis['sources_used'].append('VirusTotal')
        vt_stats = vt_result.get('details', {})
        analysis['technical_details']['virustotal'] = {
            'malicious': vt_stats.get('malicious', 0),
            'suspicious': vt_stats.get('suspicious', 0),
            'harmless': vt_stats.get('harmless', 0),
            'undetected': vt_stats.get('undetected', 0),
            'total_engines': sum(vt_stats.values()) if vt_stats else 0
        }
    
    # Kaspersky արդյունքների վերլուծություն
    if kasp_result and not kasp_result.get('pending'):
        analysis['sources_used'].append('Kaspersky')
        analysis['technical_details']['kaspersky'] = {
            'verdict': kasp_result.get('verdict', 'unknown'),
            'confidence': kasp_result.get('confidence', 'medium')
        }
    
    return analysis


def format_internal_analysis_html(internal_analysis):
    """Ֆորմատավորում է ներքին վերլուծության HTML-ը"""
    if not internal_analysis:
        return ""
    
    findings = internal_analysis.get('findings', [])
    recommendations = internal_analysis.get('recommendations', [])
    risk_score = internal_analysis.get('risk_score', 0)
    ssl_info = internal_analysis.get('ssl_info', {})
    domain_info = internal_analysis.get('domain_info', {})
    technical_details = internal_analysis.get('technical_details', {})
    
    # Ռիսկի գույն և նկարագրություն
    if risk_score <= 20:
        risk_color = 'success'
        risk_level = 'Ցածր'
    elif risk_score <= 40:
        risk_color = 'info' 
        risk_level = 'Ցածր-Միջին'
    elif risk_score <= 60:
        risk_color = 'warning'
        risk_level = 'Միջին'
    elif risk_score <= 80:
        risk_color = 'danger'
        risk_level = 'Բարձր'
    else:
        risk_color = 'danger'
        risk_level = 'Շատ Բարձր'
    
    html = f"""
        <div class="col-lg-12">
            <div class="card border-{risk_color} border-opacity-25 shadow-sm mb-3">
                <div class="card-header bg-{risk_color} bg-opacity-10">
                    <div class="d-flex align-items-center justify-content-between">
                        <div class="d-flex align-items-center">
                            <i class="fas fa-brain me-2 text-{risk_color}"></i>
                            <strong class="text-{risk_color}">Ներքին Վերլուծություն</strong>
                        </div>
                        <span class="badge bg-{risk_color}">Ռիսկ: {risk_level}</span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-8">
                            <div class="mb-3">
                                <div class="d-flex justify-content-between align-items-center mb-2">
                                    <small class="text-light d-block">Ռիսկի Գնահատում</small>
                                    <small class="fw-bold text-{risk_color}">{risk_score}/100</small>
                                </div>
                                <div class="progress" style="height: 10px;">
                                    <div class="progress-bar bg-{risk_color}" style="width: {risk_score}%"></div>
                                </div>
                            </div>
                            
                            <div class="findings-section">
                                <h6 class="text-secondary mb-2">🔍 Հայտնաբերված Գործոններ</h6>
                                <div class="findings-list">
    """
    
    # Findings-ները ցուցադրում
    for finding in findings[:8]:  # Միայն առաջին 8-ը
        html += f'<div class="small mb-1">{finding}</div>'
    
    if len(findings) > 8:
        html += f'<div class="small text-light">... և ևս {len(findings) - 8} գործոն</div>'
    
    html += """
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-4">
                            <div class="border-start ps-3">
    """
    
    # SSL տեղեկություններ
    if ssl_info.get('valid'):
        ssl_days = ssl_info.get('days_until_expiry', 0)
        ssl_color = 'success' if ssl_days > 30 else 'warning' if ssl_days > 0 else 'danger'
        html += f"""
                                <div class="mb-3">
                                    <small class="text-light d-block">SSL Կարգավիճակ</small>
                                    <span class="badge bg-{ssl_color}">Վավեր ({ssl_days} օր)</span>
                                </div>
        """
    elif ssl_info.get('error'):
        html += """
                                <div class="mb-3">
                                    <small class="text-light d-block">SSL Կարգավիճակ</small>
                                    <span class="badge bg-danger">Սխալ</span>
                                </div>
        """
    
    # Դոմենի տարիք
    if domain_info.get('age_days'):
        age_days = domain_info['age_days']
        age_color = 'success' if age_days > 365 else 'warning' if age_days > 90 else 'danger'
        html += f"""
                                <div class="mb-3">
                                    <small class="text-light d-block">Դոմենի Տարիք</small>
                                    <span class="badge bg-{age_color}">{age_days} օր</span>
                                </div>
        """
    
    # IP հասցեներ
    if technical_details.get('ip_addresses'):
        ip_count = len(technical_details['ip_addresses'])
        html += f"""
                                <div class="mb-3">
                                    <small class="text-light d-block">IP Հասցեներ</small>
                                    <span class="fw-bold text-primary">{ip_count}</span>
                                </div>
        """
    
    html += """
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Manual Review Notice -->
        <div class="col-12">
            <div class="alert alert-info border-0 bg-info bg-opacity-10">
                <div class="d-flex align-items-start">
                    <i class="fas fa-user-clock text-info me-3 mt-1"></i>
                    <div>
                        <h6 class="text-info mb-2">Մանուալ Ստուգում</h6>
                        <p class="mb-2 text-light">
                            Այս կայքը չի գտնվել մեր արտաքին ստուգիչների ցանկում (VirusTotal, Kaspersky): 
                            Մեր մասնագետները կանեն ձեռքով ստուգում և կտրամադրեն ճշգրիտ պատասխան:
                        </p>
                        <div class="row">
                            <div class="col-md-6">
                                <ul class="list-unstyled small text-light">
                                    <li><i class="fas fa-check text-success me-2"></i>Կպարզենք` արդյոք կայքը կեղծ է</li>
                                    <li><i class="fas fa-check text-success me-2"></i>Կստուգենք` արդյոք գողանում է տվյալներ</li>
                                    <li><i class="fas fa-check text-success me-2"></i>Կգնահատենք` անվտանգ է թե վտանգավոր</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-clock text-info me-2"></i>
                                    <strong class="text-info">Պատասխանը` 1-3 աշխատանքային օրվա ընթացքում</strong>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    """
    
    return html

def format_detailed_response(status, url, vt_result, kasp_result, safebrowsing_result=None, need_manual_review=False):
    """Ստեղծում է կոմպակտ և հասկանալի հայերեն պատասխան"""
    
    # Ստանդարտ պատասխանի կառուցվածք
    response_data = {
        'url': url,
        'overall_status': _determine_overall_status(status, vt_result, kasp_result, safebrowsing_result, need_manual_review),
        'security_score': _calculate_security_score(vt_result, kasp_result, safebrowsing_result),
        'external_checks': _format_external_checks(vt_result, kasp_result, safebrowsing_result),
        'internal_analysis': need_manual_review,  # Show manual review only if needed
        'recommendations': _generate_recommendations(status, need_manual_review),
        'summary': _create_summary(status, url, need_manual_review),
        'manual_review_required': need_manual_review,
        'review_message': "Այս URL-ը անհայտ է մեր արտաքին անվտանգության աղբյուրներում: Մեր անվտանգության թիմը կանցկացնի manual վերլուծություն 5 աշխատանքային օրվա ընթացքում: Արդյունքները կհրապարակվեն կայքի քարտեի էջում:" if need_manual_review else None
    }
    
    return _render_compact_html(response_data)

def _determine_overall_status(status, vt_result, kasp_result, safebrowsing_result=None, need_manual_review=False):
    """Որոշում է ընդհանուր կարգավիճակը"""
    # Առաջնություն արտաքին աղբյուրներին
    if vt_result and not vt_result.get('pending'):
        if vt_result.get('malicious', 0) > 0:
            return {'status': 'malicious', 'source': 'external', 'confidence': 'high'}
    
    if kasp_result and not kasp_result.get('pending'):
        if kasp_result.get('malicious', False):
            return {'status': 'malicious', 'source': 'external', 'confidence': 'high'}
    
    # Google Safe Browsing ստուգում
    if safebrowsing_result and not safebrowsing_result.get('pending'):
        if safebrowsing_result.get('malicious', False):
            return {'status': 'malicious', 'source': 'external', 'confidence': 'high'}
    
    # Եթե manual review է պահանջվում
    if need_manual_review:
        return {'status': 'pending', 'source': 'manual_review', 'confidence': 'low'}
    
    return {'status': status, 'source': 'external', 'confidence': 'medium'}

def _calculate_security_score(vt_result, kasp_result, safebrowsing_result=None):
    """Հաշվարկում է անվտանգության գնահատականը"""
    external_score = None
    scores = []
    
    # Արտաքին գնահատական - VirusTotal
    if vt_result and not vt_result.get('pending'):
        details = vt_result.get('details', {})
        total_engines = details.get('total_engines', 1)
        malicious = details.get('malicious', 0)
        if total_engines > 0:
            vt_score = max(0, 100 - int((malicious / total_engines) * 100))
            scores.append(vt_score)
    
    # Kaspersky-ի գնահատական
    if kasp_result and not kasp_result.get('pending'):
        kasp_score = 50  # Default
        if kasp_result.get('status') == 'malicious':
            kasp_score = 0
        elif kasp_result.get('status') == 'safe':
            kasp_score = 100
        elif kasp_result.get('status') == 'suspicious':
            kasp_score = 30
        scores.append(kasp_score)
    
    # Google Safe Browsing-ի գնահատական
    if safebrowsing_result and not safebrowsing_result.get('pending'):
        gsb_score = 50  # Default
        if safebrowsing_result.get('malicious', False):
            gsb_score = 0  # Վտանգավոր
        elif safebrowsing_result.get('status') == 'safe':
            gsb_score = 100  # Անվտանգ
        scores.append(gsb_score)
    
    # Միջին գնահատականի հաշվարկ
    if scores:
        external_score = sum(scores) // len(scores)
    
    return {
        'external': external_score,
        'combined': external_score if external_score is not None else 50
    }

def _format_external_checks(vt_result, kasp_result, safebrowsing_result=None):
    """Ձևավորում է արտաքին ստուգումների արդյունքները"""
    checks = {}
    
    # VirusTotal
    if vt_result and not vt_result.get('pending'):
        malicious = vt_result.get('details', {}).get('malicious', 0)
        total = vt_result.get('details', {}).get('total_engines', 0)
        
        # Կայքի ֆորմատ նստույց
        details_text = ""
        if malicious > 0:
            details_text = f"{malicious}/{total} ինժեներ հայտնաբերել են խնդիր"
            status = 'malicious'
        else:
            details_text = f"Ստուգված {total} ինժեներ - խնդիր չի հայտնաբերվել"
            status = 'safe'
            
        checks['virustotal'] = {
            'status': status,
            'details': details_text,
            'available': True,
            'data': vt_result  # Ամբողջ տվյալները
        }
    else:
        checks['virustotal'] = {
            'status': 'unknown',
            'details': 'Տվյալները հասանելի չեն',
            'available': False
        }
    
    # Kaspersky
    if kasp_result and not kasp_result.get('pending'):
        if kasp_result.get('malicious', False):
            checks['kaspersky'] = {
                'status': 'malicious',
                'details': 'Հայտնաբերվել է որպես վտանգավոր',
                'available': True,
                'data': kasp_result  # Ամբողջ տվյալները
            }
        else:
            checks['kaspersky'] = {
                'status': 'safe',
                'details': 'Վերլուծված և անվտանգ է',
                'available': True,
                'data': kasp_result  # Ամբողջ տվյալները
            }
    else:
        checks['kaspersky'] = {
            'status': 'unknown',
            'details': 'Տվյալները հասանելի չեն',
            'available': False
        }
    
    # Google Safe Browsing
    if safebrowsing_result and not safebrowsing_result.get('pending'):
        if safebrowsing_result.get('malicious', False):
            threat_desc = safebrowsing_result.get('threat_description', 'Վտանգավոր')
            checks['safebrowsing'] = {
                'status': 'malicious',
                'details': f'Հայտնաբերվել է {threat_desc}',
                'available': True,
                'data': safebrowsing_result
            }
        else:
            checks['safebrowsing'] = {
                'status': 'safe',
                'details': 'Google Safe Browsing-ը չի հայտնաբերել սպառնալիք',
                'available': True,
                'data': safebrowsing_result
            }
    else:
        checks['safebrowsing'] = {
            'status': 'unknown',
            'details': 'Տվյալները հասանելի չեն',
            'available': False
        }
    
    return checks

def _format_internal_analysis(internal_analysis):
    """Ձևավորում է ներքին վերլուծության արդյունքները"""
    if not internal_analysis:
        return {
            'available': False,
            'ssl_status': 'Տվյալներ չկան',
            'domain_age': 'Տվյալներ չկան',
            'security_headers': 'Տվյալներ չկան',
            'risk_factors': [],
            'positive_factors': []
        }
    
    return {
        'available': True,
        'ssl_status': _format_ssl_status(internal_analysis.get('ssl_info', {})),
        'domain_age': _format_domain_age(internal_analysis.get('domain_info', {})),
        'security_headers': _format_security_headers(internal_analysis.get('technical_details', {}).get('headers', {})),
        'risk_factors': _extract_risk_factors(internal_analysis.get('findings', [])),
        'positive_factors': _extract_positive_factors(internal_analysis.get('findings', []))
    }

def _extract_risk_factors(findings):
    """Հանում է ռիսկային գործոնները findings ցանկից"""
    risk_indicators = ['⚠️', '❌', '🚨', '🔴']
    risk_factors = []
    
    for finding in findings:
        if any(indicator in finding for indicator in risk_indicators):
            # Հեռացնում ենք emoji-ները և մաքրում ենք տեքստը
            clean_finding = finding
            for indicator in risk_indicators:
                clean_finding = clean_finding.replace(indicator, '').strip()
            risk_factors.append(clean_finding)
    
    return risk_factors[:5]  # Առաջին 5-ը

def _extract_positive_factors(findings):
    """Հանում է դրական գործոնները findings ցանկից"""
    positive_indicators = ['✅', '🟢', '💚']
    positive_factors = []
    
    for finding in findings:
        if any(indicator in finding for indicator in positive_indicators):
            # Հեռացնում ենք emoji-ները և մաքրում ենք տեքստը
            clean_finding = finding
            for indicator in positive_indicators:
                clean_finding = clean_finding.replace(indicator, '').strip()
            positive_factors.append(clean_finding)
    
    return positive_factors[:5]  # Առաջին 5-ը

def _format_ssl_status(ssl_info):
    """Ձևավորում է SSL կարգավիճակը"""
    if not ssl_info:
        return "Տվյալներ չկան"
    
    if ssl_info.get('valid'):
        days = ssl_info.get('days_until_expiry', 0)
        if days > 30:
            return f"Վավեր և անվտանգ ({days} օր մնացել է)"
        elif days > 0:
            return f"Վավեր, բայց շուտով կարժանցի ({days} օր)"
        else:
            return "Ժամկետանց վկայական"
    else:
        return "SSL վկայական չկա կամ սխալ է"

def _format_domain_age(domain_info):
    """Ձևավորում է դոմենի տարիքը"""
    if not domain_info or not domain_info.get('age_days'):
        return "Տվյալներ հասանելի չեն"
    
    days = domain_info['age_days']
    if days > 365:
        years = days // 365
        return f"Հին դոմեն ({years} տարի)"
    elif days > 30:
        months = days // 30
        return f"Միջին տարիքի դոմեն ({months} ամիս)"
    else:
        return f"Նոր դոմեն ({days} օր)"

def _format_security_headers(headers):
    """Ձևավորում է անվտանգության հեդերները"""
    if not headers:
        return "Տվյալներ չկան"
    
    security_count = sum(1 for key in ['strict-transport-security', 'content-security-policy', 'x-frame-options'] 
                        if key in headers)
    
    if security_count >= 2:
        return "Բարձր անվտանգության մակարդակ"
    elif security_count == 1:
        return "Միջին անվտանգության մակարդակ"
    else:
        return "Ցածր անվտանգության մակարդակ"
    
    # VirusTotal-ի հաշվարկ
    vt_available = vt_result and not vt_result.get('trusted', False)
    if vt_available:
        total_sources += 1
        vt_status = vt_result.get('status', 'pending')
        if vt_status == 'safe':
            safe_sources += 1
        elif vt_status == 'malicious':
            malicious_sources += 1
        elif vt_status == 'suspicious':
            suspicious_sources += 1
        else:
            pending_sources += 1
    
    # Kaspersky-ի հաշվարկ
    kasp_available = kasp_result and not kasp_result.get('trusted', False)
    if kasp_available:
        total_sources += 1
        kasp_status = kasp_result.get('status', 'pending')
        if kasp_status == 'safe':
            safe_sources += 1
        elif kasp_status == 'malicious':
            malicious_sources += 1
        elif kasp_status == 'suspicious':
            suspicious_sources += 1
        else:
            pending_sources += 1
    
    # Վստահելի դոմենի հաշվարկ
    is_trusted = vt_result.get('trusted', False) or kasp_result.get('trusted', False)
    if is_trusted:
        total_sources += 1
        safe_sources += 1
    
    # HTML ձևաչափով ստեղծում ենք մանրամասն պատասխանը
    result_html = f"""
    <div class="url-analysis-result">
        <!-- Status Header -->
        <div class="alert alert-{config['color']} border-0" role="alert">
            <div class="d-flex align-items-center">
                <div class="me-3 text-center">
                    <div class="rounded-circle bg-white d-inline-flex align-items-center justify-content-center" style="width: 60px; height: 60px;">
                        <i class="fas {config['icon']} fa-2x text-{config['color']}"></i>
                    </div>
                </div>
                <div class="flex-grow-1">
                    <h5 class="alert-heading mb-1">
                        {config['emoji']} URL Անվտանգության Վերլուծություն
                    </h5>
                    <p class="mb-1">
                        <strong>Կարգավիճակ:</strong> 
                        <span class="badge bg-{config['color']} fs-6 ms-1">{status_text}</span>
                    </p>
                    <small class="text-light">
                        <i class="fas fa-globe me-1"></i>
                        <code class="text-dark bg-light px-2 py-1 rounded">{url}</code>
                    </small>
                </div>
            </div>
        </div>
        
        <!-- Overall Statistics -->
        <div class="row g-3 mb-4">
            <div class="col-md-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-light text-dark">
                        <h6 class="mb-0 text-dark"><i class="fas fa-chart-pie me-2"></i>Ընդհանուր Վիճակագրություն</h6>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-3">
                                <div class="text-success fw-bold fs-4">{safe_sources}</div>
                                <small class="text-light">Անվտանգ</small>
                            </div>
                            <div class="col-3">
                                <div class="text-danger fw-bold fs-4">{malicious_sources}</div>
                                <small class="text-light">Վտանգավոր</small>
                            </div>
                            <div class="col-3">
                                <div class="text-warning fw-bold fs-4">{suspicious_sources}</div>
                                <small class="text-light">Կասկածելի</small>
                            </div>
                            <div class="col-3">
                                <div class="text-info fw-bold fs-4">{pending_sources}</div>
                                <small class="text-light">Սպասում</small>
                            </div>
                        </div>
                        <div class="mt-3">
                            <small class="text-light d-block text-center">
                                Ընդհանուր {total_sources} աղբյուր ստուգված
                            </small>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-light text-dark">
                        <h6 class="mb-0 text-dark"><i class="fas fa-chart-donut me-2"></i>Անվտանգության Բաշխում</h6>
                    </div>
                    <div class="card-body text-center">
                        <canvas id="securityChart" width="200" height="200" style="max-width: 200px; max-height: 200px;"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Analysis Details Cards -->
        <div class="row g-3 mb-4">
    """
    
    # Եթե API-ները չեն գտել URL-ը կամ pending են, ցուցադրում ենք ներքին վերլուծությունը
    # Բայց ոչ վտանգավոր կարգավիճակի դեպքում
    if status == 'pending' and (not vt_result or vt_result.get('pending')) and (not kasp_result or kasp_result.get('pending')):
        try:
            # Ստանում ենք ներքին վերլուծությունը
            analysis_details = get_detailed_analysis(url, vt_result, kasp_result)
            if analysis_details.get('analysis_type') == 'internal':
                internal_analysis = analysis_details.get('internal_analysis')
                if internal_analysis:
                    result_html += format_internal_analysis_html(internal_analysis)
        except Exception as e:
            print(f"Error adding internal analysis to HTML: {str(e)}")
    
    # API արդյունքների ցուցադրում (եթե կան)
    
    # VirusTotal արդյունքներ - միայն եթե հասանելի է
    if vt_available and not vt_result.get('pending'):
        vt_details = vt_result.get('details', {})
        if vt_details:
            malicious = vt_details.get('malicious', 0)
            suspicious = vt_details.get('suspicious', 0) 
            harmless = vt_details.get('harmless', 0)
            undetected = vt_details.get('undetected', 0)
            total = malicious + suspicious + harmless + undetected
            reputation = vt_details.get('reputation', 0)
            scan_date = vt_details.get('scan_date', 'Անհայտ')[:16]
            domain_info = vt_details.get('domain_info', {})
            
            # Գծապատկեր՝ անվտանգության մակարդակի համար
            safe_percent = round(((harmless + undetected) / total * 100) if total > 0 else 0)
            
            vt_color = 'success' if malicious == 0 else ('danger' if malicious > 2 else 'warning')
            
            result_html += f"""
                <div class="col-lg-12">
                    <div class="card border-{vt_color} border-opacity-25 shadow-sm mb-3">
                        <div class="card-header bg-{vt_color} bg-opacity-10">
                            <div class="d-flex align-items-center justify-content-between">
                                <div class="d-flex align-items-center">
                                    <i class="fas fa-virus me-2 text-{vt_color}"></i>
                                    <strong class="text-{vt_color}">VirusTotal Մանրամասն Վերլուծություն</strong>
                                </div>
                                <span class="badge bg-{vt_color}">Ակտիվ</span>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-8">
                                    <div class="row text-center mb-3">
                                        <div class="col-3">
                                            <div class="text-danger fw-bold fs-3">{malicious}</div>
                                            <small class="text-muted">Վտանգավոր</small>
                                        </div>
                                        <div class="col-3">
                                            <div class="text-warning fw-bold fs-3">{suspicious}</div>
                                            <small class="text-muted">Կասկածելի</small>
                                        </div>
                                        <div class="col-3">
                                            <div class="text-success fw-bold fs-3">{harmless}</div>
                                            <small class="text-muted">Անվնաս</small>
                                        </div>
                                        <div class="col-3">
                                            <div class="text-secondary fw-bold fs-3">{undetected}</div>
                                            <small class="text-muted">Չհայտնաբերված</small>
                                        </div>
                                    </div>
                                    
                                    <!-- Progress Bar -->
                                    <div class="mb-3">
                                        <div class="d-flex justify-content-between align-items-center mb-1">
                                            <small class="text-muted">Անվտանգության մակարդակ</small>
                                            <small class="fw-bold text-{vt_color}">{safe_percent}%</small>
                                        </div>
                                        <div class="progress" style="height: 10px;">
                                            <div class="progress-bar bg-{vt_color}" style="width: {safe_percent}%"></div>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="col-md-4">
                                    <div class="border-start ps-3">
                                        <div class="row text-center mb-3">
                                            <div class="col-6">
                                                <small class="text-muted d-block">Համբավ</small>
                                                <span class="badge bg-{'success' if reputation >= 0 else 'danger'} fs-6">{reputation}</span>
                                            </div>
                                            <div class="col-6">
                                                <small class="text-muted d-block">Ընդհանուր</small>
                                                <span class="fw-bold text-primary fs-6">{total}</span>
                                            </div>
                                        </div>
                                        <div class="text-center">
                                            <small class="text-muted">
                                                <i class="fas fa-calendar me-1"></i>
                                                {scan_date}
                                            </small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            """
            
            # Դոմենի տեղեկություններ (եթե կան)
            if domain_info and domain_info.get('whois_available'):
                result_html += f"""
                    <div class="col-12">
                        <div class="card border-info border-opacity-25 shadow-sm mb-3">
                            <div class="card-header bg-info bg-opacity-10 d-flex align-items-center">
                                <i class="fas fa-globe me-2 text-info"></i>
                                <strong class="text-info">Դոմենի WHOIS Տեղեկություններ</strong>
                            </div>
                            <div class="card-body">
                                <div class="row g-3 text-center">
                """
                
                if domain_info.get('registrar'):
                    result_html += f"""
                                    <div class="col-md-4">
                                        <div class="border rounded p-3">
                                            <i class="fas fa-building text-primary fa-2x mb-2"></i>
                                            <div class="small text-muted">Գրանցիչ</div>
                                            <div class="fw-bold">{domain_info['registrar']}</div>
                                        </div>
                                    </div>
                    """
                
                if domain_info.get('creation_date'):
                    creation_date = domain_info['creation_date'][:10]
                    result_html += f"""
                                    <div class="col-md-4">
                                        <div class="border rounded p-3">
                                            <i class="fas fa-calendar-plus text-success fa-2x mb-2"></i>
                                            <div class="small text-muted">Ստեղծման ամսաթիվ</div>
                                            <div class="fw-bold">{creation_date}</div>
                                        </div>
                                    </div>
                    """
                
                if domain_info.get('expiry_date'):
                    expiry_date = domain_info['expiry_date'][:10]
                    result_html += f"""
                                    <div class="col-md-4">
                                        <div class="border rounded p-3">
                                            <i class="fas fa-calendar-times text-warning fa-2x mb-2"></i>
                                            <div class="small text-muted">Ավարտման ամսաթիվ</div>
                                            <div class="fw-bold">{expiry_date}</div>
                                        </div>
                                    </div>
                    """
                
                result_html += """
                                </div>
                            </div>
                        </div>
                    </div>
                """
    
    # Kaspersky արդյունքներ - միայն եթե հասանելի է
    if kasp_available and not kasp_result.get('pending'):
        verdict = kasp_result.get('verdict', 'անհայտ')
        confidence = kasp_result.get('confidence', 'միջին')
        zone = kasp_result.get('zone', '')
        categories = kasp_result.get('categories', [])
        threat_types = kasp_result.get('threat_types', [])
        detection_time = kasp_result.get('detection_time', '')
        
        kasp_color = 'success' if verdict.lower() in ['clean', 'safe'] else ('danger' if verdict.lower() in ['malicious', 'phishing'] else 'warning')
        
        # Confidence մակարդակի բարձություն
        conf_percent = {'high': 100, 'medium': 70, 'low': 40}.get(confidence, 50)
        
        result_html += f"""
            <div class="col-lg-12">
                <div class="card border-{kasp_color} border-opacity-25 shadow-sm mb-3">
                    <div class="card-header bg-{kasp_color} bg-opacity-10">
                        <div class="d-flex align-items-center justify-content-between">
                            <div class="d-flex align-items-center">
                                <i class="fas fa-shield-virus me-2 text-{kasp_color}"></i>
                                <strong class="text-{kasp_color}">Kaspersky OpenTIP Վերլուծություն</strong>
                            </div>
                            <span class="badge bg-{kasp_color}">Ակտիվ</span>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="text-center mb-3">
                                    <div class="rounded-circle bg-{kasp_color} bg-opacity-10 d-inline-flex align-items-center justify-content-center mb-3" style="width: 80px; height: 80px;">
                                        <i class="fas fa-certificate text-{kasp_color} fa-2x"></i>
                                    </div>
                                    <div>
                                        <span class="badge bg-{kasp_color} fs-5 px-3 py-2">{verdict.title()}</span>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <small class="text-muted d-block text-center mb-1">Վստահության մակարդակ</small>
                                    <div class="progress mx-auto" style="height: 8px; width: 80%;">
                                        <div class="progress-bar bg-{kasp_color}" style="width: {conf_percent}%"></div>
                                    </div>
                                    <small class="text-{kasp_color} fw-bold d-block text-center mt-1">{confidence.title()}</small>
                                </div>
                            </div>
                            
                            <div class="col-md-6">
                                <div class="border-start ps-3">
        """
        
        if zone:
            result_html += f"""
                                    <div class="mb-3">
                                        <small class="text-muted d-block">Գոտակարգ</small>
                                        <span class="badge bg-secondary">{zone}</span>
                                    </div>
            """
        
        if categories:
            categories_text = ', '.join(categories[:3])
            if len(categories) > 3:
                categories_text += f" +{len(categories) - 3}"
            result_html += f"""
                                    <div class="mb-3">
                                        <small class="text-muted d-block">Կատեգորիաներ</small>
                                        <div class="fw-bold small">{categories_text}</div>
                                    </div>
            """
        
        if threat_types:
            threats_text = ', '.join(threat_types[:2])
            result_html += f"""
                                    <div class="mb-3">
                                        <small class="text-muted d-block">Սպառնալիքի տեսակ</small>
                                        <span class="badge bg-warning">{threats_text}</span>
                                    </div>
            """
        
        if detection_time:
            result_html += f"""
                                    <div class="mb-2">
                                        <small class="text-muted d-block">Հայտնաբերման ժամ</small>
                                        <small class="fw-bold">{detection_time[:16]}</small>
                                    </div>
            """
        
        result_html += """
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        """
    
    # Վստահելի դոմենների մասին
    if is_trusted:
        result_html += f"""
            <div class="col-12">
                <div class="card border-success border-2 shadow-sm mb-3">
                    <div class="card-header bg-success bg-opacity-10 d-flex align-items-center justify-content-between">
                        <div class="d-flex align-items-center">
                            <i class="fas fa-certificate me-2 text-success"></i>
                            <strong class="text-success">Վստահելի Դոմեն</strong>
                        </div>
                        <span class="badge bg-success">Վավերացված</span>
                    </div>
                    <div class="card-body">
                        <div class="d-flex align-items-center">
                            <div class="rounded-circle bg-success bg-opacity-10 d-inline-flex align-items-center justify-content-center me-3" style="width: 50px; height: 50px;">
                                <i class="fas fa-check-double text-success fa-lg"></i>
                            </div>
                            <div>
                                <h6 class="mb-1 text-success">Նախապես Վավերացված Դոմեն</h6>
                                <small class="text-muted">
                                    Այս դոմենը գտնվում է մեր վստահելի դոմենների ցուցակում և լրացուցիչ ստուգում չի պահանջվում
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        """
    
    result_html += """
        </div>
        
        <!-- Recommendations Section -->
        <div class="recommendations mb-4">
            <div class="card border-0 shadow-sm">
                <div class="card-header bg-light text-dark">
                    <h6 class="mb-0 text-dark">
                        <i class="fas fa-lightbulb me-2"></i>Մեր Առաջարկությունները
                    </h6>
                </div>
                <div class="card-body">
    """
    
    # Կարգավիճակ-հատուկ առաջարկություններ
    if status == 'safe':
        result_html += f"""
                    <div class="alert alert-success border-0 bg-success bg-opacity-10">
                        <div class="d-flex align-items-start">
                            <i class="fas fa-check-circle text-success me-3 mt-1"></i>
                            <div>
                                <h6 class="text-success mb-2">Անվտանգ է այցելել</h6>
                                <ul class="mb-0 text-muted">
                                    <li>Կայքը գնահատվել է որպես անվտանգ մեր բոլոր ստուգումներով</li>
                                    <li>Դեռևս խորհուրդ է տրվում զգույշ լինել անձնական տվյալների հետ</li>
                                    <li>Վստահ եղեք, որ URL-ը ճշգրիտ է և չունի տառային սխալներ</li>
                                    <li>Օգտագործեք HTTPS կապ, երբ հնարավոր է</li>
                                </ul>
                            </div>
                        </div>
                    </div>
        """
    elif status == 'malicious':
        result_html += f"""
                    <div class="alert alert-danger border-0 bg-danger bg-opacity-10">
                        <div class="d-flex align-items-start">
                            <i class="fas fa-ban text-danger me-3 mt-1"></i>
                            <div>
                                <h6 class="text-danger mb-2">ԽԻՍՏ ԽՈՒՍԱՓԵՔ այս կայքից</h6>
                                <ul class="mb-0 text-muted">
                                    <li><strong>Այս կայքը բնութագրվել է որպես վտանգավոր</strong></li>
                                    <li>Կարող է պարունակել վիրուսներ կամ փորձել գողանալ տվյալներ</li>
                                    <li>Եթե արդեն այցելել եք, անմիջապես փակեք բրաուզերը</li>
                                    <li>Ստուգեք համակարգչի անվտանգությունը հակավիրուսային ծրագրով</li>
                                    <li>Փոխեք գաղտնաբառերը, եթե մուտքագրել եք</li>
                                </ul>
                            </div>
                        </div>
                    </div>
        """
    elif status == 'suspicious':
        result_html += f"""
                    <div class="alert alert-warning border-0 bg-warning bg-opacity-10">
                        <div class="d-flex align-items-start">
                            <i class="fas fa-exclamation-triangle text-warning me-3 mt-1"></i>
                            <div>
                                <h6 class="text-warning mb-2">Զգույշ եղեք այս կայքի հետ</h6>
                                <ul class="mb-0 text-muted">
                                    <li>Կարող է պարունակել կասկածելի կամ անհուսալի բովանդակություն</li>
                                    <li>Մի տվեք անձնական տվյալներ (գաղտնաբառեր, քարտի տվյալներ)</li>
                                    <li>Ստուգեք URL-ի ճշտությունը շրջանցիկ տառերի համար</li>
                                    <li>Խորհրդակցեք IT մասնագետի կամ ցանցային ադմինիստրատորի հետ</li>
                                    <li>Օգտագործեք VPN կամ անվտանգ զննարկիչ</li>
                                </ul>
                            </div>
                        </div>
                    </div>
        """
    else:  # pending
        result_html += f"""
                    <div class="alert alert-info border-0 bg-info bg-opacity-10">
                        <div class="d-flex align-items-start">
                            <i class="fas fa-hourglass-half text-info me-3 mt-1"></i>
                            <div>
                                <h6 class="text-info mb-2">Սպասում է մանուալ ստուգման</h6>
                                <ul class="mb-0 text-muted">
                                    <li>Մեր մասնագետները կվերլուծեն այս URL-ը լրացուցիչ</li>
                                    <li>Արդյունքը կստանաք 24-48 ժամվա ընթացքում</li>
                                    <li>Այս ընթացքում խուսափեք այցելել այս կայք</li>
                                    <li>Արտակարգ դեպքերում կապվեք մեզ հետ</li>
                                </ul>
                            </div>
                        </div>
                    </div>
        """
    
    result_html += """
                </div>
            </div>
        </div>
        
        <!-- Technical Details Accordion -->
        <div class="accordion mb-4" id="technicalAccordion">
            <div class="accordion-item border-0 shadow-sm">
                <h2 class="accordion-header">
                    <button class="accordion-button collapsed bg-light text-dark" type="button" data-bs-toggle="collapse" data-bs-target="#technicalDetails">
                        <i class="fas fa-cogs me-2"></i>Տեխնիկական Մանրամասներ
                    </button>
                </h2>
                <div id="technicalDetails" class="accordion-collapse collapse" data-bs-parent="#technicalAccordion">
                    <div class="accordion-body bg-light text-dark">
    """
    
    # Տեխնիկական մանրամասներ
    analysis_details = get_detailed_analysis(url, vt_result, kasp_result)
    if analysis_details:
        suspicious_count = analysis_details.get('suspicious_patterns', 0)
        pattern_text = f"Կասկածելի օրինակներ: {suspicious_count}" if suspicious_count > 0 else "URL-ի կառուցվածքը նորմալ է"
        
        result_html += f"""
                        <div class="row g-3">
                            <div class="col-md-6">
                                <h6 class="text-secondary mb-2">🔍 URL Վերլուծություն</h6>
                                <small class="text-muted">{pattern_text}</small>
                            </div>
                            <div class="col-md-6">
                                <h6 class="text-secondary mb-2">📊 Ստուգման Աղբյուրներ</h6>
                                <div class="d-flex flex-wrap gap-1">
        """
        
        # Աղբյուրների տեսակները
        sources = []
        if vt_result and not vt_result.get('pending'):
            sources.append('<span class="badge bg-primary">VirusTotal</span>')
        if kasp_result and not kasp_result.get('pending'):
            sources.append('<span class="badge bg-info">Kaspersky</span>')
        if vt_result.get('trusted') or kasp_result.get('trusted'):
            sources.append('<span class="badge bg-success">Վստահելի Ցուցակ</span>')
            
        result_html += ' '.join(sources) if sources else '<span class="badge bg-secondary">Ներքին Վերլուծություն</span>'
        
        result_html += """
                                </div>
                            </div>
                        </div>
        """
    else:
        result_html += """
                        <p class="mb-0 text-muted">
                            <i class="fas fa-info-circle me-1"></i>
                            Տեխնիկական մանրամասները հասանելի չեն այս վերլուծության համար:
                        </p>
        """
    
    result_html += """
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="text-center pt-3 border-top">
            <small class="text-muted">
                <i class="fas fa-shield-alt text-primary me-1"></i>
                <strong>CyberAratta</strong> - Ձեր Թվային Անվտանգության Հուսալի Գործընկեր
            </small>
        </div>
    </div>
    """
    
    return result_html.strip()

def check_url_virustotal(url):
    """VirusTotal API-ի միջոցով URL ստուգում"""
    # Վստահելի դոմենների արագ ստուգում
    if is_trusted_domain(url):
        return {
            "malicious": False,
            "status": "safe",
            "details": {"trusted_domain": True, "harmless": 60, "undetected": 10},
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
                import base64
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
            from urllib.parse import urlparse
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

        # Վերջին վերլուծության ամսաթիվ
        import datetime
        if last_analysis_date:
            analysis_date = datetime.datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
        else:
            analysis_date = 'Անհայտ'

        if status == "completed":
            # Ավելի բարդ տրամաբանություն
            if malicious_count > 2:  # 3+ engines համարում են վտանգավոր
                verdict = "malicious"
                message = f"{malicious_count} անվտանգության լուծում հայտնաբերել է վտանգ"
            elif malicious_count > 0 or suspicious_count > 3:
                verdict = "suspicious" 
                message = f"Կասկածելի է ({malicious_count} վտանգավոր, {suspicious_count} կասկածելի)"
            elif total_engines > 40:  # Բավարար քանակությամբ engines ստուգել են
                verdict = "safe"
                message = f"{total_engines} սկաներից {harmless_count + undetected_count} հատը չի գտել սպառնալիք"
            else:
                verdict = "pending"
                message = "Անբավարար տվյալներ վերջնական գնահատականի համար"
                
            return {
                "malicious": malicious_count > 2,
                "status": verdict,
                "details": {
                    **stats,
                    'scan_date': analysis_date,
                    'reputation': reputation,
                    'total_engines': total_engines,
                    'title': title,
                    'categories': categories,
                    'times_submitted': times_submitted,
                    'final_url': last_final_url,
                    'http_response_code': http_response_code,
                    'content_length': content_length,
                    'community_votes': {
                        'harmless': harmless_votes,
                        'malicious': malicious_votes,
                        'total': harmless_votes + malicious_votes
                    },
                    'domain_info': domain_info
                },
                "message": message,
                "confidence": "high" if total_engines > 40 else "medium"
            }
            
        elif status in ["queued", "awaiting manual review"]:
            return {
                "malicious": False,
                "status": "pending",
                "details": stats,
                "message": "VirusTotal վերլուծությունը ընթացքի մեջ է",
                "pending": True
            }
        else:
            return {
                "malicious": False,
                "status": "pending",
                "details": stats,
                "message": f"VirusTotal վիճակ: {status}",
                "pending": True
            }

    except requests.RequestException as e:
        return {
            "malicious": False,
            "status": "pending",
            "details": {},
            "message": f"VirusTotal API սխալ: {str(e)[:100]}...",
            "pending": True
        }

def check_url_kaspersky(url):
    """Kaspersky OpenTIP API-ի միջոցով URL ստուգում"""
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
                "verdict": verdict or "unknown",
                "message": "Kaspersky-ում տվյալներ չկան, անհրաժեշտ է լրացուցիչ ստուգում",
                "pending": True,
                "raw": data
            }
            
    except requests.RequestException as e:
        return {
            "malicious": False,
            "status": "pending",
            "verdict": None,
            "message": f"Kaspersky API սխալ: {str(e)[:100]}...",
            "pending": True,
            "raw": {}
        }

def check_url_safebrowsing(url):
    """Google Safe Browsing API-ի միջոցով URL ստուգում"""
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
        
        # Check if any threats were found
        if "matches" in data and data["matches"]:
            # Threat detected
            match = data["matches"][0]  # Get first match
            threat_type = match.get("threatType", "UNKNOWN")
            platform_type = match.get("platformType", "ANY_PLATFORM")
            
            # Map threat types to Armenian
            threat_map = {
                "MALWARE": "Վիրուս/Վնասակար Ծրագիր",
                "SOCIAL_ENGINEERING": "Ֆիշինգ/Սոցիալական Ինժեներություն", 
                "UNWANTED_SOFTWARE": "Անցանկալի Ծրագիր",
                "POTENTIALLY_HARMFUL_APPLICATION": "Պոտենցիալ Վտանգավոր Ծրագիր"
            }
            
            threat_description = threat_map.get(threat_type, threat_type)
            
            return {
                "malicious": True,
                "status": "malicious",
                "verdict": "malicious",
                "threat_type": threat_type,
                "threat_description": threat_description,
                "platform_type": platform_type,
                "message": f"Google Safe Browsing-ը հայտնաբերել է {threat_description}",
                "confidence": "high",
                "raw": data
            }
        else:
            # No threats found
            return {
                "malicious": False,
                "status": "safe",
                "verdict": "clean",
                "message": "Google Safe Browsing-ը չի հայտնաբերել սպառնալիք",
                "confidence": "high",
                "raw": data
            }
            
    except requests.RequestException as e:
        return {
            "malicious": False,
            "status": "pending",
            "verdict": None,
            "message": f"Google Safe Browsing API սխալ: {str(e)[:100]}...",
            "pending": True,
            "raw": {}
        }

def _generate_recommendations(status, need_manual_review):
    """Ստեղծում է համապատասխան առաջարկություններ"""
    recommendations = []
    
    # Ընդհանուր առաջարկություններ ըստ կարգավիճակի
    if status in ['malicious', 'suspicious']:
        recommendations.append("🚫 Խուսափեք այցելել այս հղմամբ եթե վերլուծության արդյունքները կասկածելի կամ վտանգավոր են թվում")
    elif status == 'pending' and need_manual_review:
        recommendations.extend([
            "⏳ Սպասեք manual վերլուծության արդյունքներին",
            "⚠️ Խուսափեք այցելել մինչև վերլուծությունը",
            "� Ստուգեք նմանատիպ կայքերի վարկանիշը"
        ])
    else:
        recommendations.extend([
            "✅ Կայքը թվում է անվտանգ",
            "🔒 Միշտ ուշադրություն դարձրեք URL-ին"
        ])
    
    return recommendations
    
    # Լրացուցիչ առաջարկություններ ըստ ներքին վերլուծության - միայն կարևոր դեպքերում
    if internal_analysis and internal_analysis.get('available'):
        ssl_info = internal_analysis.get('ssl_info', {})
        # Ավելացնում ենք SSL առաջարկություն միայն եթե իրոք խնդիր կա
        if ssl_info and not ssl_info.get('valid'):
            recommendations.append("🔒 Այս կայքը չունի վավեր SSL վկայական")
        
        # Դոմենի տարիքի առաջարկություն միայն շատ նոր դոմենների համար
        domain_info = internal_analysis.get('domain_info', {})
        age_days = domain_info.get('age_days', 0) if domain_info else 0
        if age_days > 0 and age_days < 7:  # Միայն շատ նոր դոմենների համար
            recommendations.append("🆕 Շատ նոր դոմեն է (1 շաբաթից պակաս)")
    
    return recommendations[:4]  # Սահմանափակում ենք 4 առաջարկությամբ

def _create_summary(status, url, need_manual_review):
    """Ստեղծում է համառոտ ամփոփում"""
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    if status == 'malicious':
        return f"❌ {domain} դոմենը հայտնաբերվել է որպես վտանգավոր"
    elif status == 'suspicious':
        return f"⚠️ {domain} դոմենը պարունակում է կասկածելի տարրեր"
    elif status == 'pending' and need_manual_review:
        return f"⏳ {domain} դոմենը պահանջում է manual վերլուծություն"
    elif status == 'safe':
        return f"✅ {domain} դոմենը թվում է անվտանգ"
    else:
        return f"❓ {domain} դոմենի մասին բավարար տեղեկություններ չկան"

def _render_compact_html(data):
    """Ստեղծում է կոմպակտ HTML պատասխան"""
    
    # Ստանում ենք հիմնական տվյալները
    overall_status = data['overall_status']
    security_score = data['security_score']
    external_checks = data['external_checks']
    internal_analysis = data.get('internal_analysis')  # Can be None
    recommendations = data['recommendations']
    summary = data['summary']
    
    # Ստատուսի կոնֆիգուրացիա
    status_config = {
        'malicious': {'color': 'danger', 'icon': 'fa-exclamation-triangle', 'emoji': '🚨'},
        'suspicious': {'color': 'warning', 'icon': 'fa-exclamation-circle', 'emoji': '⚠️'},
        'pending': {'color': 'info', 'icon': 'fa-clock', 'emoji': '⏳'},
        'safe': {'color': 'success', 'icon': 'fa-shield-alt', 'emoji': '✅'},
        'unknown': {'color': 'secondary', 'icon': 'fa-question', 'emoji': '❓'}
    }
    
    config = status_config.get(overall_status['status'], status_config['unknown'])
    
    html = f"""
    <div class="security-analysis-result">
        <!-- Գլխավոր ամփոփում -->
        <div class="card border-0 shadow-sm mb-4" style="background-color: white;">
            <div class="card-body">
                <div class="row align-items-center">
                    <div class="col-auto">
                        <div class="rounded-circle bg-{config['color']} bg-opacity-10 d-flex align-items-center justify-content-center" 
                             style="width: 60px; height: 60px;">
                            <i class="fas {config['icon']} fa-2x text-{config['color']}"></i>
                        </div>
                    </div>
                    <div class="col">
                        <h5 class="mb-1" style="color: black;">{config['emoji']} {summary}</h5>
                        <p class="mb-2" style="color: black;">
                            <strong>URL:</strong> 
                            <code class="text-dark bg-light px-2 py-1 rounded">{data['url']}</code>
                        </p>
                        <div class="d-flex align-items-center gap-3">
                            <span class="badge bg-{config['color']} fs-6">
                                {_get_status_text(overall_status['status'])}
                            </span>
                            {_render_confidence_badge(overall_status['confidence'])}
                            {_render_score_badge(security_score['combined'])}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Արտաքին ստուգումներ -->
        <div class="row g-3 mb-4">
            <div class="col-12">
                {_render_external_checks_card(external_checks)}
            </div>
        </div>
        
        <!-- Առաջարկություններ -->
        <div class="card border-0 shadow-sm" style="background-color: white;">
            <div class="card-header bg-light text-dark">
                <h6 class="mb-0 text-dark">
                    <i class="fas fa-lightbulb me-2"></i>Առաջարկություններ
                </h6>
            </div>
            <div class="card-body">
                <div class="row">
                    {"".join(f'<div class="col-md-6 mb-2"><small style="color: black;">• {rec}</small></div>' for rec in recommendations)}
                </div>
            </div>
        </div>
    </div>
    """
    
    return html.strip()

def _get_status_text(status):
    """Վերադարձնում է ստատուսի հայերեն տեքստը"""
    status_texts = {
        'malicious': 'Վտանգավոր',
        'suspicious': 'Կասկածելի', 
        'caution': 'Զգուշություն',
        'safe': 'Անվտանգ',
        'unknown': 'Անհայտ'
    }
    return status_texts.get(status, 'Անհայտ')

def _render_confidence_badge(confidence):
    """Ստեղծում է վստահության մակարդակի նշան"""
    confidence_config = {
        'high': {'color': 'success', 'text': 'Բարձր վստահություն'},
        'medium': {'color': 'warning', 'text': 'Միջին վստահություն'},
        'low': {'color': 'secondary', 'text': 'Ցածր վստահություն'}
    }
    
    config = confidence_config.get(confidence, confidence_config['low'])
    return f'<span class="badge bg-{config["color"]} fs-6">{config["text"]}</span>'

def _render_score_badge(score):
    """Ստեղծում է գնահատականի նշան"""
    if score is None:
        return '<span class="badge bg-secondary fs-6">Գնահատական չկա</span>'
    
    if score >= 80:
        color = 'success'
    elif score >= 60:
        color = 'warning'
    else:
        color = 'danger'
    
    return f'<span class="badge bg-{color} fs-6">Գնահատական: {score:.0f}%</span>'

def _render_external_checks_card(external_checks):
    """Ստեղծում է արտաքին ստուգումների քարտը"""
    html = """
    <div class="card border-0 shadow-sm" style="background-color: white;">
        <div class="card-header" style="background-color: #f8f9fa; color: black;">
            <h6 class="mb-0" style="color: black;">
                <i class="fas fa-globe me-2"></i>Արտաքին Ստուգումներ
            </h6>
        </div>
        <div class="card-body" style="background-color: white;">
    """
    
    for source, data in external_checks.items():
        source_name = {
            'virustotal': 'VirusTotal',
            'kaspersky': 'Kaspersky',
            'safebrowsing': 'Google Safe Browsing'
        }.get(source, source.title())
        
        if data['available']:
            status_icon = '✅' if data['status'] == 'safe' else '❌' if data['status'] == 'malicious' else '❓'
            
            # VirusTotal-ի մանրամասն տվյալները
            if source == 'virustotal' and 'data' in data:
                vt_data = data['data']
                details = vt_data.get('details', {})
                
                html += f"""
                <div class="border rounded p-3 mb-3" style="background-color: #f8f9fa;">
                    <div class="d-flex align-items-center mb-2">
                        <span class="fs-4 me-3">{status_icon}</span>
                        <div>
                            <strong style="color: black;">{source_name}</strong>
                            <span class="badge bg-primary ms-2">{details.get('total_engines', 0)} engines</span>
                        </div>
                    </div>
                    
                    <div class="row mb-2">
                        <div class="col-6">
                            <small style="color: #666;">Վտանգավոր: <span class="text-danger fw-bold">{details.get('malicious', 0)}</span></small>
                        </div>
                        <div class="col-6">
                            <small style="color: #666;">Կասկածելի: <span class="text-warning fw-bold">{details.get('suspicious', 0)}</span></small>
                        </div>
                    </div>
                    
                    <div class="row mb-2">
                        <div class="col-6">
                            <small style="color: #666;">Անվտանգ: <span class="text-success fw-bold">{details.get('harmless', 0)}</span></small>
                        </div>
                        <div class="col-6">
                            <small style="color: #666;">Չհայտնաբերված: <span class="text-secondary fw-bold">{details.get('undetected', 0)}</span></small>
                        </div>
                    </div>
                """
                
                # Կայքի վերնագիր
                if details.get('title'):
                    html += f"""
                    <div class="mb-2">
                        <small style="color: #666;">Վերնագիր: <span style="color: black;">{details.get('title')[:100]}...</span></small>
                    </div>
                    """
                
                # HTTP ստատուս
                if details.get('http_response_code'):
                    http_color = 'success' if str(details.get('http_response_code')).startswith('2') else 'warning'
                    html += f"""
                    <div class="mb-2">
                        <small style="color: #666;">HTTP Status: <span class="badge bg-{http_color}">{details.get('http_response_code')}</span></small>
                    </div>
                    """
                
                # Community votes
                votes = details.get('community_votes', {})
                if votes.get('total', 0) > 0:
                    html += f"""
                    <div class="mb-2">
                        <small style="color: #666;">Համայնքի գնահատական: 
                            <span class="text-success">{votes.get('harmless', 0)} 👍</span> / 
                            <span class="text-danger">{votes.get('malicious', 0)} 👎</span>
                        </small>
                    </div>
                    """
                
                # Ստուգման ամսաթիվ
                if details.get('scan_date') and details.get('scan_date') != 'Անհայտ':
                    html += f"""
                    <div class="mb-2">
                        <small style="color: #666;">Վերջին ստուգում: <span style="color: black;">{details.get('scan_date')}</span></small>
                    </div>
                    """
                    
                html += "</div>"
                
            # Kaspersky-ի մանրամասն տվյալները  
            elif source == 'kaspersky' and 'data' in data:
                kasp_data = data['data']
                
                html += f"""
                <div class="border rounded p-3 mb-3" style="background-color: #f8f9fa;">
                    <div class="d-flex align-items-center mb-2">
                        <span class="fs-4 me-3">{status_icon}</span>
                        <div>
                            <strong style="color: black;">{source_name}</strong>
                            <span class="badge bg-success ms-2">OpenTIP</span>
                        </div>
                    </div>
                    
                    <div class="mb-2">
                        <small style="color: #666;">Գնահատական: <span class="fw-bold" style="color: black;">{kasp_data.get('verdict', 'Unknown').title()}</span></small>
                    </div>
                    
                    <div class="mb-2">
                        <small style="color: #666;">{kasp_data.get('message', data['details'])}</small>
                    </div>
                </div>
                """
                
            # Google Safe Browsing-ի մանրամասն տվյալները
            elif source == 'safebrowsing' and 'data' in data:
                gsb_data = data['data']
                
                html += f"""
                <div class="border rounded p-3 mb-3" style="background-color: #f8f9fa;">
                    <div class="d-flex align-items-center mb-2">
                        <span class="fs-4 me-3">{status_icon}</span>
                        <div>
                            <strong style="color: black;">{source_name}</strong>
                            <span class="badge bg-info ms-2">Safe Browsing</span>
                        </div>
                    </div>
                    
                    <div class="mb-2">
                        <small style="color: #666;">Գնահատական: <span class="fw-bold" style="color: black;">{gsb_data.get('verdict', 'Unknown').title()}</span></small>
                    </div>
                    
                    <div class="mb-2">
                        <small style="color: #666;">{gsb_data.get('message', data['details'])}</small>
                    </div>
                    
                    {f'<div class="mb-2"><small style="color: #666;">Սպառնալիքի տեսակ: <span class="badge bg-warning">{gsb_data.get("threat_description", "Unknown")}</span></small></div>' if gsb_data.get('threat_description') else ''}
                </div>
                """
            else:
                # Հին ֆորմատ
                html += f"""
                <div class="d-flex align-items-center mb-3">
                    <div class="me-3">
                        <span class="fs-4">{status_icon}</span>
                    </div>
                    <div>
                        <strong style="color: black;">{source_name}</strong>
                        <br>
                        <small style="color: #666;">{data['details']}</small>
                    </div>
                </div>
                """
        else:
            html += f"""
            <div class="d-flex align-items-center mb-3">
                <div class="me-3">
                    <span class="fs-4">⏳</span>
                </div>
                <div>
                    <strong style="color: black;">{source_name}</strong>
                    <br>
                    <small style="color: #666;">{data['details']}</small>
                </div>
            </div>
            """
    
    html += """
        </div>
    </div>
    """
    
    return html

def _render_internal_analysis_card(internal_analysis):
    """Ստեղծում է ներքին վերլուծության քարտը"""
    if not internal_analysis:
        return ""  # Don't show anything if no internal analysis needed
    
    html = """
    <div class="card border-0 shadow-sm" style="background-color: white;">
        <div class="card-header bg-light text-dark">
            <h6 class="mb-0 text-dark">
                <i class="fas fa-info-circle me-2"></i>Manual Review
            </h6>
        </div>
        <div class="card-body">
            <div class="text-center py-3">
                <i class="fas fa-clock fa-2x text-info mb-3"></i>
                <p class="mb-0" style="color: black;">Manual վերլուծություն կանցկացվի 5 աշխատանքային օրվա ընթացքում</p>
            </div>
        </div>
    </div>
    """
    
    return html