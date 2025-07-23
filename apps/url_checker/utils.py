import requests
from decouple import config
import time
import re
from urllib.parse import urlparse
import json

VIRUSTOTAL_API_KEY = config("VIRUSTOTAL_API_KEY")
KASPERSKY_API_KEY = config("KASPERSKY_API_KEY")

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

def get_detailed_analysis(url, vt_result, kasp_result):
    """Ստեղծում է մանրամասն վերլուծություն"""
    analysis = {
        'url': url,
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

def format_detailed_response(status, url, vt_result, kasp_result):
    """Ստեղծում է մանրամասն հայերեն պատասխան Bootstrap-ի HTML ձևաչափով"""
    
    # Հիմնական կարգավիճակի նկարագրություն
    status_descriptions = {
        'safe': 'Անվտանգ',
        'malicious': 'Վտանգավոր', 
        'suspicious': 'Կասկածելի',
        'pending': 'Սպասում է ստուգման'
    }
    
    status_text = status_descriptions.get(status, 'Անհայտ')
    
    # Վիզուալ ցուցիչներ և գույներ
    status_configs = {
        'safe': {'icon': 'fa-shield-alt', 'color': 'success', 'bg': 'success', 'emoji': '✅'},
        'malicious': {'icon': 'fa-exclamation-triangle', 'color': 'danger', 'bg': 'danger', 'emoji': '🚨'},
        'suspicious': {'icon': 'fa-exclamation-circle', 'color': 'warning', 'bg': 'warning', 'emoji': '⚠️'},
        'pending': {'icon': 'fa-clock', 'color': 'info', 'bg': 'info', 'emoji': '⏳'}
    }
    
    config = status_configs.get(status, {'icon': 'fa-question', 'color': 'secondary', 'bg': 'secondary', 'emoji': '❓'})
    
    # Ընդհանուր վիճակագրություններ
    total_sources = 0
    safe_sources = 0
    malicious_sources = 0
    suspicious_sources = 0
    pending_sources = 0
    
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
                    <small class="text-muted">
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
                    <div class="card-header bg-light">
                        <h6 class="mb-0"><i class="fas fa-chart-pie me-2"></i>Ընդհանուր Վիճակագրություն</h6>
                    </div>
                    <div class="card-body">
                        <div class="row text-center">
                            <div class="col-3">
                                <div class="text-success fw-bold fs-4">{safe_sources}</div>
                                <small class="text-muted">Անվտանգ</small>
                            </div>
                            <div class="col-3">
                                <div class="text-danger fw-bold fs-4">{malicious_sources}</div>
                                <small class="text-muted">Վտանգավոր</small>
                            </div>
                            <div class="col-3">
                                <div class="text-warning fw-bold fs-4">{suspicious_sources}</div>
                                <small class="text-muted">Կասկածելի</small>
                            </div>
                            <div class="col-3">
                                <div class="text-info fw-bold fs-4">{pending_sources}</div>
                                <small class="text-muted">Սպասում</small>
                            </div>
                        </div>
                        <div class="mt-3">
                            <small class="text-muted d-block text-center">
                                Ընդհանուր {total_sources} աղբյուր ստուգված
                            </small>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-light">
                        <h6 class="mb-0"><i class="fas fa-chart-donut me-2"></i>Անվտանգության Բաշխում</h6>
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
                <div class="card-header bg-light">
                    <h6 class="mb-0 text-secondary">
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
                    <button class="accordion-button collapsed bg-light" type="button" data-bs-toggle="collapse" data-bs-target="#technicalDetails">
                        <i class="fas fa-cogs me-2"></i>Տեխնիկական Մանրամասներ
                    </button>
                </h2>
                <div id="technicalDetails" class="accordion-collapse collapse" data-bs-parent="#technicalAccordion">
                    <div class="accordion-body bg-light">
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
        
        # Լրացուցիչ մանրամասներ VirusTotal-ից
        attributes = result.get('data', {}).get('attributes', {})
        url_info = attributes.get('url', '')
        last_analysis_date = attributes.get('last_analysis_date', 0)
        reputation = attributes.get('reputation', 0)
        
        # Domain տեղեկություններ (եթե URL-ը կարող ենք վերլուծել)
        domain_info = {}
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # WHOIS տեղեկություններ VirusTotal-ից (եթե կան)
            whois_data = attributes.get('whois', '')
            if whois_data:
                domain_info['whois_available'] = True
                # Փորձում ենք գտնել registrar
                import re
                registrar_match = re.search(r'Registrar:\s*(.+)', whois_data, re.IGNORECASE)
                if registrar_match:
                    domain_info['registrar'] = registrar_match.group(1).strip()
                
                # Creation date
                creation_match = re.search(r'Creation Date:\s*(.+)', whois_data, re.IGNORECASE)
                if not creation_match:
                    creation_match = re.search(r'Created On:\s*(.+)', whois_data, re.IGNORECASE)
                if creation_match:
                    domain_info['creation_date'] = creation_match.group(1).strip()
                    
                # Expiration date
                expiry_match = re.search(r'Registry Expiry Date:\s*(.+)', whois_data, re.IGNORECASE)
                if not expiry_match:
                    expiry_match = re.search(r'Expiration Date:\s*(.+)', whois_data, re.IGNORECASE)
                if expiry_match:
                    domain_info['expiry_date'] = expiry_match.group(1).strip()
                    
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
                    'url_info': url_info,
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