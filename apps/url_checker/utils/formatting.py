"""
HTML Formatting Module

Այս մոդուլը պարունակում է URL ստուգման արդյունքների HTML ձևավորման ֆունկցիաներ:
"""

from django.utils.safestring import mark_safe
from django.utils.html import escape


def format_scan_result_html(result, integration_name):
    """
    Ստուգման արդյունքների ձևավորում HTML ձևաչափով
    
    Args:
        result (dict): Ստուգման արդյունքների տվյալներ
        integration_name (str): Ինտեգրացիայի անունը (օր․ 'VirusTotal', 'Kaspersky', 'SafeBrowsing')
        
    Returns:
        str: HTML ձևաչափով ձևավորված արդյունք
    """
    status = result.get('status', 'pending')
    
    if status == 'pending':
        return format_pending_result(integration_name)
    
    # Ստուգում ենք եթե վստահելի տիրույթ է
    if result.get('trusted', False):
        return format_trusted_domain_result(integration_name)
    
    if integration_name == 'VirusTotal':
        return format_virustotal_result(result)
    elif integration_name == 'Kaspersky':
        return format_kaspersky_result(result)
    elif integration_name == 'SafeBrowsing':
        return format_safebrowsing_result(result)
    else:
        # Ընդհանուր ձևաչափ
        return format_generic_result(result, integration_name)


def format_pending_result(integration_name):
    """
    Ձևավորում է ընթացիկ ստուգման արդյունքը HTML ձևաչափով
    
    Args:
        integration_name (str): Ինտեգրացիայի անունը
        
    Returns:
        str: HTML ձևաչափով ձևավորված ընթացիկ արդյունք
    """
    return mark_safe(f"""
    <div class="card border-warning mb-3">
        <div class="card-header bg-warning text-white">
            <i class="fas fa-clock me-2"></i> {escape(integration_name)} - Ընթացքի մեջ է
        </div>
        <div class="card-body">
            <div class="spinner-border text-warning" role="status">
                <span class="visually-hidden">Բեռնվում է...</span>
            </div>
            <span class="ms-2">{escape(integration_name)} ստուգումը ընթացքի մեջ է...</span>
        </div>
    </div>
    """)


def format_trusted_domain_result(integration_name):
    """
    Ձևավորում է վստահելի տիրույթի արդյունքը HTML ձևաչափով
    
    Args:
        integration_name (str): Ինտեգրացիայի անունը
        
    Returns:
        str: HTML ձևաչափով ձևավորված վստահելի տիրույթի արդյունք
    """
    return mark_safe(f"""
    <div class="card border-success mb-3">
        <div class="card-header bg-success text-white">
            <i class="fas fa-shield-alt me-2"></i> {escape(integration_name)} - Անվտանգ
        </div>
        <div class="card-body">
            <p class="card-text">
                <i class="fas fa-check-circle text-success me-2"></i>
                Կայքը գտնվում է վստահելի դոմենների ցուցակում։
            </p>
        </div>
    </div>
    """)


def format_virustotal_result(result):
    """
    Ձևավորում է VirusTotal ստուգման արդյունքը HTML ձևաչափով
    
    Args:
        result (dict): VirusTotal ստուգման արդյունքների տվյալներ
        
    Returns:
        str: HTML ձևաչափով ձևավորված VirusTotal արդյունք
    """
    status = result.get('status', 'pending')
    message = result.get('message', 'Արդյունքները հասանելի չեն')
    details = result.get('details', {})
    
    # Ստատիստիկա
    malicious = details.get('malicious', 0)
    suspicious = details.get('suspicious', 0)
    harmless = details.get('harmless', 0)
    undetected = details.get('undetected', 0)
    total_engines = details.get('total_engines', 0)
    
    # Լրացուցիչ տվյալներ
    scan_date = details.get('scan_date', 'Անհայտ')
    reputation = details.get('reputation', 0)
    title = details.get('title', '')
    categories = details.get('categories', {})
    
    # Համայնքի քվեարկությունների տվյալներ
    community_votes = details.get('community_votes', {})
    harmless_votes = community_votes.get('harmless', 0)
    malicious_votes = community_votes.get('malicious', 0)
    total_votes = community_votes.get('total', 0)
    
    # Որոշում ենք գույնը
    card_color = "success" if status == "safe" else ("warning" if status == "suspicious" else "danger")
    
    # Կատեգորիաների ցուցակի ձևավորում
    categories_html = ""
    if categories:
        categories_html = "<div class='mt-3'><strong>Կատեգորիաներ:</strong><ul class='mb-0 mt-1'>"
        for vendor, category in categories.items():
            categories_html += f"<li><strong>{escape(vendor)}:</strong> {escape(category)}</li>"
        categories_html += "</ul></div>"
    
    # Քվեարկությունների ձևավորում
    votes_html = ""
    if total_votes > 0:
        votes_html = f"""
        <div class="mt-3">
            <strong>Համայնքի կարծիք:</strong> 
            <span class="text-success">{harmless_votes} անվտանգ</span> / 
            <span class="text-danger">{malicious_votes} վտանգավոր</span>
            (ընդամենը {total_votes} քվեարկություն)
        </div>
        """
    
    # Սկանավորման արդյունքների գրաֆիկական ներկայացում
    scan_results_html = ""
    if total_engines > 0:
        malicious_percent = int((malicious / total_engines) * 100) if total_engines > 0 else 0
        suspicious_percent = int((suspicious / total_engines) * 100) if total_engines > 0 else 0
        harmless_percent = int((harmless / total_engines) * 100) if total_engines > 0 else 0
        undetected_percent = 100 - malicious_percent - suspicious_percent - harmless_percent
        
        scan_results_html = f"""
        <div class="mt-3">
            <div class="progress" style="height: 25px;">
                <div class="progress-bar bg-danger" role="progressbar" style="width: {malicious_percent}%" 
                     aria-valuenow="{malicious_percent}" aria-valuemin="0" aria-valuemax="100" title="Վտանգավոր">
                    {malicious}
                </div>
                <div class="progress-bar bg-warning" role="progressbar" style="width: {suspicious_percent}%" 
                     aria-valuenow="{suspicious_percent}" aria-valuemin="0" aria-valuemax="100" title="Կասկածելի">
                    {suspicious}
                </div>
                <div class="progress-bar bg-success" role="progressbar" style="width: {harmless_percent}%" 
                     aria-valuenow="{harmless_percent}" aria-valuemin="0" aria-valuemax="100" title="Անվտանգ">
                    {harmless}
                </div>
                <div class="progress-bar bg-secondary" role="progressbar" style="width: {undetected_percent}%" 
                     aria-valuenow="{undetected_percent}" aria-valuemin="0" aria-valuemax="100" title="Չհայտնաբերված">
                    {undetected}
                </div>
            </div>
            <div class="d-flex justify-content-between mt-1">
                <small><span class="badge bg-danger">Վտանգավոր: {malicious}</span></small>
                <small><span class="badge bg-warning">Կասկածելի: {suspicious}</span></small>
                <small><span class="badge bg-success">Անվտանգ: {harmless}</span></small>
                <small><span class="badge bg-secondary">Չհայտնաբերված: {undetected}</span></small>
            </div>
        </div>
        """
    
    # Կազմում ենք վերջնական HTML
    return mark_safe(f"""
    <div class="card border-{card_color} mb-3">
        <div class="card-header bg-{card_color} text-white">
            <i class="fas {'fa-shield-alt' if status == 'safe' else 'fa-exclamation-triangle'} me-2"></i>
            VirusTotal - {'Անվտանգ' if status == 'safe' else 'Կասկածելի' if status == 'suspicious' else 'Վտանգավոր'}
        </div>
        <div class="card-body">
            <p class="card-text">{escape(message)}</p>
            
            {scan_results_html}
            
            <div class="mt-3">
                <strong>Սկանավորման ամսաթիվ:</strong> {escape(str(scan_date))}
            </div>
            
            {votes_html}
            {categories_html}
            
            <div class="mt-3">
                <a href="https://www.virustotal.com/gui/home/url" target="_blank" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-external-link-alt me-1"></i> Բացել VirusTotal-ում
                </a>
            </div>
        </div>
    </div>
    """)


def format_kaspersky_result(result):
    """
    Ձևավորում է Kaspersky ստուգման արդյունքը HTML ձևաչափով
    
    Args:
        result (dict): Kaspersky ստուգման արդյունքների տվյալներ
        
    Returns:
        str: HTML ձևաչափով ձևավորված Kaspersky արդյունք
    """
    status = result.get('status', 'pending')
    verdict = result.get('verdict', 'unknown')
    message = result.get('message', 'Արդյունքները հասանելի չեն')
    zone = result.get('zone', '')
    categories = result.get('categories', [])
    threat_types = result.get('threat_types', [])
    detection_time = result.get('detection_time', '')
    last_seen = result.get('last_seen', '')
    confidence = result.get('confidence', 'medium')
    
    # Որոշում ենք գույնը
    card_color = "success" if status == "safe" else ("warning" if status == "suspicious" else "danger")
    
    # Կատեգորիաների ցուցակի ձևավորում
    categories_html = ""
    if categories:
        categories_html = "<div class='mt-3'><strong>Կատեգորիաներ:</strong><ul class='mb-0 mt-1'>"
        for category in categories:
            categories_html += f"<li>{escape(category)}</li>"
        categories_html += "</ul></div>"
    
    # Սպառնալիքների տեսակների ցուցակի ձևավորում
    threat_types_html = ""
    if threat_types:
        threat_types_html = "<div class='mt-3'><strong>Սպառնալիքների տեսակներ:</strong><ul class='mb-0 mt-1'>"
        for threat in threat_types:
            threat_types_html += f"<li>{escape(threat)}</li>"
        threat_types_html += "</ul></div>"
    
    # Վստահության աստիճանի ցուցադրում
    confidence_badge = ""
    if confidence:
        confidence_color = "success" if confidence == "high" else ("warning" if confidence == "medium" else "secondary")
        confidence_text = "Բարձր" if confidence == "high" else ("Միջին" if confidence == "medium" else "Ցածր")
        confidence_badge = f"""
        <div class="mt-3">
            <strong>Վստահության աստիճան:</strong> 
            <span class="badge bg-{confidence_color}">{confidence_text}</span>
        </div>
        """
    
    # Վերջին տեսնվելու ամսաթվի ցուցադրում
    date_info_html = ""
    if detection_time or last_seen:
        date_info_html = "<div class='mt-3'>"
        if detection_time:
            date_info_html += f"<div><strong>Հայտնաբերման ամսաթիվ:</strong> {escape(detection_time)}</div>"
        if last_seen:
            date_info_html += f"<div class='mt-1'><strong>Վերջին տեսնվելու ամսաթիվ:</strong> {escape(last_seen)}</div>"
        date_info_html += "</div>"
    
    # Կազմում ենք վերջնական HTML
    return mark_safe(f"""
    <div class="card border-{card_color} mb-3">
        <div class="card-header bg-{card_color} text-white">
            <i class="fas {'fa-shield-alt' if status == 'safe' else 'fa-exclamation-triangle'} me-2"></i>
            Kaspersky - {'Անվտանգ' if status == 'safe' else 'Կասկածելի' if status == 'suspicious' else 'Վտանգավոր'}
        </div>
        <div class="card-body">
            <p class="card-text">{escape(message)}</p>
            
            <div>
                <strong>Վճիռ:</strong> {escape(verdict)}
                {f'<span class="ms-2">(<strong>Զոնա:</strong> {escape(zone)})</span>' if zone else ''}
            </div>
            
            {confidence_badge}
            {date_info_html}
            {categories_html}
            {threat_types_html}
            
            <div class="mt-3">
                <a href="https://opentip.kaspersky.com/" target="_blank" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-external-link-alt me-1"></i> Բացել Kaspersky OpenTIP-ում
                </a>
            </div>
        </div>
    </div>
    """)


def format_safebrowsing_result(result):
    """
    Ձևավորում է Google Safe Browsing ստուգման արդյունքը HTML ձևաչափով
    
    Args:
        result (dict): Google Safe Browsing ստուգման արդյունքների տվյալներ
        
    Returns:
        str: HTML ձևաչափով ձևավորված Google Safe Browsing արդյունք
    """
    status = result.get('status', 'pending')
    message = result.get('message', 'Արդյունքները հասանելի չեն')
    threat_type = result.get('threat_type', '')
    threat_description = result.get('threat_description', '')
    confidence = result.get('confidence', 'medium')
    
    # Որոշում ենք գույնը
    card_color = "success" if status == "safe" else "danger"
    
    # Վստահության աստիճանի ցուցադրում
    confidence_badge = ""
    if confidence:
        confidence_color = "success" if confidence == "high" else ("warning" if confidence == "medium" else "secondary")
        confidence_text = "Բարձր" if confidence == "high" else ("Միջին" if confidence == "medium" else "Ցածր")
        confidence_badge = f"""
        <div class="mt-3">
            <strong>Վստահության աստիճան:</strong> 
            <span class="badge bg-{confidence_color}">{confidence_text}</span>
        </div>
        """
    
    # Սպառնալիքի տեսակի ցուցադրում
    threat_html = ""
    if threat_type:
        threat_html = f"""
        <div class="mt-3">
            <strong>Սպառնալիքի տեսակ:</strong> {escape(threat_type)}
            {f'<div class="mt-1">{escape(threat_description)}</div>' if threat_description else ''}
        </div>
        """
    
    # Կազմում ենք վերջնական HTML
    return mark_safe(f"""
    <div class="card border-{card_color} mb-3">
        <div class="card-header bg-{card_color} text-white">
            <i class="fas {'fa-shield-alt' if status == 'safe' else 'fa-exclamation-triangle'} me-2"></i>
            Google Safe Browsing - {'Անվտանգ' if status == 'safe' else 'Վտանգավոր'}
        </div>
        <div class="card-body">
            <p class="card-text">{escape(message)}</p>
            
            {confidence_badge}
            {threat_html}
            
            <div class="mt-3">
                <a href="https://transparencyreport.google.com/safe-browsing/search" target="_blank" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-external-link-alt me-1"></i> Բացել Google Safe Browsing-ում
                </a>
            </div>
        </div>
    </div>
    """)


def format_generic_result(result, integration_name):
    """
    Ձևավորում է ընդհանուր ստուգման արդյունքը HTML ձևաչափով
    
    Args:
        result (dict): Ստուգման արդյունքների տվյալներ
        integration_name (str): Ինտեգրացիայի անունը
        
    Returns:
        str: HTML ձևաչափով ձևավորված ընդհանուր արդյունք
    """
    status = result.get('status', 'pending')
    message = result.get('message', 'Արդյունքները հասանելի չեն')
    
    # Որոշում ենք գույնը
    card_color = "success" if status == "safe" else ("warning" if status == "suspicious" else "danger")
    
    return mark_safe(f"""
    <div class="card border-{card_color} mb-3">
        <div class="card-header bg-{card_color} text-white">
            <i class="fas {'fa-shield-alt' if status == 'safe' else 'fa-exclamation-triangle'} me-2"></i>
            {escape(integration_name)} - {'Անվտանգ' if status == 'safe' else 'Կասկածելի' if status == 'suspicious' else 'Վտանգավոր'}
        </div>
        <div class="card-body">
            <p class="card-text">{escape(message)}</p>
        </div>
    </div>
    """)


def format_overall_result(security_score, all_results):
    """
    Ձևավորում է ընդհանուր արդյունքը HTML ձևաչափով
    
    Args:
        security_score (int): Անվտանգության միավորը (0-100)
        all_results (dict): Բոլոր ստուգումների արդյունքները
        
    Returns:
        str: HTML ձևաչափով ձևավորված ընդհանուր արդյունք
    """
    # Գտնում ենք վտանգավոր ստուգումների քանակը
    malicious_count = sum(1 for result in all_results.values() if result.get('malicious', False))
    suspicious_count = sum(1 for result in all_results.values() 
                         if not result.get('malicious', False) and result.get('status') == 'suspicious')
    safe_count = sum(1 for result in all_results.values() 
                   if not result.get('malicious', False) and result.get('status') == 'safe')
    total_checks = len(all_results)
    
    # Որոշում ենք գույնը և տեքստը
    if security_score >= 80:
        color = "success"
        verdict = "Անվտանգ"
        icon = "fa-shield-alt"
    elif security_score >= 50:
        color = "warning"
        verdict = "Կասկածելի"
        icon = "fa-exclamation-circle"
    else:
        color = "danger"
        verdict = "Վտանգավոր"
        icon = "fa-exclamation-triangle"
    
    # Անվտանգության նկարագրություն
    security_description = ""
    if security_score >= 80:
        security_description = "Այս կայքը անվտանգ է օգտագործման համար։"
    elif security_score >= 50:
        security_description = "Այս կայքը պարունակում է որոշ կասկածելի նշաններ։ Զգուշությամբ օգտագործեք։"
    else:
        security_description = "Այս կայքը վտանգավոր է։ Խորհուրդ չի տրվում այցելել այս կայքը։"
    
    # Ստուգումների վիճակագրություն
    checks_summary = ""
    if total_checks > 0:
        checks_summary = f"""
        <div class="d-flex justify-content-between align-items-center mt-3 mb-3">
            <div class="text-center">
                <h5 class="mb-1 text-success">{safe_count}</h5>
                <small class="text-muted">Անվտանգ</small>
            </div>
            <div class="text-center">
                <h5 class="mb-1 text-warning">{suspicious_count}</h5>
                <small class="text-muted">Կասկածելի</small>
            </div>
            <div class="text-center">
                <h5 class="mb-1 text-danger">{malicious_count}</h5>
                <small class="text-muted">Վտանգավոր</small>
            </div>
            <div class="text-center">
                <h5 class="mb-1">{total_checks}</h5>
                <small class="text-muted">Ընդամենը</small>
            </div>
        </div>
        """
    
    # Ձևավորում ենք արդյունքի գրաֆիկական ներկայացումը
    return mark_safe(f"""
    <div class="card border-{color} mb-4">
        <div class="card-header bg-{color} text-white">
            <h5 class="mb-0">
                <i class="fas {icon} me-2"></i> Ընդհանուր արդյունք - {verdict}
            </h5>
        </div>
        <div class="card-body">
            <div class="row align-items-center">
                <div class="col-md-4 text-center">
                    <div class="position-relative d-inline-block">
                        <canvas id="securityScoreChart" width="150" height="150"></canvas>
                        <div class="position-absolute top-50 start-50 translate-middle">
                            <h2 class="mb-0 fw-bold text-{color}">{security_score}</h2>
                            <small>միավոր</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-8">
                    <h4 class="text-{color} mb-3">{verdict}</h4>
                    {checks_summary}
                    <p class="lead mt-2">
                        {security_description}
                    </p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
    document.addEventListener('DOMContentLoaded', function() {{
        var ctx = document.getElementById('securityScoreChart').getContext('2d');
        var chart = new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                datasets: [{{
                    data: [{security_score}, {100 - security_score}],
                    backgroundColor: [
                        '{
                            "#28a745" if security_score >= 80 else 
                            "#ffc107" if security_score >= 50 else
                            "#dc3545"
                        }',
                        '#e9ecef'
                    ],
                    borderWidth: 0
                }}]
            }},
            options: {{
                cutout: '80%',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    tooltip: {{
                        enabled: false
                    }},
                    legend: {{
                        display: false
                    }}
                }}
            }}
        }});
    }});
    </script>
    """)
