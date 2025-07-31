"""
Recommendations Module

Այս մոդուլը ստեղծում է անվտանգության առաջարկություններ URL ստուգման արդյունքների հիման վրա:
"""

from django.utils.safestring import mark_safe
from django.utils.html import escape


def generate_recommendations(url_check_results, url):
    """
    Ստեղծում է անվտանգության առաջարկություններ URL ստուգման արդյունքների հիման վրա
    
    Args:
        url_check_results (dict): URL ստուգման արդյունքները
        url (str): Ստուգվող URL-ը
        
    Returns:
        str: HTML ձևաչափով ձևավորված առաջարկություններ
    """
    try:
        malicious_count = sum(1 for result in url_check_results.values() if result.get('malicious', False))
        suspicious_count = sum(1 for result in url_check_results.values() 
                             if not result.get('malicious', False) and result.get('status') == 'suspicious')
        
        # Եթե ոչ մի վտանգավոր կամ կասկածելի արդյունք չկա
        if malicious_count == 0 and suspicious_count == 0:
            return _generate_safe_recommendations(url)
        
        # Եթե կան վտանգավոր արդյունքներ
        if malicious_count > 0:
            return _generate_malicious_recommendations(url_check_results, url)
        
        # Եթե կան միայն կասկածելի արդյունքներ
        return _generate_suspicious_recommendations(url_check_results, url)
    except Exception as e:
        # Սխալի դեպքում վերադարձնել պարզ առաջարկություն
        print(f"Error in generate_recommendations: {str(e)}")
        return mark_safe(f"""
        <div class="card border-info mb-4">
            <div class="card-header bg-info text-white">
                <h5 class="mb-0"><i class="fas fa-info-circle me-2"></i> Անվտանգության խորհուրդներ</h5>
            </div>
            <div class="card-body">
                <p style="color: #333;">URL-ի անվտանգության վերլուծության ընթացքում սխալ է տեղի ունեցել: Խնդրում ենք միշտ զգույշ լինել անծանոթ կայքեր այցելելիս:</p>
                <div class="alert alert-info" role="alert">
                    <i class="fas fa-shield-alt me-2"></i>
                    <strong style="color: #333;">Անվտանգության խորհուրդ:</strong> <span style="color: #333;">Միշտ ստուգեք URL-ը նախքան անձնական տվյալներ մուտքագրելը:</span>
                </div>
            </div>
        </div>
        """)


def _generate_safe_recommendations(url):
    """
    Ստեղծում է առաջարկություններ անվտանգ URL-ների համար
    
    Args:
        url (str): Ստուգվող URL-ը
        
    Returns:
        str: HTML ձևաչափով ձևավորված առաջարկություններ
    """
    return mark_safe(f"""
    <div class="card border-success mb-4">
        <div class="card-header bg-success text-white">
            <h5 class="mb-0"><i class="fas fa-thumbs-up me-2"></i> Անվտանգության առաջարկներ</h5>
        </div>
        <div class="card-body">
            <p class="lead" style="color: #333;">Այս կայքը թվում է անվտանգ, բայց հիշեք՝</p>
            
            <ul class="list-group list-group-flush mb-3">
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-check-circle text-success me-2"></i>
                    <span style="color: #333;">Միշտ ստուգեք URL-ը նախքան զգայուն տեղեկություններ մուտքագրելը</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-check-circle text-success me-2"></i>
                    <span style="color: #333;">Օգտագործեք ուժեղ, եզակի գաղտնաբառեր տարբեր կայքերի համար</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-check-circle text-success me-2"></i>
                    <span style="color: #333;">Եթե հնարավոր է, միացրեք երկու գործոնով նույնականացումը (2FA)</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-check-circle text-success me-2"></i>
                    <span style="color: #333;">Թարմացրեք ձեր զննարկիչը և անվտանգության ծրագրերը կանոնավոր կերպով</span>
                </li>
            </ul>
            
            <div class="alert alert-success" role="alert">
                <i class="fas fa-shield-alt me-2"></i>
                <strong style="color: #333;">Կայքը թվում է անվտանգ:</strong> <span style="color: #333;">{escape(url)}-ը անցել է մեր անվտանգության ստուգումները:</span>
            </div>
        </div>
    </div>
    """)


def _generate_malicious_recommendations(url_check_results, url):
    """
    Ստեղծում է առաջարկություններ վտանգավոր URL-ների համար
    
    Args:
        url_check_results (dict): URL ստուգման արդյունքները
        url (str): Ստուգվող URL-ը
        
    Returns:
        str: HTML ձևաչափով ձևավորված առաջարկություններ
    """
    # Հավաքում ենք սպառնալիքների տիպերը
    threat_types = set()
    for result in url_check_results.values():
        if result.get('malicious', False):
            # VirusTotal սպառնալիքի տիպեր
            if 'details' in result and 'categories' in result['details']:
                for category in result['details']['categories'].values():
                    threat_types.add(category.lower())
            
            # Kaspersky սպառնալիքի տիպեր
            if 'threat_types' in result:
                for threat in result['threat_types']:
                    threat_types.add(threat.lower())
            
            # Google Safe Browsing սպառնալիքի տիպեր
            if 'threat_type' in result:
                threat_types.add(result['threat_type'].lower())
    
    # Որոշում ենք հատուկ առաջարկություններ սպառնալիքի տիպի հիման վրա
    specific_recommendations = []
    
    phishing_detected = any(t for t in threat_types if 'phish' in t or 'social' in t)
    malware_detected = any(t for t in threat_types if 'malware' in t or 'virus' in t or 'trojan' in t)
    unwanted_software = any(t for t in threat_types if 'unwanted' in t or 'adware' in t or 'pup' in t)
    
    if phishing_detected:
        specific_recommendations.append("""
        <div class="alert alert-danger mb-3">
            <h5 style="color: #000;"><i class="fas fa-fish me-2"></i> Ֆիշինգի սպառնալիք հայտնաբերված</h5>
            <p style="color: #000;">Այս կայքը փորձում է ձևացնել օրինական կայք` ձեր անձնական տվյալները գողանալու համար:</p>
            <ul style="color: #000;">
                <li>Մի մուտքագրեք որևէ անձնական տվյալներ</li>
                <li>Եթե ներմուծել եք գաղտնաբառեր կամ վճարման տվյալներ, անմիջապես փոխեք դրանք</li>
                <li>Զգուշացրեք ձեր ծանոթներին այս կայքի մասին</li>
            </ul>
        </div>
        """)
    
    if malware_detected:
        specific_recommendations.append("""
        <div class="alert alert-danger mb-3">
            <h5 style="color: #000;"><i class="fas fa-virus me-2"></i> Վնասակար ծրագրի սպառնալիք հայտնաբերված</h5>
            <p style="color: #000;">Այս կայքը կարող է ներբեռնել վնասակար ծրագրեր ձեր սարքի վրա:</p>
            <ul style="color: #000;">
                <li>Եթե այցելել եք այս կայքը, սկանավորեք ձեր համակարգիչը հակավիրուսային ծրագրով</li>
                <li>Եթե ներբեռնել եք որևէ ֆայլ, ջնջեք այն և սկանավորեք ձեր համակարգիչը</li>
                <li>Թարմացրեք ձեր օպերացիոն համակարգը և ծրագրերը</li>
            </ul>
        </div>
        """)
    
    if unwanted_software:
        specific_recommendations.append("""
        <div class="alert alert-warning mb-3">
            <h5 style="color: #000;"><i class="fas fa-ad me-2"></i> Անցանկալի ծրագրի սպառնալիք հայտնաբերված</h5>
            <p style="color: #000;">Այս կայքը կարող է տեղադրել գովազդային ծրագրեր կամ անցանկալի ծրագրեր ձեր սարքի վրա:</p>
            <ul style="color: #000;">
                <li>Խուսափեք ներբեռնել որևէ բան այս կայքից</li>
                <li>Ստուգեք ձեր զննարկչի ընդլայնումները և հեռացրեք կասկածելիները</li>
                <li>Օգտագործեք AdwCleaner կամ նմանատիպ գործիք անցանկալի ծրագրերը հեռացնելու համար</li>
            </ul>
        </div>
        """)
    
    # Եթե որոշակի սպառնալիքներ չկան, ավելացնում ենք ընդհանուր զգուշացում
    if not specific_recommendations:
        specific_recommendations.append("""
        <div class="alert alert-danger mb-3">
            <h5 style="color: #000;"><i class="fas fa-exclamation-triangle me-2"></i> Վտանգավոր կայք հայտնաբերված</h5>
            <p style="color: #000;">Այս կայքը նշված է որպես վտանգավոր մեր անվտանգության գործիքների կողմից:</p>
            <ul style="color: #000;">
                <li>Խուսափեք այս կայքում որևէ տեղեկություն մուտքագրելուց</li>
                <li>Չներբեռնեք որևէ ֆայլ այս կայքից</li>
                <li>Լքեք այս կայքը և ջնջեք այն ձեր պատմությունից</li>
            </ul>
        </div>
        """)
    
    # Ձևավորում ենք ընդհանուր առաջարկությունները
    specific_recommendations_html = "".join(specific_recommendations)
    
    return mark_safe(f"""
    <div class="card border-danger mb-4">
        <div class="card-header bg-danger text-white">
            <h5 class="mb-0"><i class="fas fa-exclamation-triangle me-2"></i> Անվտանգության զգուշացում</h5>
        </div>
        <div class="card-body">
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-ban me-2"></i>
                <strong style="color: #fff;">Մի այցելեք այս կայքը:</strong> <span style="color: #fff;">{escape(url)}-ը հայտնաբերվել է որպես վտանգավոր:</span>
            </div>
            
            {specific_recommendations_html}
            
            <h5 class="mt-4" style="color: #ffc107; font-weight: bold;">Ընդհանուր առաջարկություններ</h5>
            <ul class="list-group list-group-flush mb-3">
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-times-circle text-danger me-2"></i>
                    <span style="color: #333;">Անմիջապես լքեք այս կայքը</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-times-circle text-danger me-2"></i>
                    <span style="color: #333;">Մի մուտքագրեք անձնական տվյալներ, գաղտնաբառեր կամ վճարման տվյալներ</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-times-circle text-danger me-2"></i>
                    <span style="color: #333;">Սկանավորեք ձեր սարքը հակավիրուսային ծրագրով</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-times-circle text-danger me-2"></i>
                    <span style="color: #333;">Թարմացրեք ձեր զննարկիչը և անվտանգության ծրագրերը</span>
                </li>
            </ul>
        </div>
    </div>
    """)


def _generate_suspicious_recommendations(url_check_results, url):
    """
    Ստեղծում է առաջարկություններ կասկածելի URL-ների համար
    
    Args:
        url_check_results (dict): URL ստուգման արդյունքները
        url (str): Ստուգվող URL-ը
        
    Returns:
        str: HTML ձևաչափով ձևավորված առաջարկություններ
    """
    return mark_safe(f"""
    <div class="card border-warning mb-4">
        <div class="card-header bg-warning text-dark">
            <h5 class="mb-0"><i class="fas fa-exclamation-circle me-2"></i> Անվտանգության զգուշացում</h5>
        </div>
        <div class="card-body">
            <div class="alert alert-warning" role="alert">
                <i class="fas fa-exclamation-circle me-2"></i>
                <strong style="color: #fff;">Զգուշությամբ այցելեք այս կայքը:</strong> <span style="color: #fff;">{escape(url)}-ը հայտնաբերվել է որպես կասկածելի:</span>
            </div>
            
            <h5 style="color: #ffc107; font-weight: bold;">Ինչ անել</h5>
            <ul class="list-group list-group-flush mb-3">
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-exclamation-circle text-warning me-2"></i>
                    <span style="color: #333;">Մի մուտքագրեք զգայուն տվյալներ այս կայքում</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-exclamation-circle text-warning me-2"></i>
                    <span style="color: #333;">Մի ներբեռնեք ֆայլեր, եթե չեք վստահում աղբյուրին</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-exclamation-circle text-warning me-2"></i>
                    <span style="color: #333;">Ստուգեք URL-ը՝ համոզվելու, որ դա այն կայքն է, որը դուք ակնկալում եք</span>
                </li>
                <li class="list-group-item" style="background-color: #f8f9fa; color: #333;">
                    <i class="fas fa-exclamation-circle text-warning me-2"></i>
                    <span style="color: #333;">Ուշադրություն դարձրեք կասկածելի նշանների՝ ինչպիսիք են քերականական սխալները, անսովոր դիզայնը</span>
                </li>
            </ul>
            
            <div class="alert alert-info mt-3" role="alert">
                <i class="fas fa-info-circle me-2"></i>
                <strong style="color: #fff;">Հուշում:</strong> <span style="color: #fff;">Այս կայքը կարող է անվնաս լինել, բայց անվտանգության գործիքները նշել են այն որպես կասկածելի. 
                Շարունակեք զգուշությամբ:</span>
            </div>
        </div>
    </div>
    """)
