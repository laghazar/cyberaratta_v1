"""
URL-ների ներքին վերլուծության համակարգ
Օգտագործվում է երբ API-ները չեն հայտնաբերում URL-ը
"""

import re
import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime, timedelta
import ipaddress

# Optional imports with fallbacks
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

class InternalURLAnalyzer:
    """Ներքին URL վերլուծության կլաս"""
    
    def __init__(self):
        self.suspicious_patterns = [
            # Phishing և scam patterns
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP հասցեներ
            r'[a-z0-9-]+\.tk$|[a-z0-9-]+\.ml$|[a-z0-9-]+\.ga$',  # Անվճար TLD-ներ
            r'[a-z0-9-]+(paypal|bank|secure|login|account)[a-z0-9-]*\.',  # Phishing բառեր
            r'[a-z0-9-]+(microsoft|google|apple|amazon)[a-z0-9-]*\.',  # Brand impersonation
            r'[a-z0-9-]+(facebook|instagram|twitter)[a-z0-9-]*\.',  # Social media phishing
            r'[a-z0-9-]+(arca|idram|teller)[a-z0-9-]*\.',  # Հայկական ֆինանսական
            r'[a-z0-9-]+(beeline|ucom|viva|vivacell)[a-z0-9-]*\.',  # Հայկական օպերատորներ
            r'[0-9]{3,}[a-z]+[0-9]+',  # Կասկածելի միջոցառումներ
            r'[a-z]+[0-9]{3,}[a-z]*',  # Կասկածելի համակցություններ
            r'[a-z]+-[a-z]+-[0-9]+',   # Կասկածելի գծիկային կապեր
            r'[a-z]{1,3}[0-9]{2,}',    # Կարճ հավելումներ մեծ թվերով
        ]
        
        self.trusted_tlds = [
            '.am', '.com', '.org', '.net', '.edu', '.gov', '.mil',
            '.co.uk', '.de', '.fr', '.jp', '.ca', '.au', '.ru', '.cn'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top',
            '.download', '.click', '.link', '.review', '.country'
        ]
        
        self.armenian_trusted_domains = [
            'gov.am', 'cba.am', 'ardshinbank.am', 'acba.am', 'ameriabank.am',
            'araratbank.am', 'byblosbank.am', 'hsbc.am', 'inecobank.am',
            'unibank.am', 'vtb.am', 'evocabank.am', 'idbank.am',
            'beeline.am', 'ucom.am', 'viva-mts.am', 'vivacell.am',
            'armentel.am', 'arca.am', 'idram.am', 'telcell.am',
            'ysu.am', 'aua.am', 'asue.am', 'seua.am', 'nuas.am'
        ]

    def analyze_url(self, url):
        """Ամբողջական URL վերլուծություն"""
        results = {
            'url': url,
            'risk_score': 0,
            'max_risk_score': 100,
            'findings': [],
            'recommendations': [],
            'ssl_info': {},
            'domain_info': {},
            'content_analysis': {},
            'technical_details': {},
            'status': 'unknown'
        }
        
        try:
            # 1. URL-ի կառուցվածքի վերլուծություն
            self._analyze_url_structure(url, results)
            
            # 2. SSL սերտիֆիկատի ստուգում
            self._check_ssl_certificate(url, results)
            
            # 3. Դոմենի տեղեկությունների ստուգում
            self._check_domain_info(url, results)
            
            # 4. DNS records ստուգում
            self._check_dns_records(url, results)
            
            # 5. Բովանդակության վերլուծություն (եթե հնարավոր է)
            self._analyze_content(url, results)
            
            # 6. Վերջնական գնահատում
            self._calculate_final_assessment(results)
            
        except Exception as e:
            results['findings'].append(f"Վերլուծության սխալ: {str(e)}")
            results['risk_score'] = 50  # Միջին ռիսկ անհայտ սխալների դեպքում
            
        return results

    def _analyze_url_structure(self, url, results):
        """URL-ի կառուցվածքի վերլուծություն"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Հայկական վստահելի դոմեններ
        if any(domain.endswith(trusted) for trusted in self.armenian_trusted_domains):
            results['findings'].append("✅ Հայկական պաշտոնական կամ հայտնի վստահելի կայք (բանկ, գործակալություն, օպերատոր)")
            results['risk_score'] -= 30
            return
        
        # IP հասցե փոխարեն դոմենի
        try:
            ipaddress.ip_address(domain.split(':')[0])
            results['findings'].append("⚠️ Կայքը օգտագործում է IP հասցե կայքի անվան փոխարեն - սա կասկածելի է")
            results['risk_score'] += 25
        except ValueError:
            pass
        
        # Կասկածելի patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain + path):
                results['findings'].append(f"⚠️ Կայքի անունը կամ հասցեն ունի կասկածելի տարրեր (օր․ ֆեյք բանկի անուններ)")
                results['risk_score'] += 15
                break
        
        # TLD ստուգում
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        if tld in self.suspicious_tlds:
            results['findings'].append(f"🚨 Օգտագործվում է կասկածելի կայքային ընդարձակում: {tld} (հաճախ օգտագործվում է խարդախությունների համար)")
            results['risk_score'] += 20
        elif tld in self.trusted_tlds:
            results['findings'].append(f"✅ Վստահելի կայքային ընդարձակում: {tld} (օր․ .com, .am, .org)")
            results['risk_score'] -= 5
        
        # HTTPS ստուգում
        if parsed.scheme != 'https':
            results['findings'].append("⚠️ Կայքը չի օգտագործում անվտանգ կապ (HTTP) - տվյալները կարող են գողացվել")
            results['risk_score'] += 15
        else:
            results['findings'].append("✅ Կայքը օգտագործում է անվտանգ կապ (HTTPS) - լավ նշան")
            results['risk_score'] -= 5
        
        # URL-ի երկարություն
        if len(url) > 100:
            results['findings'].append("⚠️ Շատ երկար կայքային հասցե - հաճախ օգտագործվում է խաբեության համար")
            results['risk_score'] += 10
        
        # Կասկածելի պարամետրեր
        if any(param in url.lower() for param in ['download', 'install', 'update', 'verify', 'confirm']):
            results['findings'].append("⚠️ Հասցեում կան կասկածելի բառեր (ներբեռնել, տեղադրել, ստուգել) - զգույշ եղեք")
            results['risk_score'] += 10

    def _check_ssl_certificate(self, url, results):
        """SSL սերտիֆիկատի ստուգում"""
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            return
            
        try:
            hostname = parsed.netloc.split(':')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Սերտիֆիկատի վավերություն
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    results['ssl_info'] = {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': cert['notAfter'],
                        'days_until_expiry': days_until_expiry
                    }
                    
                    if days_until_expiry < 30:
                        results['findings'].append(f"⚠️ Անվտանգության վկայականը շուտով կավարտվի ({days_until_expiry} օր)")
                        results['risk_score'] += 10
                    elif days_until_expiry < 0:
                        results['findings'].append("🚨 Անվտանգության վկայականը ավարտվել է - մի այցելեք")
                        results['risk_score'] += 25
                    else:
                        results['findings'].append(f"✅ Վավեր անվտանգության վկայական ({days_until_expiry} օր մնացել է)")
                        results['risk_score'] -= 10
                        
        except Exception as e:
            results['findings'].append(f"❌ Չկարողացանք ստուգել անվտանգության վկայականը - կարող է խնդիր լինել")
            results['risk_score'] += 15
            results['ssl_info'] = {'valid': False, 'error': str(e)}

    def _check_domain_info(self, url, results):
        """Դոմենի WHOIS տեղեկությունների ստուգում"""
        if not WHOIS_AVAILABLE:
            results['findings'].append("ℹ️ Կայքի գրանցման տարեթվի ստուգումը հասանելի չէ")
            return
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            
            # Հեռացնում ենք subdomain-ները
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                domain = '.'.join(domain_parts[-2:])
            
            w = whois.whois(domain)
            
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                age_days = (datetime.now() - creation_date).days
                age_years = age_days // 365
                
                results['domain_info'] = {
                    'creation_date': creation_date.strftime('%Y-%m-%d'),
                    'age_days': age_days,
                    'registrar': w.registrar,
                    'country': w.country
                }
                
                if age_days < 30:
                    results['findings'].append("🚨 Շատ նոր կայք (ստեղծվել է 1 ամսից պակաս առաջ) - խուսափեք")
                    results['risk_score'] += 30
                elif age_days < 90:
                    results['findings'].append("⚠️ Համեմատաբար նոր կայք (3 ամսից պակաս) - զգույշ եղեք")
                    results['risk_score'] += 15
                elif age_years >= 1:
                    results['findings'].append(f"✅ Հաստատված կայք (գործում է {age_years} տարի)")
                    results['risk_score'] -= 10
                else:
                    results['findings'].append(f"✅ Հաստատված կայք (գործում է {age_days} օր)")
                    results['risk_score'] -= 5
                    
        except Exception as e:
            results['findings'].append(f"ℹ️ Չկարողացանք ստուգել կայքի գրանցման տարեթիվը")
            results['domain_info'] = {'error': str(e)}

    def _check_dns_records(self, url, results):
        """DNS records-ի ստուգում"""
        if not DNS_AVAILABLE:
            results['findings'].append("ℹ️ Ցանցային տեղեկությունների ստուգումը հասանելի չէ")
            return
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            
            # A record ստուգում
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                ip_addresses = [str(record) for record in a_records]
                results['technical_details']['ip_addresses'] = ip_addresses
                
                # Ստուգում ենք IP-ների գեոլոկացիան
                for ip in ip_addresses:
                    if ipaddress.ip_address(ip).is_private:
                        results['findings'].append("⚠️ Կայքը օգտագործում է ներքին ցանցային հասցե - կարող է խնդիր լինել")
                        results['risk_score'] += 20
                        
            except Exception as e:
                results['findings'].append("⚠️ Չկարողացանք գտնել կայքի ցանցային հասցեն")
                results['risk_score'] += 10
            
            # MX record ստուգում (email-ի համար)
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                results['technical_details']['has_mx'] = True
                results['findings'].append("✅ Կայքը ունի էլ․փոստի ծառայություն - լավ նշան")
            except:
                results['technical_details']['has_mx'] = False
                
        except Exception as e:
            results['findings'].append(f"ℹ️ Չկարողացանք ստուգել ցանցային տեղեկությունները")

    def _analyze_content(self, url, results):
        """Բովանդակության վերլուծություն"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            content = response.text.lower()
            
            # Կասկածելի բառեր
            suspicious_words = [
                'verify your account', 'update payment', 'suspended account',
                'click here now', 'limited time', 'urgent action required',
                'congratulations', 'you have won', 'claim your prize',
                'verify identity', 'confirm information', 'security alert',
                'ստուգեք ձեր հաշիվը', 'թարմացրեք տվյալները', 'անվտանգության ազդանշան'
            ]
            
            suspicious_count = sum(1 for word in suspicious_words if word in content)
            if suspicious_count > 2:
                results['findings'].append(f"🚨 Կայքում գտնվել է {suspicious_count} կասկածելի արտահայտություն (օր․ «ստուգեք ձեր հաշիվը»)")
                results['risk_score'] += suspicious_count * 5
            
            # JavaScript redirection
            if 'window.location' in content or 'document.location' in content:
                results['findings'].append("⚠️ Կայքը ունի ավտոմատ վերաուղղորդում - կարող է կասկածելի լինել")
                results['risk_score'] += 10
            
            # Ֆորմերի ստուգում
            if '<form' in content and ('password' in content or 'login' in content):
                results['findings'].append("ℹ️ Կայքում կա մուտքի ֆորմ - զգույշ եղեք գաղտնաբառ մուտքագրելիս")
                results['risk_score'] += 5
                
            results['content_analysis'] = {
                'status_code': response.status_code,
                'content_length': len(content),
                'suspicious_words_found': suspicious_count
            }
            
        except Exception as e:
            results['findings'].append(f"ℹ️ Չկարողացանք ստուգել կայքի բովանդակությունը")

    def _calculate_final_assessment(self, results):
        """Վերջնական գնահատման հաշվարկ"""
        risk_score = max(0, min(100, results['risk_score']))
        results['risk_score'] = risk_score
        
        if risk_score <= 20:
            results['status'] = 'safe'
            results['recommendations'].append("✅ Կայքը թվում է ամբողջովին անվտանգ - կարող եք այցելել")
        elif risk_score <= 40:
            results['status'] = 'low_risk'
            results['recommendations'].append("⚠️ Ցածր ռիսկ - կարող եք այցելել, բայց զգույշ եղեք")
        elif risk_score <= 60:
            results['status'] = 'medium_risk'
            results['recommendations'].append("⚠️ Միջին ռիսկ - խուսափեք անձնական տվյալներ (գաղտնաբառ, քարտի տվյալներ) մուտքագրելուց")
        elif risk_score <= 80:
            results['status'] = 'high_risk'
            results['recommendations'].append("🚨 Բարձր ռիսկ - ԴՈ՛Ւք չէ այցելել այս կայքը")
        else:
            results['status'] = 'very_high_risk'
            results['recommendations'].append("🚨 Շատ բարձր ռիսկ - ԱՐԳԵԼՎՈՒՄ Է այցելել այս կայքը")
        
        # Ընդհանուր առաջարկություններ
        results['recommendations'].extend([
            "📋 Մանրամասն պատասխանը կստանաք 3 աշխատանքային օրվա ընթացքում",
            "🔍 Մեր մասնագետները կանեն ավելի խորը ստուգում",
            "📞 Կասկածի դեպքում անպայման կապվեք մեզ հետ"
        ])

def analyze_unknown_url(url):
    """Հիմնական ֆունկցիա անհայտ URL-ների վերլուծության համար"""
    analyzer = InternalURLAnalyzer()
    result = analyzer.analyze_url(url)
    
    # Ավելացնում ենք պարզ բացատրություններ
    result['simple_explanation'] = get_simple_risk_explanation(result['risk_score'])
    result['safety_tips'] = get_safety_tips(result['status'])
    
    return result

def get_simple_risk_explanation(risk_score):
    """Պարզ բացատրություն ռիսկի գնահատման մասին"""
    if risk_score <= 20:
        return "Կայքը թվում է անվտանգ: Մեր ստուգումները կտարողական խնդիրներ չեն հայտնաբերել:"
    elif risk_score <= 40:
        return "Կայքը ունի միայն մի քանի փոքր կասկածելի հատկանիշ: Հավանաբար անվտանգ է, բայց զգույշ եղեք:"
    elif risk_score <= 60:
        return "Կայքը ունի մի քանի կասկածելի հատկանիշ: Մի տվեք ձեր անձնական տվյալները (գաղտնաբառ, քարտ):"
    elif risk_score <= 80:
        return "Կայքը ունի շատ կասկածելի հատկանիշներ: Խորհուրդ չենք տալիս այցելել:"
    else:
        return "Կայքը շատ վտանգավոր է: Բացարձակապես մի այցելեք:"

def get_safety_tips(status):
    """Անվտանգության խորհուրդներ`կախված կարգավիճակից"""
    tips = [
        "💡 Երբեք մի տվեք ձեր գաղտնաբառը անծանոթ կայքերում",
        "🔒 Ստուգեք, որ կայքը սկսվում է https://-ով",
        "📱 Կասկածի դեպքում խորհրդակցեք IT մասնագետի հետ"
    ]
    
    if status in ['high_risk', 'very_high_risk']:
        tips.extend([
            "🚨 Անմիջապես փակեք այս կայքը",
            "⚠️ Մի ներբեռնեք ֆայլեր այս կայքից",
            "📞 Եթե արդեն տվել եք տվյալներ, փոխեք գաղտնաբառները"
        ])
    elif status == 'medium_risk':
        tips.extend([
            "🔍 Ստուգեք կայքի անունը` տառասխալների համար",
            "❌ Մի գործարկեք ֆայլեր այս կայքից"
        ])
    elif status in ['safe', 'low_risk']:
        tips.extend([
            "✅ Կայքը թվում է անվտանգ",
            "🔄 Բայց միշտ զգույշ եղեք օնլայն գործունեության ժամանակ"
        ])
    
    return tips
