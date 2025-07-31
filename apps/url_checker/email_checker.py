"""
Email Phishing Checker Utilities
Բարդ email phishing հայտնաբերության գործիքներ
"""
import email
import re
import json
import requests
import dns.resolver
import dkim
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from fuzzywuzzy import fuzz
from django.conf import settings
from django.utils.html import escape
import logging

logger = logging.getLogger(__name__)

# Հայտնի բրենդների ցուցակ brand impersonation-ի համար
KNOWN_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'instagram',
    'twitter', 'linkedin', 'ebay', 'netflix', 'spotify', 'uber', 'airbnb',
    'dropbox', 'github', 'stackoverflow', 'reddit', 'gmail', 'outlook',
    'yahoo', 'bank', 'visa', 'mastercard', 'amex', 'chase', 'wells',
    'citibank', 'hsbc', 'barclays', 'santander'
]

class EmailPhishingChecker:
    """Գլխավոր դաս email phishing ստուգման համար"""
    
    def __init__(self):
        self.risk_score = 0
        self.reasons = []
        self.details = {}
    
    def analyze_email(self, raw_email_content):
        """
        Վերլուծում է raw email և վերադարձնում phishing risk assessment
        
        Args:
            raw_email_content (str): Raw email content
            
        Returns:
            dict: Վերլուծության արդյունքները
        """
        try:
            # Parse email
            parsed_email = self.parse_email(raw_email_content)
            if not parsed_email:
                return self._create_error_result("Չհաջողվեց email-ը parse անել")
            
            # Reset risk score
            self.risk_score = 0
            self.reasons = []
            self.details = {}
            
            # Ստուգումների հերակարգություն
            self._check_headers(parsed_email)
            self._check_authentication(parsed_email)
            self._check_content_and_links(parsed_email)
            self._check_sender_reputation(parsed_email)
            
            # Վերջնական գնահատում
            status = self._calculate_final_status()
            
            return {
                'status': status,
                'risk_score': self.risk_score,
                'reasons': self.reasons,
                'details': self.details,
                'total_checks': len(self.reasons)
            }
            
        except Exception as e:
            logger.error(f"Email analysis error: {str(e)}")
            return self._create_error_result(f"Վերլուծության սխալ: {str(e)}")
    
    def parse_email(self, raw_email_content):
        """Parse raw email content"""
        try:
            if isinstance(raw_email_content, str):
                raw_email_content = raw_email_content.encode('utf-8')
            
            parser = BytesParser(policy=policy.default)
            parsed_email = parser.parsebytes(raw_email_content)
            return parsed_email
            
        except Exception as e:
            logger.error(f"Email parsing error: {str(e)}")
            return None
    
    def _check_headers(self, email_msg):
        """Ստուգել email headers-ը"""
        headers = dict(email_msg.items())
        self.details['headers'] = headers
        
        # From header ստուգում
        from_header = headers.get('From', '')
        if not from_header:
            self.risk_score += 20
            self.reasons.append("Բացակայում է 'From' header-ը")
        
        # Return-Path vs From ստուգում
        return_path = headers.get('Return-Path', '')
        if return_path and from_header:
            from_domain = self._extract_domain(from_header)
            return_domain = self._extract_domain(return_path)
            if from_domain != return_domain and from_domain and return_domain:
                self.risk_score += 15
                self.reasons.append(f"Return-Path ({return_domain}) տարբերվում է From դոմեյնից ({from_domain})")
        
        # Subject ստուգում
        subject = headers.get('Subject', '')
        suspicious_keywords = [
            'urgent', 'immediate', 'verify', 'suspend', 'expire', 'click here',
            'congratulations', 'winner', 'free', 'limited time', 'act now'
        ]
        
        for keyword in suspicious_keywords:
            if keyword.lower() in subject.lower():
                self.risk_score += 5
                self.reasons.append(f"Կասկածելի keyword subject-ում: '{keyword}'")
                break
    
    def _check_authentication(self, email_msg):
        """Ստուգել SPF, DKIM, DMARC"""
        headers = dict(email_msg.items())
        
        # SPF ստուգում
        spf_result = self._check_spf(email_msg)
        if spf_result['status'] == 'fail':
            self.risk_score += 25
            self.reasons.append(f"SPF ստուգումը ձախողվեց: {spf_result['reason']}")
        elif spf_result['status'] == 'missing':
            self.risk_score += 10
            self.reasons.append("SPF record բացակայում է")
        
        # DKIM ստուգում
        dkim_result = self._check_dkim(email_msg)
        if dkim_result['status'] == 'fail':
            self.risk_score += 20
            self.reasons.append(f"DKIM ստուգումը ձախողվեց: {dkim_result['reason']}")
        elif dkim_result['status'] == 'missing':
            self.risk_score += 8
            self.reasons.append("DKIM signature բացակայում է")
        
        # DMARC ստուգում
        dmarc_result = self._check_dmarc(email_msg)
        if dmarc_result['status'] == 'fail':
            self.risk_score += 15
            self.reasons.append(f"DMARC policy խախտում: {dmarc_result['reason']}")
        
        self.details['authentication'] = {
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result
        }
    
    def _check_spf(self, email_msg):
        """SPF record ստուգում"""
        try:
            from_header = email_msg.get('From', '')
            sender_domain = self._extract_domain(from_header)
            
            if not sender_domain:
                return {'status': 'missing', 'reason': 'Չհաջողվեց դոմեյնը հանել'}
            
            # DNS query SPF record-ի համար
            try:
                answers = dns.resolver.resolve(sender_domain, 'TXT')
                spf_record = None
                
                for answer in answers:
                    txt_record = str(answer).strip('"')
                    if txt_record.startswith('v=spf1'):
                        spf_record = txt_record
                        break
                
                if not spf_record:
                    return {'status': 'missing', 'reason': 'SPF record չգտնվեց'}
                
                # Պարզ SPF վերլուծություն
                if 'include:' in spf_record or 'a:' in spf_record or 'mx:' in spf_record:
                    return {'status': 'pass', 'reason': 'SPF record գտնվեց', 'record': spf_record}
                else:
                    return {'status': 'neutral', 'reason': 'SPF record գտնվեց բայց չի կարող ստուգվել', 'record': spf_record}
                    
            except dns.resolver.NXDOMAIN:
                return {'status': 'fail', 'reason': 'Դոմեյնը գոյություն չունի'}
            except Exception as dns_error:
                return {'status': 'error', 'reason': f'DNS query սխալ: {str(dns_error)}'}
                
        except Exception as e:
            return {'status': 'error', 'reason': f'SPF ստուգման սխալ: {str(e)}'}
    
    def _check_dkim(self, email_msg):
        """DKIM signature ստուգում"""
        try:
            dkim_signature = email_msg.get('DKIM-Signature', '')
            
            if not dkim_signature:
                return {'status': 'missing', 'reason': 'DKIM signature բացակայում է'}
            
            # Պարզ DKIM ստուգում - ավելի բարդը կպահանջի email bytes
            # Այստեղ ուղղակի ստուգում ենք signature-ի առկայությունը
            if 'v=1' in dkim_signature and 'a=' in dkim_signature and 's=' in dkim_signature:
                return {'status': 'present', 'reason': 'DKIM signature առկա է', 'signature': dkim_signature[:100] + '...'}
            else:
                return {'status': 'invalid', 'reason': 'DKIM signature ֆորմատը սխալ է'}
                
        except Exception as e:
            return {'status': 'error', 'reason': f'DKIM ստուգման սխալ: {str(e)}'}
    
    def _check_dmarc(self, email_msg):
        """DMARC policy ստուգում"""
        try:
            from_header = email_msg.get('From', '')
            sender_domain = self._extract_domain(from_header)
            
            if not sender_domain:
                return {'status': 'missing', 'reason': 'Չհաջողվեց դոմեյնը հանել'}
            
            # DMARC record DNS query
            try:
                dmarc_domain = f'_dmarc.{sender_domain}'
                answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                
                for answer in answers:
                    txt_record = str(answer).strip('"')
                    if txt_record.startswith('v=DMARC1'):
                        # DMARC policy վերլուծություն
                        if 'p=reject' in txt_record:
                            return {'status': 'strict', 'reason': 'DMARC reject policy', 'record': txt_record}
                        elif 'p=quarantine' in txt_record:
                            return {'status': 'moderate', 'reason': 'DMARC quarantine policy', 'record': txt_record}
                        elif 'p=none' in txt_record:
                            return {'status': 'lenient', 'reason': 'DMARC none policy', 'record': txt_record}
                        else:
                            return {'status': 'present', 'reason': 'DMARC policy գտնվեց', 'record': txt_record}
                
                return {'status': 'missing', 'reason': 'DMARC record չգտնվեց'}
                
            except dns.resolver.NXDOMAIN:
                return {'status': 'missing', 'reason': 'DMARC record չգտնվեց'}
            except Exception as dns_error:
                return {'status': 'error', 'reason': f'DMARC DNS query սխալ: {str(dns_error)}'}
                
        except Exception as e:
            return {'status': 'error', 'reason': f'DMARC ստուգման սխալ: {str(e)}'}
    
    def _check_content_and_links(self, email_msg):
        """Email բովանդակության և հղումների ստուգում"""
        try:
            # Email body հանում
            body = self._extract_body(email_msg)
            if not body:
                return
            
            # HTML links հանում
            links = self._extract_links(body)
            self.details['links_found'] = len(links)
            
            if not links:
                return
            
            # Link mismatch ստուգում
            mismatched_links = self._check_link_mismatch(body)
            if mismatched_links:
                self.risk_score += 20
                self.reasons.append(f"Գտնվել է {len(mismatched_links)} link որտեղ display text-ը չի համապատասխանում href-ին")
                self.details['mismatched_links'] = mismatched_links[:3]  # Առաջին 3-ը
            
            # Brand impersonation ստուգում
            impersonation_results = self._check_brand_impersonation(links)
            if impersonation_results:
                self.risk_score += 25
                self.reasons.append(f"Հայտնաբերվել է հավանական brand impersonation: {', '.join(impersonation_results[:3])}")
                self.details['brand_impersonation'] = impersonation_results
            
            # URL blacklist ստուգում
            blacklist_results = self._check_url_blacklists(links)
            if blacklist_results['malicious_count'] > 0:
                self.risk_score += 35
                self.reasons.append(f"{blacklist_results['malicious_count']} հղում գտնվել է blacklist-ում")
                self.details['blacklisted_urls'] = blacklist_results['malicious_urls']
            
            # Կասկածելի URL patterns
            suspicious_patterns = self._check_suspicious_url_patterns(links)
            if suspicious_patterns:
                self.risk_score += 15
                self.reasons.append(f"Գտնվել է կասկածելի URL patterns: {', '.join(suspicious_patterns[:3])}")
            
        except Exception as e:
            logger.error(f"Content check error: {str(e)}")
    
    def _extract_body(self, email_msg):
        """Email body հանում"""
        try:
            body = ""
            
            if email_msg.is_multipart():
                for part in email_msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_content() or ""
                    elif part.get_content_type() == "text/html":
                        body += part.get_content() or ""
            else:
                body = email_msg.get_content() or ""
            
            return body
            
        except Exception as e:
            logger.error(f"Body extraction error: {str(e)}")
            return ""
    
    def _extract_links(self, html_content):
        """HTML-ից links հանում"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = []
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                text = a_tag.get_text(strip=True)
                links.append({'href': href, 'text': text})
            
            # Regex-ով նաև ստուգում ենք plain text URL-ները
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            plain_urls = re.findall(url_pattern, html_content)
            
            for url in plain_urls:
                if not any(link['href'] == url for link in links):
                    links.append({'href': url, 'text': url})
            
            return links
            
        except Exception as e:
            logger.error(f"Link extraction error: {str(e)}")
            return []
    
    def _check_link_mismatch(self, html_content):
        """Link display text և href mismatch ստուգում"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            mismatched = []
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                text = a_tag.get_text(strip=True)
                
                # Եթե text-ը URL է, ստուգենք համապատասխանությունը
                if text.startswith('http'):
                    href_domain = self._extract_domain(href)
                    text_domain = self._extract_domain(text)
                    
                    if href_domain and text_domain and href_domain != text_domain:
                        mismatched.append({
                            'display_text': text,
                            'actual_href': href,
                            'display_domain': text_domain,
                            'actual_domain': href_domain
                        })
            
            return mismatched
            
        except Exception as e:
            logger.error(f"Link mismatch check error: {str(e)}")
            return []
    
    def _check_brand_impersonation(self, links):
        """Brand impersonation ստուգում"""
        try:
            impersonation_found = []
            
            for link in links:
                href = link['href']
                domain = self._extract_domain(href)
                
                if not domain:
                    continue
                
                # Ստուգել յուրաքանչյուր հայտնի բրենդի դեմ
                for brand in KNOWN_BRANDS:
                    # Fuzzy matching ratio
                    similarity = fuzz.ratio(domain.lower(), f"{brand}.com")
                    
                    # Եթե շատ նման է բայց ճիշտ չէ
                    if 70 <= similarity < 100:
                        impersonation_found.append({
                            'domain': domain,
                            'suspected_brand': brand,
                            'similarity': similarity,
                            'url': href
                        })
                    
                    # Typosquatting ստուգում
                    if brand in domain.lower() and f"{brand}.com" != domain.lower():
                        # Ստուգել common typos
                        typos = [
                            domain.replace('o', '0'),  # o->0
                            domain.replace('i', '1'),  # i->1
                            domain.replace('l', '1'),  # l->1
                            domain.replace('e', '3'),  # e->3
                        ]
                        
                        if any(typo != domain for typo in typos):
                            impersonation_found.append({
                                'domain': domain,
                                'suspected_brand': brand,
                                'type': 'typosquatting',
                                'url': href
                            })
            
            return impersonation_found
            
        except Exception as e:
            logger.error(f"Brand impersonation check error: {str(e)}")
            return []
    
    def _check_url_blacklists(self, links):
        """URL blacklist ստուգում Google Safe Browsing և PhishTank API-ներով"""
        try:
            urls = [link['href'] for link in links if link['href'].startswith('http')]
            malicious_urls = []
            
            if not urls:
                return {'malicious_count': 0, 'malicious_urls': []}
            
            # Google Safe Browsing API ստուգում
            safe_browsing_results = self._check_google_safe_browsing(urls)
            malicious_urls.extend(safe_browsing_results)
            
            # PhishTank API ստուգում (եթե կա API key)
            # phishtank_results = self._check_phishtank(urls)
            # malicious_urls.extend(phishtank_results)
            
            return {
                'malicious_count': len(malicious_urls),
                'malicious_urls': malicious_urls,
                'total_checked': len(urls)
            }
            
        except Exception as e:
            logger.error(f"URL blacklist check error: {str(e)}")
            return {'malicious_count': 0, 'malicious_urls': []}
    
    def _check_google_safe_browsing(self, urls):
        """Google Safe Browsing API ստուգում"""
        try:
            api_key = getattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY', '')
            if not api_key:
                return []
            
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            
            request_body = {
                "client": {
                    "clientId": "cyberaratta",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url} for url in urls[:100]]  # Max 100 URLs
                }
            }
            
            response = requests.post(api_url, json=request_body, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                return [match['threat']['url'] for match in matches]
            else:
                logger.warning(f"Safe Browsing API error: {response.status_code}")
                return []
            
        except Exception as e:
            logger.error(f"Google Safe Browsing check error: {str(e)}")
            return []
    
    def _check_suspicious_url_patterns(self, links):
        """Կասկածելի URL patterns ստուգում"""
        try:
            suspicious_patterns = []
            
            for link in links:
                url = link['href']
                
                # URL shorteners
                shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
                if any(shortener in url for shortener in shorteners):
                    suspicious_patterns.append(f"URL shortener օգտագործում: {url}")
                
                # IP addresses instead of domains
                ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                if re.match(ip_pattern, url):
                    suspicious_patterns.append(f"IP հասցե domain-ի փոխարեն: {url}")
                
                # Suspicious TLDs
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.loan']
                if any(tld in url for tld in suspicious_tlds):
                    suspicious_patterns.append(f"Կասկածելի TLD: {url}")
                
                # Long domains (possible IDN homograph)
                domain = self._extract_domain(url)
                if domain and len(domain) > 50:
                    suspicious_patterns.append(f"Չափազանց երկար domain: {domain}")
            
            return suspicious_patterns
            
        except Exception as e:
            logger.error(f"Suspicious URL patterns check error: {str(e)}")
            return []
    
    def _check_sender_reputation(self, email_msg):
        """Ուղարկողի reputation ստուգում"""
        try:
            from_header = email_msg.get('From', '')
            sender_domain = self._extract_domain(from_header)
            
            if not sender_domain:
                return
            
            # Նոր դոմեյン ստուգում (պարզ վերլուծություն)
            try:
                # MX record ստուգում
                mx_records = dns.resolver.resolve(sender_domain, 'MX')
                if not mx_records:
                    self.risk_score += 10
                    self.reasons.append("Ուղարկողի դոմեյնը չունի MX record")
                
            except dns.resolver.NXDOMAIN:
                self.risk_score += 30
                self.reasons.append("Ուղարկողի դոմեյնը գոյություն չունի")
            except Exception:
                pass  # DNS error, չենք գնահատում
            
            # Free email providers ստուգում
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.ru']
            if any(provider in sender_domain.lower() for provider in free_providers):
                # Եթե կորպորատիվ տիպի subject կա բայց free email է
                subject = email_msg.get('Subject', '').lower()
                corporate_keywords = ['invoice', 'payment', 'account', 'verify', 'suspended']
                if any(keyword in subject for keyword in corporate_keywords):
                    self.risk_score += 15
                    self.reasons.append("Free email provider-ից կորպորատիվ տիպի հաղորդագրություն")
            
        except Exception as e:
            logger.error(f"Sender reputation check error: {str(e)}")
    
    def _extract_domain(self, email_or_url):
        """Email կամ URL-ից domain հանում"""
        try:
            if '@' in email_or_url:
                # Email format
                return email_or_url.split('@')[-1].strip('<>')
            elif email_or_url.startswith('http'):
                # URL format
                parsed = urlparse(email_or_url)
                return parsed.netloc
            else:
                return None
        except Exception:
            return None
    
    def _calculate_final_status(self):
        """Վերջնական status հաշվարկ"""
        if self.risk_score >= 50:
            return 'likely_phishing'
        elif self.risk_score >= 25:
            return 'suspicious'
        else:
            return 'safe'
    
    def _create_error_result(self, error_message):
        """Error result ստեղծում"""
        return {
            'status': 'error',
            'risk_score': 0,
            'reasons': [error_message],
            'details': {},
            'total_checks': 0
        }


def get_email_provider_instructions():
    """Email provider-ների համաձայն raw email ստանալու ցուցումներ"""
    return {
        'gmail': {
            'name': 'Gmail',
            'steps': [
                'Բացեք email-ը Gmail-ում',
                'Սեղմեք "Show original" կամ "..." → "Show original"',
                'Կոպի արեք ամբողջ raw email-ը',
                'Paste արեք ներքևի դաշտում'
            ],
            'icon': 'fab fa-google'
        },
        'outlook': {
            'name': 'Outlook/Hotmail',
            'steps': [
                'Բացեք email-ը Outlook-ում',
                'Սեղմեք "..." → "View message source"',
                'Կոպի արեք ամբողջ source code-ը',
                'Paste արեք ներքևի դաշտում'
            ],
            'icon': 'fab fa-microsoft'
        },
        'yahoo': {
            'name': 'Yahoo Mail',
            'steps': [
                'Բացեք email-ը Yahoo Mail-ում',
                'Սեղմեք "More" → "View Raw Message"',
                'Կոպի արեք ամբողջ raw content-ը',
                'Paste արեք ներքևի դաշտում'
            ],
            'icon': 'fab fa-yahoo'
        },
        'mailru': {
            'name': 'Mail.ru',
            'steps': [
                'Բացեք email-ը Mail.ru-ում',
                'Սեղմեք "Еще" → "Исходный код письма"',
                'Կոպի արեք ամբողջ կոդը',
                'Paste արեք ներքևի դաշտում'
            ],
            'icon': 'fas fa-envelope'
        }
    }


# Sample email for testing
SAMPLE_PHISHING_EMAIL = """Return-Path: <no-reply@paypa1-security.com>
Delivered-To: user@example.com
Received: by 2002:a17:90a:abc0:0:0:0:0 with SMTP id example123csp456789
From: "PayPal Security" <security@paypa1-security.com>
To: user@example.com
Subject: Urgent: Your PayPal Account Has Been Limited
Date: Thu, 31 Jul 2025 10:30:00 +0000
Message-ID: <123456789@paypa1-security.com>
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h2>PayPal Account Limited</h2>
<p>Dear Valued Customer,</p>
<p>We have detected suspicious activity on your PayPal account and have temporarily limited access for your security.</p>
<p>Please verify your account immediately by clicking the link below:</p>
<a href="http://192.168.1.100/paypal-verify">Click Here to Verify Your PayPal Account</a>
<p>If you do not verify within 24 hours, your account will be permanently suspended.</p>
<p>Thank you,<br>PayPal Security Team</p>
</body>
</html>"""
