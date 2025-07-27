#!/usr/bin/env python
"""
Demo Data Population Script for CyberAratta
Creates comprehensive test data for all modules
"""

import os
import sys
import django
from datetime import datetime, timedelta
from django.utils import timezone
import random

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberaratta.settings')
django.setup()

from django.contrib.auth.models import User
from apps.reporting.models import PhishingReport, PlatformSource, ContactInfo
from apps.url_checker.models import URLCheck, UrlCheckResult
from apps.threat_map.models import Threat, PhishingURL, CyberThreatIntelligence
from apps.quiz.models import Question, Answer, QuizCategory

class DemoDataPopulator:
    def __init__(self):
        self.platforms = []
        self.contacts = []
        self.users = []
        
    def create_platforms(self):
        """Create platform sources"""
        platforms_data = [
            'Facebook', 'Instagram', 'Telegram', 'WhatsApp', 'Viber',
            'SMS', 'Email', 'Website', 'Phone Call', 'Mobile App'
        ]
        
        for name in platforms_data:
            platform, created = PlatformSource.objects.get_or_create(name=name)
            self.platforms.append(platform)
            if created:
                print(f"✅ Created platform: {platform.name}")
    
    def create_contacts(self):
        """Create contact information"""
        contacts_data = [
            {
                'name': 'ԱՄՆ Դեսպանություն - Անվտանգության բաժին',
                'description': 'ԱՄՆ քաղաքացիների համար',
                'phone': '+374-10-464-700',
                'email': 'security@usembassy.am',
                'order': 1,
                'is_emergency': True
            },
            {
                'name': 'Հայաստանի Ոստիկանություն - Կիբեռ ոստիկանություն',
                'description': 'Կիբեռ հանցագործությունների մասին հաղորդում',
                'phone': '102',
                'email': 'cyber@police.am',
                'order': 2,
                'is_emergency': True
            },
            {
                'name': 'ՏԿՏՆ - Կիբեռ անվտանգության կենտրոն',
                'description': 'Տեխնոլոգիական անվտանգության հարցեր',
                'phone': '+374-11-300-300',
                'email': 'cert@mincom.am',
                'order': 3
            },
            {
                'name': 'Բանկային հաճախորդների ծառայություն',
                'description': 'Ֆինանսական կազմակերպությունների հետ կապված',
                'phone': '(+374) call center',
                'email': 'support@bank.am',
                'order': 4
            },
        ]
        
        for data in contacts_data:
            contact, created = ContactInfo.objects.get_or_create(
                name=data['name'],
                defaults=data
            )
            self.contacts.append(contact)
            if created:
                print(f"✅ Created contact: {contact.name}")
    
    def create_users(self):
        """Create demo users"""
        users_data = [
            {'username': 'admin', 'email': 'admin@cyberaratta.am', 'is_staff': True, 'is_superuser': True},
            {'username': 'analyst', 'email': 'analyst@cyberaratta.am', 'is_staff': True},
            {'username': 'reporter', 'email': 'reporter@cyberaratta.am'},
        ]
        
        for data in users_data:
            user, created = User.objects.get_or_create(
                username=data['username'],
                defaults={
                    'email': data['email'],
                    'is_staff': data.get('is_staff', False),
                    'is_superuser': data.get('is_superuser', False),
                    'first_name': data['username'].title(),
                    'last_name': 'Demo'
                }
            )
            if created:
                user.set_password('demo123')
                user.save()
                print(f"✅ Created user: {user.username}")
            self.users.append(user)
    
    def create_phishing_reports(self):
        """Create comprehensive phishing reports"""
        categories = ['banking', 'social_media', 'sms', 'email', 'cryptocurrency', 'government', 'other']
        suspicious_urls = [
            'https://fakebank-armenia.com/login',
            'https://ardshinbank-secure.net/transfer',
            'https://inecobank-verification.org/confirm',
            'https://facebook-security-check.net/login',
            'https://instagram-verify-account.com/verify',
            'https://telegram-premium-free.org/activate',
            'https://whatsapp-backup-restore.net/backup',
            'https://gov-am-services.org/register',
            'https://tax-service-armenia.net/declaration',
            'https://covid-vaccine-registration.am/book',
            'https://bitcoin-armenia-exchange.com/trade',
            'https://ethereum-mining-armenia.org/start',
            'https://freelance-jobs-armenia.net/apply',
            'https://online-shopping-armenia.com/deals',
            'https://mobile-recharge-armenia.org/topup'
        ]
        
        descriptions = [
            'Կեղծ բանկային կայք, որը փորձում է գողանալ մուտքի տվյալները',
            'Ֆիշինգ SMS հաղորդագրություն բանկային քարտի մանրամասներով',
            'Կեղծ սոցիալական ցանցի էջ անձնական տվյալների հավաքման համար',
            'Խաբեբայական էլ. նամակ՝ մրցույթի մասին',
            'Կիբեռ գրոհ՝ նպատակաուղղված պետական կառույցների վրա',
            'Կեղծ COVID-19 պատվաստման գրանցման կայք',
            'Կրիպտոարժույթի խաբկանքի կայք',
            'Կեղծ աշխատանքի առաջարկություն',
            'Ֆիշինգ հարձակում մոբայլ բանկինգի միջոցով',
            'Կեղծ գովերանական ծառայությունների կայք',
            'Խաբեբայական առևտրային կայք',
            'Կեղծ տեխնիկական աջակցության զանգ',
            'Վնասակար հավելված Google Play-ից',
            'Ֆիշինգ էջ բանկային հավելվածի անունով',
            'Կեղծ նվերների և մրցույթների կայք'
        ]
        
        for i in range(50):
            # Random date within last 30 days
            days_ago = random.randint(0, 30)
            report_date = timezone.now() - timedelta(days=days_ago)
            
            report = PhishingReport.objects.create(
                suspicious_url=random.choice(suspicious_urls),
                description=random.choice(descriptions),
                category=random.choice(categories),
                platform_source=random.choice(self.platforms),
                contact_info=f'reporter{i+1}@example.com, +374-XX-{random.randint(100000, 999999)}',
                created_at=report_date
            )
            
        print(f"✅ Created 50 phishing reports")
    
    def create_url_checks(self):
        """Create URL checker results"""
        urls_to_check = [
            'https://facebook.com', 'https://google.com', 'https://microsoft.com',
            'https://suspicious-site.net', 'https://malware-host.org', 'https://phishing-example.com',
            'https://ardshinbank.am', 'https://inecobank.am', 'https://ameria.am',
            'https://gov.am', 'https://mfa.am', 'https://police.am',
            'https://fake-bank.scam', 'https://virus-download.net', 'https://steal-data.org'
        ]
        
        statuses = ['safe', 'suspicious', 'malicious']
        status_weights = [0.6, 0.3, 0.1]  # 60% safe, 30% suspicious, 10% malicious
        
        for i in range(100):
            days_ago = random.randint(0, 30)
            check_date = timezone.now() - timedelta(days=days_ago)
            
            url = random.choice(urls_to_check)
            status = random.choices(statuses, weights=status_weights)[0]
            
            url_check = URLCheck.objects.create(
                input_text=url,
                status=status,
                checked_at=check_date,
                analysis_result=f'Scan result: {status} - confidence: {random.randint(70, 99)}%'
            )
            
            # Create scan result
            UrlCheckResult.objects.create(
                url_check=url_check,
                virustotal_result={
                    'scanner': 'VirusTotal',
                    'result': status,
                    'confidence': random.randint(70, 99),
                    'details': f'VirusTotal scan for {url} - {status}'
                },
                kaspersky_result={
                    'scanner': 'Kaspersky',
                    'result': status,
                    'confidence': random.randint(70, 99),
                    'details': f'Kaspersky scan for {url} - {status}'
                }
            )
        
        print(f"✅ Created 100 URL checks with scan results")
    
    def create_threats(self):
        """Create threat intelligence data"""
        threat_types = [
            'DDoS Attack', 'Malware Distribution', 'Phishing Campaign',
            'Brute Force', 'SQL Injection', 'Data Breach Attempt',
            'Ransomware', 'APT Activity', 'Bot Network'
        ]
        
        source_countries = [
            'Russia', 'China', 'Iran', 'Turkey', 'North Korea',
            'Azerbaijan', 'USA', 'Germany', 'Ukraine', 'Belarus'
        ]
        
        severities = ['low', 'medium', 'high']
        severity_weights = [0.4, 0.4, 0.2]
        
        for i in range(80):
            days_ago = random.randint(0, 30)
            threat_date = timezone.now() - timedelta(days=days_ago)
            
            threat_type = random.choice(threat_types)
            source_country = random.choice(source_countries)
            severity = random.choices(severities, weights=severity_weights)[0]
            
            threat = Threat.objects.create(
                type=threat_type,
                source_country=source_country,
                severity=severity,
                description=f'{threat_type} attack detected from {source_country}',
                reported_at=threat_date,
                is_active=random.choice([True, False])
            )
        
        print(f"✅ Created 80 threat intelligence records")
    
    def create_phishing_urls(self):
        """Create phishing URL database"""
        # Get some existing reports to link with
        existing_reports = list(PhishingReport.objects.all()[:15])
        
        if not existing_reports:
            print("⚠️ No PhishingReports found, skipping PhishingURL creation")
            return
            
        phishing_domains = [
            'fake-ardshinbank.net', 'phishing-inecobank.org', 'scam-ameria.com',
            'fake-gov-am.net', 'phishing-police.org', 'scam-tax.am',
            'fake-facebook.net', 'phishing-instagram.com', 'scam-telegram.org',
            'bitcoin-scam.net', 'ethereum-fake.org', 'crypto-phishing.com',
            'job-scam-armenia.net', 'fake-shopping.am', 'phishing-delivery.org'
        ]
        
        categories = ['banking', 'government', 'social_media', 'cryptocurrency', 'employment', 'shopping']
        
        for i, domain in enumerate(phishing_domains):
            days_ago = random.randint(0, 30)
            creation_date = timezone.now() - timedelta(days=days_ago)
            
            # Use existing report or create reference
            source_report = random.choice(existing_reports)
            
            phishing_url = PhishingURL.objects.create(
                url=f'https://{domain}',
                source_report=source_report,
                category=random.choice(categories),
                platform_source=random.choice(['Website', 'Email', 'SMS', 'Social Media']),
                is_active=random.choice([True, False]),
                status_code=random.choice([200, 404, 403]),
                created_at=creation_date,
                last_checked=creation_date + timedelta(hours=random.randint(1, 24))
            )
        
        print(f"✅ Created {len(phishing_domains)} phishing URLs")
    
    def create_quiz_questions(self):
        """Create cybersecurity quiz questions"""
        
        # Create categories first
        categories_data = [
            {'name': 'Ֆիշինգ', 'category_type': 'school', 'description': 'Ֆիշինգ հարձակումների մասին'},
            {'name': 'Գաղտնաբառեր', 'category_type': 'student', 'description': 'Անվտանգ գաղտնաբառերի մասին'},
            {'name': 'Էլ. փոստի անվտանգություն', 'category_type': 'professional', 'professional_field': 'it', 'description': 'Էլեկտրոնային փոստի անվտանգություն'},
            {'name': 'Վնասակար ծրագրեր', 'category_type': 'school', 'description': 'Malware-ի մասին'},
        ]
        
        quiz_categories = []
        for cat_data in categories_data:
            category, created = QuizCategory.objects.get_or_create(
                name=cat_data['name'],
                defaults=cat_data
            )
            quiz_categories.append(category)
            if created:
                print(f"✅ Created quiz category: {category.name}")
        
        questions_data = [
            {
                'question_text': 'Ինչ է ֆիշինգը?',
                'category': quiz_categories[0],
                'difficulty': 1,
                'question_type': 'classic',
                'answers': [
                    {'answer_text': 'Ձկնորսություն', 'is_correct': False},
                    {'answer_text': 'Անձնական տվյալների գողացում կեղծ կայքերի միջոցով', 'is_correct': True},
                    {'answer_text': 'Ծրագրային ապահովման տեղադրում', 'is_correct': False},
                    {'answer_text': 'Համակարգչային խաղ', 'is_correct': False}
                ]
            },
            {
                'question_text': 'Ինչ է ուժեղ գաղտնաբառը?',
                'category': quiz_categories[1],
                'difficulty': 2,
                'question_type': 'classic',
                'answers': [
                    {'answer_text': 'Միայն տառեր', 'is_correct': False},
                    {'answer_text': '8+ նիշ, տառեր, թվեր, սիմվոլներ', 'is_correct': True},
                    {'answer_text': 'Միայն ծանոթ բառեր', 'is_correct': False},
                    {'answer_text': 'Ծննդյան թվականը', 'is_correct': False}
                ]
            },
            {
                'question_text': 'Ինչ անել կասկածելի էլ. նամակ ստանալիս?',
                'category': quiz_categories[2],
                'difficulty': 2,
                'question_type': 'classic',
                'answers': [
                    {'answer_text': 'Անմիջապես բացել բոլոր հղումները', 'is_correct': False},
                    {'answer_text': 'Ջնջել առանց բացելու', 'is_correct': True},
                    {'answer_text': 'Փոխանցել բոլոր ծանոթներին', 'is_correct': False},
                    {'answer_text': 'Տպել և պահել', 'is_correct': False}
                ]
            },
            {
                'question_text': 'Ինչ է վնասակար ծրագիրը (malware)?',
                'category': quiz_categories[3],
                'difficulty': 1,
                'question_type': 'classic',
                'answers': [
                    {'answer_text': 'Օգտակար ծրագիր', 'is_correct': False},
                    {'answer_text': 'Համակարգչին վնաս հասցնող ծրագիր', 'is_correct': True},
                    {'answer_text': 'Ծրագրային թարմացում', 'is_correct': False},
                    {'answer_text': 'Անվտանգության ծրագիր', 'is_correct': False}
                ]
            },
            {
                'question_text': 'Ռանսոմվեր ծրագիրները ինչ են անում?',
                'category': quiz_categories[3],
                'difficulty': 3,
                'question_type': 'millionaire',
                'answers': [
                    {'answer_text': 'Ֆայլերը կոդավորում են և փոխարկում պահանջում', 'is_correct': True},
                    {'answer_text': 'Համակարգչը արագացնում են', 'is_correct': False},
                    {'answer_text': 'Վիրուսները ջնջում են', 'is_correct': False},
                    {'answer_text': 'Նոր ծրագրեր տեղադրում են', 'is_correct': False}
                ]
            }
        ]
        
        for q_data in questions_data:
            question = Question.objects.create(
                question_text=q_data['question_text'],
                category=q_data['category'],
                difficulty=q_data['difficulty'],
                question_type=q_data['question_type'],
                points=10 * q_data['difficulty']
            )
            
            for a_data in q_data['answers']:
                Answer.objects.create(
                    question=question,
                    answer_text=a_data['answer_text'],
                    is_correct=a_data['is_correct']
                )
        
        print(f"✅ Created {len(questions_data)} quiz questions with answers")
    
    def create_cyber_threat_intelligence(self):
        """Create cyber threat intelligence data"""
        source_feeds = [
            'VirusTotal', 'Kaspersky', 'Symantec', 'FireEye', 'CrowdStrike',
            'Internal Analysis', 'CERT-AM', 'Government Sources'
        ]
        
        threat_types = [
            'APT Activity', 'Malware Campaign', 'Phishing Operation',
            'DDoS Botnet', 'Ransomware Group', 'Data Exfiltration',
            'Credential Theft', 'Supply Chain Attack', 'Zero-day Exploit'
        ]
        
        source_countries = [
            'Russia', 'China', 'Iran', 'North Korea', 'Turkey',
            'Azerbaijan', 'Unknown', 'Multiple'
        ]
        
        target_sectors = [
            'Government', 'Banking', 'Healthcare', 'Education',
            'Energy', 'Telecommunications', 'Defense', 'Critical Infrastructure'
        ]
        
        for i in range(30):
            days_ago = random.randint(0, 15)
            intel_date = timezone.now() - timedelta(days=days_ago)
            
            threat_type = random.choice(threat_types)
            source_country = random.choice(source_countries)
            
            intel = CyberThreatIntelligence.objects.create(
                threat_type=threat_type,
                source_country=source_country,
                target_sector=random.choice(target_sectors),
                description=f'{threat_type} detected from {source_country} targeting Armenian infrastructure',
                confidence_level=random.choice(['low', 'medium', 'high']),
                source_feed=random.choice(source_feeds),
                detected_at=intel_date
            )
        
        print(f"✅ Created 30 cyber threat intelligence records")
    
    def run_all(self):
        """Run all data population methods"""
        print("🚀 Starting demo data population for CyberAratta...")
        print("=" * 60)
        
        try:
            self.create_users()
            self.create_platforms()
            self.create_contacts()
            self.create_phishing_reports()
            self.create_url_checks()
            self.create_threats()
            self.create_phishing_urls()
            self.create_quiz_questions()
            self.create_cyber_threat_intelligence()
            
            print("=" * 60)
            print("✅ Demo data population completed successfully!")
            print("📊 Summary:")
            print(f"   - Users: {User.objects.count()}")
            print(f"   - Platforms: {PlatformSource.objects.count()}")
            print(f"   - Contacts: {ContactInfo.objects.count()}")
            print(f"   - Phishing Reports: {PhishingReport.objects.count()}")
            print(f"   - URL Checks: {URLCheck.objects.count()}")
            print(f"   - Threats: {Threat.objects.count()}")
            print(f"   - Phishing URLs: {PhishingURL.objects.count()}")
            print(f"   - Quiz Questions: {Question.objects.count()}")
            print(f"   - Threat Intelligence: {CyberThreatIntelligence.objects.count()}")
            print("\n🎬 Ready for demo!")
            
        except Exception as e:
            print(f"❌ Error during data population: {e}")
            sys.exit(1)

if __name__ == '__main__':
    populator = DemoDataPopulator()
    populator.run_all()
