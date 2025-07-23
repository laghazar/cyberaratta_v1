#!/usr/bin/env python3
"""
Test data generator for CyberAratta platform
"""

import os
import sys
import django
from datetime import datetime, timedelta
from random import choice, randint

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberaratta.settings')
django.setup()

# Import models
from apps.reporting.models import PhishingReport, ContactInfo, ContactGuideline
from apps.threat_map.models import Threat, PhishingURL, CyberThreatIntelligence
from apps.quiz.models import Question, Answer, QuizCategory
from apps.url_checker.models import URLCheck
from django.contrib.auth.models import User

def create_test_data():
    print("🔄 Ստեղծում են տեստային տվյալներ...")
    
    # 1. Phishing Reports
    print("📊 Ավելացնում եմ phishing reports...")
    platforms = ['facebook', 'instagram', 'telegram', 'whatsapp', 'email', 'sms']
    categories = ['banking', 'social_media', 'cryptocurrency', 'government', 'other']
    
    for i in range(20):
        PhishingReport.objects.create(
            category=choice(categories),
            description=f"Տեստային ֆիշինգ զեկուցում #{i+1} - կասկածելի գործունեություն հայտնաբերված է",
            platform_source=choice(platforms),
            suspicious_url=f"https://fake-site-{i+1}.malicious.com/login",
            suspicious_email=f"scammer{i+1}@fake-domain.com",
            contact_info=f"test-user{i+1}@email.com",
            is_anonymous=choice([True, False]),
            severity=choice(['low', 'medium', 'high', 'critical']),
            status=choice(['pending', 'investigating', 'resolved'])
        )
    
    # 2. Threats
    print("🚨 Ավելացնում եմ threats...")
    threat_types = ['phishing', 'malware', 'ddos', 'data_breach', 'ransomware']
    countries = ['Russia', 'China', 'Iran', 'North Korea', 'Unknown', 'Turkey']
    
    for i in range(15):
        Threat.objects.create(
            type=choice(threat_types),
            source_country=choice(countries),
            target_country='Armenia',
            severity=choice(['low', 'medium', 'high', 'critical']),
            description=f"Կիբեր սպառնալիք #{i+1} - {choice(threat_types)} հարձակում",
            is_active=choice([True, False]),
            ip_address=f"192.168.{randint(1,255)}.{randint(1,255)}"
        )
    
    # 3. Contact Info & Guidelines
    print("📞 Ավելացնում եմ contact info...")
    contacts_data = [
        {
            'name': 'Հայաստանի Հանրապետության Ոստիկանություն',
            'description': 'Կիբեր հանցագործությունների բաժին',
            'phone': '+374-10-54-69-14',
            'email': 'cyber@police.am',
            'website': 'https://www.police.am',
            'is_emergency': True,
            'order': 1
        },
        {
            'name': 'ԱԱԾ Կիբեր Անվտանգության Կենտրոն',
            'description': 'Ազգային կիբեր անվտանգության ծառայություն',
            'phone': '+374-10-56-11-23',
            'email': 'info@csc.am',
            'website': 'https://www.csc.am',
            'is_emergency': False,
            'order': 2
        },
        {
            'name': 'Կենտրոնական Բանկ',
            'description': 'Ֆինանսական համակարգի անվտանգություն',
            'phone': '+374-10-58-38-41',
            'email': 'info@cba.am',
            'website': 'https://www.cba.am',
            'is_emergency': False,
            'order': 3
        }
    ]
    
    for contact_data in contacts_data:
        contact_info, created = ContactInfo.objects.get_or_create(
            name=contact_data['name'],
            defaults=contact_data
        )
        
        if created:
            # Create guideline for this contact
            ContactGuideline.objects.create(
                contact=contact_info,
                when_to_contact="Երբ հայտնաբերվում են կիբեր հանցագործության նշաններ",
                required_documents="Անձնագիր, վկայություններ, screenshot-ներ",
                process_description="Դիմում ներկայացրեք 24 ժամվա ընթացքում",
                response_time="48-72 ժամ",
                additional_info="Լրացուցիչ տեղեկությունների համար զանգահարեք",
                is_active=True
            )
    
    # 4. Quiz Questions
    print("❓ Ավելացնում եմ quiz questions...")
    
    # First create a category
    category, created = QuizCategory.objects.get_or_create(
        name='Կիբեր Անվտանգություն',
        defaults={
            'category_type': 'professional',
            'professional_field': 'it',
            'description': 'Կիբեր անվտանգության հիմունքներ',
            'is_active': True
        }
    )
    
    quiz_questions = [
        {
            'text': 'Ինչպիսի նշան է ֆիշինգ էլ. նամակի?',
            'options': [
                ('Անհայտ ուղարկող', True),
                ('Պաշտոնական ուղարկող', False),
                ('Հայտնի ընկերություն', False),
                ('Գործընկեր', False)
            ]
        },
        {
            'text': 'Ինչ պետք է անել կասկածելի հղում ստանալիս?',
            'options': [
                ('Անմիջապես սեղմել', False),
                ('Ուղարկել ընկերներին', False),
                ('Ստուգել URL-ը', True),
                ('Արհամարհել', False)
            ]
        },
        {
            'text': 'Ինչպիսի գաղտնաբառ է ամենաանվտանգը?',
            'options': [
                ('123456', False),
                ('password', False),
                ('MyName123', False),
                ('R@nd0m!P@ssw0rd#2024', True)
            ]
        }
    ]
    
    for q_data in quiz_questions:
        question, created = Question.objects.get_or_create(
            question_text=q_data['text'],
            defaults={
                'question_type': 'classic',
                'category': category,
                'difficulty': randint(1, 3),
                'points': 10,
                'explanation': 'Կիբեր անվտանգության հիմունքներ',
                'is_active': True
            }
        )
        
        if created:
            for option_text, is_correct in q_data['options']:
                Answer.objects.create(
                    question=question,
                    answer_text=option_text,
                    is_correct=is_correct
                )
    
    # 5. URL Checks
    print("🔗 Ավելացնում եմ URL checks...")
    test_urls = [
        'https://suspicious-banking-site.fake.com',
        'https://phishing-social-media.scam.net',
        'https://fake-government-portal.mal.org',
        'https://cryptocurrency-scam.fake.co',
        'https://malicious-download.virus.com'
    ]
    
    for url in test_urls:
        URLCheck.objects.create(
            input_text=url,
            status=choice(['safe', 'suspicious', 'malicious']),
            source='Test Data',
            analysis_result=f'Հայտնաբերվել է {randint(0, 5)} վտանգ',
        )
    
    # 6. Cyber Threat Intelligence
    print("🔍 Ավելացնում եմ cyber threat intelligence...")
    for i in range(10):
        CyberThreatIntelligence.objects.create(
            threat_type=choice(['APT', 'Botnet', 'Ransomware', 'Phishing Campaign']),
            source_country=choice(countries),
            target_sector=choice(['Banking', 'Government', 'Healthcare', 'Education']),
            description=f"Հետախուզական տվյալներ #{i+1} - նոր սպառնալիք հայտնաբերված",
            confidence_level=choice(['low', 'medium', 'high']),
            source_feed=choice(['OSINT', 'Commercial Feed', 'Government Source'])
        )
    
    print("✅ Տեստային տվյալները հաջողությամբ ստեղծվեցին!")
    print(f"📊 Ստեղծվեց:")
    print(f"   - {PhishingReport.objects.count()} Phishing Reports")
    print(f"   - {Threat.objects.count()} Threats")
    print(f"   - {ContactInfo.objects.count()} Contact Info")
    print(f"   - {ContactGuideline.objects.count()} Contact Guidelines")
    print(f"   - {Question.objects.count()} Quiz Questions")
    print(f"   - {URLCheck.objects.count()} URL Checks")
    print(f"   - {CyberThreatIntelligence.objects.count()} Threat Intelligence")

if __name__ == '__main__':
    create_test_data()
