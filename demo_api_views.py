"""
Enhanced API endpoints for demo
"""
from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count, Q
from apps.threat_map.models import Threat, PhishingURL, CyberThreatIntelligence
from apps.reporting.models import PhishingReport
from apps.url_checker.models import URLCheck
from apps.quiz.models import Question, QuizCategory
import random

def live_demo_stats_api(request):
    """Enhanced stats for live demo"""
    last_month = timezone.now() - timedelta(days=30)
    last_week = timezone.now() - timedelta(days=7)
    last_24h = timezone.now() - timedelta(hours=24)
    
    # Generate some dynamic numbers for demo
    base_threats = Threat.objects.filter(reported_at__gte=last_month).count()
    base_reports = PhishingReport.objects.count()
    
    # Add some randomness for live effect
    current_hour = timezone.now().hour
    dynamic_modifier = (current_hour % 5) + random.randint(0, 3)
    
    stats = {
        'total_threats': base_threats + dynamic_modifier,
        'recent_threats': Threat.objects.filter(reported_at__gte=last_24h).count() + random.randint(0, 2),
        'total_reports': base_reports + dynamic_modifier,
        'recent_reports': PhishingReport.objects.filter(created_at__gte=last_week).count(),
        'url_checks': URLCheck.objects.filter(checked_at__gte=last_month).count(),
        'phishing_urls': PhishingURL.objects.filter(is_active=True).count(),
        'threat_intelligence': CyberThreatIntelligence.objects.count(),
        'quiz_questions': Question.objects.count(),
        
        # Live threat map data
        'live_attacks': random.randint(8, 20),
        'source_countries': random.randint(5, 12),
        'threat_level': random.choice(['low', 'medium', 'high']),
        
        # Platform breakdown
        'platform_stats': [
            {'name': 'Facebook', 'count': random.randint(15, 40)},
            {'name': 'Instagram', 'count': random.randint(10, 35)},
            {'name': 'Telegram', 'count': random.randint(8, 25)},
            {'name': 'SMS', 'count': random.randint(12, 30)},
            {'name': 'Email', 'count': random.randint(20, 45)},
        ],
        
        # Recent activity (last 5 minutes simulation)
        'recent_activity': [
            {
                'type': 'phishing_detected',
                'message': 'Նոր ֆիշինգ կայք հայտնաբերվել է',
                'url': 'https://fake-bank-' + str(random.randint(100, 999)) + '.net',
                'timestamp': (timezone.now() - timedelta(minutes=random.randint(1, 5))).isoformat()
            },
            {
                'type': 'threat_blocked',
                'message': 'DDoS հարձակում արգելափակվել է',
                'source': random.choice(['Russia', 'China', 'Iran']),
                'timestamp': (timezone.now() - timedelta(minutes=random.randint(2, 8))).isoformat()
            },
            {
                'type': 'report_received',
                'message': 'Նոր ֆիշինգ հաղորդագրություն ստացվել է',
                'platform': random.choice(['Telegram', 'WhatsApp', 'SMS']),
                'timestamp': (timezone.now() - timedelta(minutes=random.randint(3, 10))).isoformat()
            }
        ],
        
        'last_updated': timezone.now().isoformat()
    }
    
    return JsonResponse(stats)

def demo_threat_feed_api(request):
    """Live threat feed for demo"""
    threats = []
    
    # Generate realistic threat data
    threat_types = [
        'DDoS Attack', 'Malware Distribution', 'Phishing Campaign',
        'Brute Force', 'SQL Injection', 'Data Breach Attempt',
        'Ransomware', 'APT Activity', 'Bot Network'
    ]
    
    source_countries = [
        {'name': 'Russia', 'threat': 'high', 'flag': '🇷🇺'},
        {'name': 'China', 'threat': 'medium', 'flag': '🇨🇳'},
        {'name': 'Iran', 'threat': 'high', 'flag': '🇮🇷'},
        {'name': 'Turkey', 'threat': 'medium', 'flag': '🇹🇷'},
        {'name': 'North Korea', 'threat': 'high', 'flag': '🇰🇵'},
        {'name': 'Azerbaijan', 'threat': 'medium', 'flag': '🇦🇿'}
    ]
    
    for i in range(random.randint(10, 25)):
        source = random.choice(source_countries)
        threat_type = random.choice(threat_types)
        
        threats.append({
            'id': f'threat_{timezone.now().timestamp()}_{i}',
            'type': threat_type,
            'source_country': source['name'],
            'source_flag': source['flag'],
            'severity': source['threat'],
            'target': 'Armenia 🇦🇲',
            'timestamp': (timezone.now() - timedelta(hours=random.randint(0, 24))).isoformat(),
            'ip': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'description': f'{threat_type} detected from {source["name"]} targeting Armenian infrastructure',
            'status': random.choice(['active', 'blocked', 'investigating'])
        })
    
    return JsonResponse({
        'threats': sorted(threats, key=lambda x: x['timestamp'], reverse=True),
        'total_count': len(threats),
        'last_updated': timezone.now().isoformat()
    })

def demo_quiz_stats_api(request):
    """Quiz statistics for demo"""
    categories = QuizCategory.objects.all()
    category_stats = []
    
    for category in categories:
        questions_count = Question.objects.filter(category=category).count()
        category_stats.append({
            'name': category.name,
            'questions_count': questions_count,
            'difficulty_avg': random.randint(1, 3),
            'completion_rate': random.randint(65, 95),
            'category_type': category.get_category_type_display() if hasattr(category, 'get_category_type_display') else 'General'
        })
    
    return JsonResponse({
        'categories': category_stats,
        'total_questions': Question.objects.count(),
        'total_attempts': random.randint(150, 300),
        'average_score': random.randint(70, 85),
        'last_updated': timezone.now().isoformat()
    })

def demo_url_checker_stats_api(request):
    """URL checker statistics for demo"""
    last_month = timezone.now() - timedelta(days=30)
    
    url_stats = {
        'total_checks': URLCheck.objects.count(),
        'recent_checks': URLCheck.objects.filter(checked_at__gte=last_month).count(),
        'safe_urls': URLCheck.objects.filter(status='safe').count(),
        'suspicious_urls': URLCheck.objects.filter(status='suspicious').count(),
        'malicious_urls': URLCheck.objects.filter(status='malicious').count(),
        
        # Recent scans simulation
        'recent_scans': [
            {
                'url': 'https://suspicious-site-' + str(random.randint(100, 999)) + '.net',
                'status': random.choice(['safe', 'suspicious', 'malicious']),
                'confidence': random.randint(75, 99),
                'scan_time': (timezone.now() - timedelta(minutes=random.randint(1, 30))).isoformat()
            }
            for _ in range(5)
        ],
        
        'scanning_engines': [
            {'name': 'VirusTotal', 'status': 'online', 'response_time': random.randint(200, 800)},
            {'name': 'Google Safe Browsing', 'status': 'online', 'response_time': random.randint(150, 600)},
            {'name': 'Kaspersky', 'status': 'online', 'response_time': random.randint(300, 900)},
            {'name': 'Internal Scanner', 'status': 'online', 'response_time': random.randint(100, 400)}
        ],
        
        'last_updated': timezone.now().isoformat()
    }
    
    return JsonResponse(url_stats)

def demo_reporting_stats_api(request):
    """Reporting module statistics for demo"""
    last_month = timezone.now() - timedelta(days=30)
    last_week = timezone.now() - timedelta(days=7)
    
    # Category breakdown
    category_breakdown = []
    categories = ['banking', 'social_media', 'sms', 'email', 'cryptocurrency', 'government', 'other']
    
    for category in categories:
        count = PhishingReport.objects.filter(category=category).count()
        if count > 0:
            category_breakdown.append({
                'category': category,
                'count': count,
                'percentage': round((count / PhishingReport.objects.count()) * 100, 1),
                'trend': random.choice(['up', 'down', 'stable'])
            })
    
    reporting_stats = {
        'total_reports': PhishingReport.objects.count(),
        'pending_reports': PhishingReport.objects.filter(status='pending').count(),
        'resolved_reports': PhishingReport.objects.filter(status='resolved').count(),
        'recent_reports': PhishingReport.objects.filter(created_at__gte=last_week).count(),
        
        'category_breakdown': category_breakdown,
        
        'recent_submissions': [
            {
                'id': report.id,
                'category': report.get_category_display(),
                'platform': report.platform_source.name if report.platform_source else 'Unknown',
                'status': report.get_status_display() if hasattr(report, 'get_status_display') else 'Pending',
                'submitted': report.created_at.isoformat(),
                'url_preview': report.suspicious_url[:50] + '...' if len(report.suspicious_url) > 50 else report.suspicious_url
            }
            for report in PhishingReport.objects.order_by('-created_at')[:5]
        ],
        
        'platform_distribution': [
            {
                'platform': platform.name,
                'count': PhishingReport.objects.filter(platform_source=platform).count()
            }
            for platform in PhishingReport.objects.values_list('platform_source__name', flat=True).distinct()[:8]
            if platform
        ],
        
        'last_updated': timezone.now().isoformat()
    }
    
    return JsonResponse(reporting_stats)
