from django.shortcuts import render
from django.utils import timezone
from django.http import JsonResponse
from datetime import timedelta
from django.db.models import Count, Q
from .models import Threat, PhishingURL, CyberThreatIntelligence
from apps.reporting.models import PhishingReport
from apps.url_checker.models import URLCheck
import requests
from urllib.parse import urlparse

def threat_map_view(request):
    """Կիբեռ սպառնալիքների ինտերակտիվ քարտեզ"""
    from apps.reporting.models import ContactGuideline
    
    last_month = timezone.now() - timedelta(days=30)
    last_week = timezone.now() - timedelta(days=7)
    today = timezone.now().date()
    
    # Get phishing URLs from reports
    phishing_urls = get_phishing_urls_from_reports()
    
    # Get URL checker results
    url_checker_results = URLCheck.objects.filter(
        checked_at__gte=last_month,
        status__in=['suspicious', 'malicious']
    ).order_by('-checked_at')[:50]
    
    # Get threat statistics
    recent_threats = Threat.objects.filter(reported_at__gte=last_month)
    threat_by_country = recent_threats.values('source_country').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    threat_by_type = recent_threats.values('type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Platform statistics from phishing reports
    platform_stats = PhishingReport.objects.filter(
        created_at__gte=last_month,
        platform_source__isnull=False
    ).values('platform_source__name', 'category').annotate(
        count=Count('id')
    ).order_by('-count')[:15]
    
    # Report statistics
    total_reports = PhishingReport.objects.count()
    today_reports = PhishingReport.objects.filter(created_at__date=today).count()
    
    # Get platform statistics for template
    platform_dict = {}
    platform_report_stats = (PhishingReport.objects
                            .filter(platform_source__isnull=False)
                            .values('platform_source__name')
                            .annotate(count=Count('id'))
                            .order_by('-count'))
    
    for stat in platform_report_stats:
        if stat['platform_source__name']:
            platform_dict[stat['platform_source__name']] = stat['count']
    
    # Get contact guidelines
    contact_guidelines = ContactGuideline.objects.filter(is_active=True).order_by('contact__order')
    
    # Statistics
    stats = {
        'total_threats': recent_threats.count(),
        'active_phishing': phishing_urls.filter(is_active=True).count(),
        'suspicious_urls': url_checker_results.count(),
        'recent_reports': PhishingReport.objects.filter(created_at__gte=last_week).count(),
    }
    
    context = {
        'page_title': 'Վտանգների քարտեզ',
        'phishing_urls': phishing_urls[:20],
        'url_checker_results': url_checker_results,
        'threat_by_country': threat_by_country,
        'threat_by_type': threat_by_type,
        'platform_stats_detailed': platform_stats,
        'stats': stats,
        'recent_threats': recent_threats.order_by('-reported_at')[:10],
        'total_reports': total_reports,
        'today_reports': today_reports,
        'platform_stats': platform_dict,
        'contact_guidelines': contact_guidelines,
    }
    return render(request, 'threat_map/threat_map.html', context)

def get_phishing_urls_from_reports():
    """Extract and update phishing URLs from reports"""
    last_month = timezone.now() - timedelta(days=30)
    
    # Get reports with URLs
    reports_with_urls = PhishingReport.objects.filter(
        created_at__gte=last_month,
        suspicious_url__isnull=False
    ).exclude(suspicious_url='')
    
    phishing_urls = []
    
    for report in reports_with_urls:
        # Create or get PhishingURL object
        phishing_url, created = PhishingURL.objects.get_or_create(
            url=report.suspicious_url,
            source_report=report,
            defaults={
                'category': report.category,
                'platform_source': report.platform_source or '',
            }
        )
        
        # Update category and platform if changed
        if not created:
            phishing_url.category = report.category
            phishing_url.platform_source = report.platform_source or ''
            phishing_url.save()
        
        phishing_urls.append(phishing_url)
    
    return PhishingURL.objects.filter(created_at__gte=last_month).order_by('-created_at')

def check_url_status(request):
    """AJAX endpoint to check URL status"""
    if request.method == 'POST':
        url = request.POST.get('url')
        
        try:
            response = requests.head(url, timeout=10, allow_redirects=True)
            status_code = response.status_code
            is_active = status_code < 400
            
            # Update PhishingURL if exists
            try:
                phishing_url = PhishingURL.objects.get(url=url)
                phishing_url.is_active = is_active
                phishing_url.status_code = status_code
                phishing_url.save()
            except PhishingURL.DoesNotExist:
                pass
            
            return JsonResponse({
                'success': True,
                'is_active': is_active,
                'status_code': status_code
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request'})

def threat_data_api(request):
    """API endpoint for real-time threat data"""
    last_hour = timezone.now() - timedelta(hours=1)
    
    recent_threats = Threat.objects.filter(
        reported_at__gte=last_hour,
        is_active=True
    ).values(
        'id', 'type', 'source_country', 'severity', 'reported_at', 'description'
    )
    
    threats_list = []
    for threat in recent_threats:
        threats_list.append({
            'id': threat['id'],
            'title': f"{threat['type']} от {threat['source_country']}",
            'category': threat['type'],
            'severity': threat['severity'],
            'created_at': threat['reported_at'].isoformat(),
            'description': threat['description'] or 'Նկարագրություն չկա'
        })
    
    return JsonResponse({
        'threats': threats_list,
        'timestamp': timezone.now().isoformat()
    })

def stats_api(request):
    """API endpoint for statistics"""
    last_month = timezone.now() - timedelta(days=30)
    last_week = timezone.now() - timedelta(days=7)
    
    # Get basic statistics
    total_threats = Threat.objects.count()
    active_threats = Threat.objects.filter(is_active=True).count()
    resolved_threats = total_threats - active_threats
    phishing_urls = PhishingURL.objects.count()
    
    return JsonResponse({
        'total_threats': total_threats,
        'active_threats': active_threats,
        'resolved_threats': resolved_threats,
        'phishing_urls': phishing_urls,
        'timestamp': timezone.now().isoformat()
    })

def phishing_urls_api(request):
    """API endpoint for phishing URLs"""
    last_month = timezone.now() - timedelta(days=30)
    
    phishing_urls = PhishingURL.objects.filter(
        created_at__gte=last_month
    ).select_related('source_report').order_by('-created_at')[:20]
    
    urls_list = []
    for url_obj in phishing_urls:
        urls_list.append({
            'id': url_obj.id,
            'url': url_obj.url,
            'category': url_obj.category,
            'platform_source': url_obj.platform_source,
            'status': 'active' if url_obj.is_active else 'inactive',
            'last_checked': url_obj.last_checked.isoformat(),
            'created_at': url_obj.created_at.isoformat()
        })
    
    return JsonResponse({
        'urls': urls_list,
        'timestamp': timezone.now().isoformat()
    })

def check_url_api(request):
    """API endpoint for checking URL status"""
    if request.method == 'POST':
        import json
        try:
            data = json.loads(request.body)
            url = data.get('url')
            
            if not url:
                return JsonResponse({
                    'status': 'error',
                    'message': 'URL պարամետրը պարտադիր է'
                })
            
            # Here you would implement actual URL checking logic
            # For now, return a mock response
            
            return JsonResponse({
                'status': 'success',
                'message': f'URL-ը ստուգվել է: {url}',
                'url_status': 'safe',
                'checked_at': timezone.now().isoformat()
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Սխալ JSON ձևաչափ'
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Սխալ: {str(e)}'
            })
    
    return JsonResponse({
        'status': 'error',
        'message': 'Միայն POST հարցումներ են թույլատրված'
    })

def live_threat_map_view(request):
    """Live Threat Map - Real-time Armenia cyber security monitor"""
    context = {
        'page_title': 'Live Threat Map - Հայաստանի Կիբեռ Անվտանգություն',
        'description': 'Հայաստանը թիրախ դարձնող կիբեռ սպառնալիքների իրական ժամանակի մոնիտորինգ',
    }
    return render(request, 'threat_map/live_map.html', context)

def live_threats_api(request):
    """API endpoint for live threat data"""
    import random
    from datetime import datetime, timedelta
    
    # Mock data generator - replace with real threat intelligence APIs
    source_countries = [
        {'name': 'Russia', 'coords': [55.7558, 37.6176], 'flag': '🇷🇺', 'threat': 'high'},
        {'name': 'China', 'coords': [39.9042, 116.4074], 'flag': '🇨🇳', 'threat': 'medium'},
        {'name': 'Iran', 'coords': [35.6892, 51.3890], 'flag': '🇮🇷', 'threat': 'high'},
        {'name': 'Turkey', 'coords': [39.9334, 32.8597], 'flag': '🇹🇷', 'threat': 'medium'},
        {'name': 'USA', 'coords': [38.9072, -77.0369], 'flag': '🇺🇸', 'threat': 'low'},
        {'name': 'Germany', 'coords': [52.5200, 13.4050], 'flag': '🇩🇪', 'threat': 'low'},
        {'name': 'North Korea', 'coords': [39.0392, 125.7625], 'flag': '🇰🇵', 'threat': 'high'},
        {'name': 'Azerbaijan', 'coords': [40.4093, 49.8671], 'flag': '🇦🇿', 'threat': 'medium'}
    ]
    
    attack_types = [
        'DDoS Attack', 'Malware Distribution', 'Phishing Campaign',
        'Brute Force', 'SQL Injection', 'Data Breach Attempt',
        'Ransomware', 'APT Activity', 'Bot Network'
    ]
    
    # Generate random attacks
    attacks = []
    num_attacks = random.randint(8, 20)
    
    for i in range(num_attacks):
        source = random.choice(source_countries)
        attack_type = random.choice(attack_types)
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 24))
        
        attacks.append({
            'id': f'attack_{int(timestamp.timestamp())}_{i}',
            'source': source,
            'target': {'name': 'Armenia', 'coords': [40.1792, 44.4991]},
            'type': attack_type,
            'timestamp': timestamp.isoformat(),
            'severity': source['threat'],
            'ip': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'details': f'{attack_type} detected from {source["name"]}'
        })
    
    # Sort by timestamp (newest first)
    attacks.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Calculate statistics
    now = datetime.now()
    five_minutes_ago = now - timedelta(minutes=5)
    recent_attacks = [a for a in attacks if datetime.fromisoformat(a['timestamp']) > five_minutes_ago]
    
    countries = set(attack['source']['name'] for attack in attacks)
    high_threat_attacks = [a for a in attacks if a['severity'] == 'high']
    
    # Determine threat level
    if len(high_threat_attacks) > 5:
        threat_level = 'high'
    elif len(high_threat_attacks) > 2 or len(recent_attacks) > 3:
        threat_level = 'medium'
    else:
        threat_level = 'low'
    
    response_data = {
        'attacks': attacks,
        'statistics': {
            'total': len(attacks),
            'recent': len(recent_attacks),
            'countries': len(countries),
            'threat_level': threat_level
        },
        'last_updated': now.isoformat()
    }
    
    return JsonResponse(response_data)

def unified_threat_map_view(request):
    """Ամբողջական սպառնալիքների քարտեզ և կայքի վիճակագրություն"""
    from apps.reporting.models import ContactGuideline
    
    last_month = timezone.now() - timedelta(days=30)
    last_week = timezone.now() - timedelta(days=7)
    today = timezone.now().date()
    
    # Get phishing reports data
    recent_reports = PhishingReport.objects.filter(
        created_at__gte=last_week
    ).select_related('platform_source').order_by('-created_at')[:10]
    
    # Get URL checker results
    recent_url_checks = URLCheck.objects.filter(
        checked_at__gte=last_week
    ).order_by('-checked_at')[:10]
    
    # Platform statistics from phishing reports
    platform_reports = PhishingReport.objects.filter(
        created_at__gte=last_month,
        platform_source__isnull=False
    ).values('platform_source__name').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    total_platform_reports = sum(p['count'] for p in platform_reports)
    platform_statistics = []
    for platform in platform_reports:
        percentage = (platform['count'] / total_platform_reports * 100) if total_platform_reports > 0 else 0
        platform_statistics.append({
            'name': platform['platform_source__name'],
            'count': platform['count'],
            'percentage': percentage
        })
    
    # Report categories
    report_categories = PhishingReport.objects.filter(
        created_at__gte=last_month
    ).values('category').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # URL statistics
    url_stats = {
        'safe': URLCheck.objects.filter(
            checked_at__gte=last_month, 
            status='safe'
        ).count(),
        'suspicious': URLCheck.objects.filter(
            checked_at__gte=last_month, 
            status='suspicious'
        ).count(),
        'malicious': URLCheck.objects.filter(
            checked_at__gte=last_month, 
            status__in=['malicious', 'phishing']
        ).count(),
    }
    
    # Site statistics
    site_stats = {
        'total_threats': Threat.objects.filter(reported_at__gte=last_month).count(),
        'total_reports': PhishingReport.objects.count(),
        'url_checks': URLCheck.objects.filter(checked_at__gte=last_month).count(),
        'phishing_urls': PhishingURL.objects.filter(is_active=True).count(),
    }
    
    context = {
        'page_title': 'Վտանգների քարտեզ - Հայաստանի Կիբեռ Անվտանգություն',
        'recent_reports': recent_reports,
        'recent_url_checks': recent_url_checks,
        'platform_statistics': platform_statistics,
        'report_categories': report_categories,
        'url_stats': url_stats,
        'site_stats': site_stats,
        'timestamp': timezone.now().timestamp(),
    }
    
    return render(request, 'threat_map/unified_threat_map.html', context)

def site_statistics_api(request):
    """API endpoint for real-time site statistics"""
    last_month = timezone.now() - timedelta(days=30)
    last_week = timezone.now() - timedelta(days=7)
    today = timezone.now().date()
    
    # Calculate statistics
    stats = {
        'total_threats': Threat.objects.filter(reported_at__gte=last_month).count(),
        'total_reports': PhishingReport.objects.count(),
        'today_reports': PhishingReport.objects.filter(created_at__date=today).count(),
        'url_checks': URLCheck.objects.filter(checked_at__gte=last_month).count(),
        'phishing_urls': PhishingURL.objects.filter(is_active=True).count(),
        'recent_reports': PhishingReport.objects.filter(created_at__gte=last_week).count(),
        
        # Platform breakdown
        'platform_breakdown': list(
            PhishingReport.objects.filter(
                created_at__gte=last_month,
                platform_source__isnull=False
            ).values('platform_source__name').annotate(
                count=Count('id')
            ).order_by('-count')[:5]
        ),
        
        # URL status breakdown
        'url_breakdown': {
            'safe': URLCheck.objects.filter(
                checked_at__gte=last_month, 
                status='safe'
            ).count(),
            'suspicious': URLCheck.objects.filter(
                checked_at__gte=last_month, 
                status='suspicious'
            ).count(),
            'malicious': URLCheck.objects.filter(
                checked_at__gte=last_month, 
                status__in=['malicious', 'phishing']
            ).count(),
        },
        
        # Reports by category
        'category_breakdown': list(
            PhishingReport.objects.filter(
                created_at__gte=last_month
            ).values('category').annotate(
                count=Count('id')
            ).order_by('-count')[:5]
        ),
    }
    
    return JsonResponse({
        'status': 'success',
        'data': stats,
        'last_updated': timezone.now().isoformat()
    })
