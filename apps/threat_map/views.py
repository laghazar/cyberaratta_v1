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
    ).exclude(platform_source='').values('platform_source', 'category').annotate(
        count=Count('id')
    ).order_by('-count')[:15]
    
    # Report statistics
    total_reports = PhishingReport.objects.count()
    today_reports = PhishingReport.objects.filter(created_at__date=today).count()
    
    # Get platform statistics for template
    platform_dict = {}
    platform_report_stats = (PhishingReport.objects
                            .values('platform_source')
                            .annotate(count=Count('id'))
                            .order_by('-count'))
    
    for stat in platform_report_stats:
        if stat['platform_source']:
            # Get the display name for platform choice
            platform_name = dict(PhishingReport.PLATFORM_CHOICES).get(stat['platform_source'], stat['platform_source'])
            platform_dict[platform_name] = stat['count']
    
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
