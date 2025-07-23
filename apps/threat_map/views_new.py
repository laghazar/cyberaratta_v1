from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import Threat
from apps.reporting.models import PhishingReport
from apps.url_checker.models import URLCheck
from apps.core.utils import update_statistics

def threat_map(request):
    """Սպառնալիqqների քարտեզի էջ"""
    threats = Threat.objects.all()
    
    # Get statistics for the threat map
    last_month = timezone.now() - timedelta(days=30)
    recent_reports = PhishingReport.objects.filter(created_at__gte=last_month).count()
    total_reports = PhishingReport.objects.count()
    
    # URL checks statistics
    try:
        total_url_checks = URLCheck.objects.count()
        recent_url_checks = URLCheck.objects.filter(created_at__gte=last_month).count()
    except:
        total_url_checks = 0
        recent_url_checks = 0
    
    # Threat types by category
    threat_types = PhishingReport.objects.values('category').annotate(
        count=Count('category')
    ).order_by('-count')
    
    # Recent threats by platform/source
    platform_threats = PhishingReport.objects.filter(
        created_at__gte=last_month,
        platform_source__isnull=False
    ).values('platform_source', 'category').annotate(
        count=Count('id')
    ).order_by('-count')[:10]

    context = {
        'page_title': 'Սպառնալիqqների Քարտեզ',
        'threats': threats,
        'threat_types': threat_types,
        'platform_threats': platform_threats,
        'stats': {
            'recent_reports': recent_reports,
            'total_reports': total_reports,
            'total_url_checks': total_url_checks,
            'recent_url_checks': recent_url_checks,
        }
    }
    return render(request, 'threat_map/map.html', context)
