from django.shortcuts import render
from .models import Threat
from apps.reporting.models import PhishingReport
from django.db.models import Count

def threat_map(request):
    """Սպառնալիքների քարտեզի էջ"""
    threats = Threat.objects.all()
    threat_types = PhishingReport.objects.values('category').annotate(count=Count('category'))

    context = {
        'page_title': 'Սպառնալիքների Քարտեզ',
        'threats': threats,
        'threat_types': threat_types,
    }
    return render(request, 'threat_map/map.html', context)