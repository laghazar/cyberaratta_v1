from django.shortcuts import render
from django.http import JsonResponse
#from django.views.decorators.cache import cache_page
from .models import SiteStatistics, Character
from apps.reporting.models import PhishingReport
from apps.quiz.models import QuizResult, QuizAttempt
from apps.url_checker.models import URLCheck
from .utils import update_statistics

def home(request):
    """Գլխավոր էջ"""
    stats, created = SiteStatistics.objects.get_or_create(pk=1)
    ara_character = Character.objects.filter(character_type='ara').first()
    shamiram_character = Character.objects.filter(character_type='shamiram').first()
    
    updated_stats = update_statistics()
    
    context = {
        'stats': stats,
        'ara_character': ara_character,
        'shamiram_character': shamiram_character,
        'updated_stats': updated_stats,
        'page_title': 'CyberAratta - Կիբեռանվտանգության Կրթական Հարթակ'
    }
    
    return render(request, 'core/home.html', context)

def demo_dashboard(request):
    """Demo dashboard for presentation"""
    context = {
        'page_title': 'CyberAratta Demo Dashboard - Հայաստանի Կիբեռ Անվտանգություն'
    }
    return render(request, 'demo_dashboard.html', context)

def update_statistics():
    stats = {
        'checked_urls': URLCheck.objects.count(),
        'detected_threats': URLCheck.objects.filter(status='malicious').count(),
        'completed_quizzes': QuizAttempt.objects.count(),
        'reports': PhishingReport.objects.count(),
    }
    return stats