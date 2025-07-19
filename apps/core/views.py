from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.cache import cache_page

from apps.reporting.views import report
from .models import SiteStatistics, Character
from apps.reporting.models import PhishingReport
from apps.quiz.models import QuizResult, QuizAttempt
from apps.url_checker.models import URLCheck



from django.shortcuts import render 
def home(request):
    """Գլխավոր էջ"""
    stats, created = SiteStatistics.objects.get_or_create(pk=1)
    ara_character = Character.objects.filter(character_type='ara').first()
    shamiram_character = Character.objects.filter(character_type='shamiram').first()
    
    context = {
        'stats': stats,
        'ara_character': ara_character,
        'shamiram_character': shamiram_character,
        'page_title': 'CyberAratta - Կիբեռանվտանգության Կրթական Հարթակ'
    }
    
    return render(request, 'core/home.html',)

def home(request):
    stats = update_statistics()
    return render(request, 'core/home.html', {'stats': stats})

def update_statistics():
    stats = {
        'checked_urls': URLCheck.objects.count(),
        'detected_threats': URLCheck.objects.filter(is_malicious=True).count(),
        'completed_quizzes': QuizAttempt.objects.count(),
        'reports': report.objects.count(),
    }
    return stats

