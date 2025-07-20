from apps.quiz.models import QuizAttempt
from apps.url_checker.models import URLCheck
from apps.reporting.models import Report

def update_statistics():
    stats = {
        'total_urls': URLCheck.objects.count(),
        'threats': URLCheck.objects.filter(status='malicious').count(),
        'quizzes': QuizAttempt.objects.count(),
        'reports': Report.objects.count(),
    }
    return stats
