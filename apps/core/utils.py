from apps.quiz.models import QuizAttempt
from apps.url_checker.models import URLCheck
from apps.reporting.models import Report

def update_statistics():
    stats = {
        'checked_urls': URLCheck.objects.count(),
        'detected_threats': URLCheck.objects.filter(is_malicious=True).count(),
        'completed_quizzes': QuizAttempt.objects.count(),
        'reports': Report.objects.count(),
    }
    return stats