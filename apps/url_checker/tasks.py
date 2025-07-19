from celery import shared_task
from .models import URLCheck
import requests
from django.conf import settings

@shared_task
def analyze_url(url_check_id):
    url_check = URLCheck.objects.get(id=url_check_id)
    try:
        headers = {'x-apikey': settings.KASPERSKY_API_KEY}
        response = requests.get(f'https://opentip.kaspersky.com/api/v1/scan/url?url={url_check.input_text}', headers=headers)
        result = response.json()
        url_check.status = 'malicious' if result.get('threats_detected') else 'safe'
        url_check.analysis_result = result.get('description', 'Անվտանգ է։')
        url_check.source = 'Kaspersky'
    except requests.RequestException:
        url_check.status = 'pending'
        url_check.analysis_result = 'Հղումը սպասում է ձեռքով մշակման։'
    url_check.save()