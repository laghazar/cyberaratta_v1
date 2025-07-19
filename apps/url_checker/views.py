import requests
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import URLCheck
from django.conf import settings
from apps.core.views import update_statistics

@csrf_exempt
def check_url(request):
    """URL/Էլ. փոստի ստուգում"""
    if request.method == 'POST':
        input_text = request.POST.get('input_text')
        if not input_text:
            return JsonResponse({'error': 'Մուտքագրեք URL կամ էլ. փոստ'}, status=400)

        url_check = URLCheck.objects.create(input_text=input_text)

        try:
            headers = {'x-apikey': settings.VIRUSTOTAL_API_KEY}
            response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': input_text})
            response.raise_for_status()
            result = response.json()

            if result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
                url_check.status = 'malicious'
                url_check.analysis_result = "Հղումը վտանգավոր է։ Խորհուրդ է տրվում խուսափել դրանից։"
            else:
                url_check.status = 'safe'
                url_check.analysis_result = "Հղումը անվտանգ է։"
            url_check.source = 'VirusTotal'

        except requests.RequestException:
            url_check.status = 'pending'
            url_check.analysis_result = "Հղումը սպասում է ձեռքով մշակման։ Արդյունքը կհայտնվի 3 աշխատանքային օրվա ընթացքում։"

        url_check.save()
        update_statistics()

        return JsonResponse({
            'status': url_check.get_status_display(),
            'result': url_check.analysis_result
        })

    return render(request, 'url_checker/check.html', {'page_title': 'Ստուգիր Հղումը'})