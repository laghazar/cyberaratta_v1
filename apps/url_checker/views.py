import requests
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import URLCheck, UrlCheckResult
from django.conf import settings
from apps.core.utils import update_statistics
from .utils import check_url_virustotal, check_url_kaspersky

@csrf_exempt
def check_url(request):
    if request.method == 'POST':
        input_text = request.POST.get('input_text')
        if not input_text:
            return JsonResponse({'error': 'Մուտքագրեք URL կամ էլ. փոստ'}, status=400)

        url_check = URLCheck.objects.create(input_text=input_text)

        try:
            vt_result = check_url_virustotal(input_text)
            kasp_result = check_url_kaspersky(input_text)

            # Վերլուծություն ըստ ստացված արդյունքների
            if vt_result.get('pending') or kasp_result.get('pending'):
                url_check.status = 'pending'
                url_check.analysis_result = "Հղումը սպասում է ձեռքով մշակման։ Արդյունքը կհայտնվի 3 աշխատանքային օրվա ընթացքում։"
            elif vt_result.get('malicious') or kasp_result.get('malicious'):
                url_check.status = 'malicious'
                url_check.analysis_result = "Հղումը վտանգավոր է։ Խորհուրդ է տրվում խուսափել դրանից։"
            elif vt_result.get('status') == 'suspicious' or kasp_result.get('status') == 'suspicious':
                url_check.status = 'suspicious'
                url_check.analysis_result = "Հղումը կասկածելի է։"
            else:
                url_check.status = 'safe'
                url_check.analysis_result = "Հղումը անվտանգ է։"

            url_check.source = 'VirusTotal + Kaspersky'
            url_check.save()

            UrlCheckResult.objects.create(
                url_check=url_check,
                virustotal_result=vt_result,
                kaspersky_result=kasp_result,
            )

        except Exception as e:
            url_check.status = 'pending'
            url_check.analysis_result = f"Հղումը սպասում է ձեռքով մշակման։ Սերվերի սխալ՝ {str(e)}"
            url_check.save()

        update_statistics()

        return JsonResponse({
            'status': url_check.get_status_display(),
            'result': url_check.analysis_result,
        })

    # GET խնդրանքի դեպքում ցույց տալ HTML ձևը
    return render(request, 'url_checker/check.html', {'page_title': 'Ստուգիր Հղումը'})