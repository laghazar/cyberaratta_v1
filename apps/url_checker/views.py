import requests
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import URLCheck, UrlCheckResult
from django.conf import settings
from apps.core.utils import update_statistics
from .utils import check_url_virustotal, check_url_kaspersky, format_detailed_response, is_trusted_domain
import json

@csrf_exempt
def check_url(request):
    if request.method == 'POST':
        input_text = request.POST.get('input_text', '').strip()
        selected_sources = request.POST.getlist('sources')  # Ընտրված աղբյուրները
        
        if not input_text:
            return JsonResponse({'error': 'Մուտքագրեք URL կամ էլ. փոստ'}, status=400)

        # Եթե ոչ մի աղբյուր ընտրված չէ, օգտագործում ենք բոլորը
        if not selected_sources:
            selected_sources = ['virustotal', 'kaspersky']

        # Ստեղծում ենք URL ստուգման գրառում
        url_check = URLCheck.objects.create(input_text=input_text)

        try:
            # Առաջնային ստուգում - վստահելի դոմենների համար
            if is_trusted_domain(input_text):
                url_check.status = 'safe'
                url_check.source = 'Վստահելի դոմենների ցուցակ'
                url_check.analysis_result = format_detailed_response('safe', input_text, 
                    {'trusted': True, 'details': {'trusted_domain': True}}, 
                    {'trusted': True})
                url_check.save()
                
                # Պարզեցված արդյունք պահպանում
                UrlCheckResult.objects.create(
                    url_check=url_check,
                    virustotal_result={'status': 'trusted_domain', 'trusted': True},
                    kaspersky_result={'status': 'trusted_domain', 'trusted': True},
                )
                
                update_statistics()
                return JsonResponse({
                    'status': 'safe',
                    'status_display': 'Անվտանգ',
                    'result': url_check.analysis_result,
                    'confidence': 'high',
                    'source': url_check.source,
                    'sources_used': ['trusted_domain'],
                    'source_statistics': {
                        'safe_sources': 1,
                        'malicious_sources': 0,
                        'suspicious_sources': 0,
                        'pending_sources': 0,
                        'total_sources': 1
                    }
                })

            # Մանրամասն ստուգում ընտրված APIs-ի միջոցով
            print(f"Checking URL with selected sources: {selected_sources}")
            
            vt_result = {}
            kasp_result = {}
            sources_used = []
            
            if 'virustotal' in selected_sources:
                print(f"Checking with VirusTotal: {input_text}")
                vt_result = check_url_virustotal(input_text)
                print(f"VirusTotal result: {vt_result.get('status', 'unknown')}")
                if not vt_result.get('pending') and not vt_result.get('trusted'):
                    sources_used.append('VirusTotal')
            
            if 'kaspersky' in selected_sources:
                print(f"Checking with Kaspersky: {input_text}")
                kasp_result = check_url_kaspersky(input_text)
                print(f"Kaspersky result: {kasp_result.get('status', 'unknown')}")
                if not kasp_result.get('pending') and not kasp_result.get('trusted'):
                    sources_used.append('Kaspersky')
            
            # Վստահելի դոմենից ստուգում
            if vt_result.get('trusted') or kasp_result.get('trusted'):
                sources_used.append('Վստահելի Ցուցակ')

            # Բարդ տրամաբանություն արդյունքների համար
            final_status = determine_final_status(vt_result, kasp_result)

            # Մանրամասն պատասխան
            detailed_result = format_detailed_response(final_status, input_text, vt_result, kasp_result)
            
            url_check.status = final_status
            url_check.source = ', '.join(sources_used) if sources_used else 'Ներքին վերլուծություն'
            url_check.analysis_result = detailed_result
            url_check.save()

            # Արդյունքները պահպանում
            UrlCheckResult.objects.create(
                url_check=url_check,
                virustotal_result=vt_result,
                kaspersky_result=kasp_result,
            )

            # Վիճակագրությունը պահպանում ենք
            total_sources = 0
            safe_sources = 0
            malicious_sources = 0
            suspicious_sources = 0
            pending_sources = 0
            
            # VirusTotal-ի վիճակագրություն
            if 'virustotal' in selected_sources and vt_result:
                total_sources += 1
                vt_status = vt_result.get('status', 'pending')
                if vt_status == 'safe':
                    safe_sources += 1
                elif vt_status == 'malicious':
                    malicious_sources += 1
                elif vt_status == 'suspicious':
                    suspicious_sources += 1
                else:
                    pending_sources += 1
            
            # Kaspersky-ի վիճակագրություն
            if 'kaspersky' in selected_sources and kasp_result:
                total_sources += 1
                kasp_status = kasp_result.get('status', 'pending')
                if kasp_status == 'safe':
                    safe_sources += 1
                elif kasp_status == 'malicious':
                    malicious_sources += 1
                elif kasp_status == 'suspicious':
                    suspicious_sources += 1
                else:
                    pending_sources += 1
            
            # Վստահելի դոմենների վիճակագրություն
            if vt_result.get('trusted') or kasp_result.get('trusted'):
                total_sources += 1
                safe_sources += 1

            # Վիճակագրությունը թարմացնում
            update_statistics()

            # Վստահության մակարդակ
            confidence = determine_confidence_level(vt_result, kasp_result, final_status)

            return JsonResponse({
                'status': final_status,
                'status_display': url_check.get_status_display(),
                'result': detailed_result,
                'confidence': confidence,
                'source': url_check.source,
                'sources_used': selected_sources,
                'source_statistics': {
                    'safe_sources': safe_sources,
                    'malicious_sources': malicious_sources,
                    'suspicious_sources': suspicious_sources,
                    'pending_sources': pending_sources,
                    'total_sources': total_sources
                },
                'technical_details': {
                    'virustotal': vt_result.get('details', {}) if 'virustotal' in selected_sources else {},
                    'kaspersky': kasp_result.get('verdict', 'unknown') if 'kaspersky' in selected_sources else {},
                    'trusted_domain': vt_result.get('trusted', False) or kasp_result.get('trusted', False)
                }
            })

        except Exception as e:
            print(f"Error during URL check: {str(e)}")
            url_check.status = 'pending'
            url_check.analysis_result = format_detailed_response('pending', input_text, 
                {'pending': True, 'message': str(e)}, 
                {'pending': True, 'message': str(e)})
            url_check.source = 'Ներքին սխալ'
            url_check.save()
            
            return JsonResponse({
                'status': 'pending',
                'status_display': 'Սպասում է ձեռքով մշակման',
                'result': url_check.analysis_result,
                'confidence': 'low',
                'source': 'Ներքին սխալ'
            })

    # GET խնդրանքի դեպքում ցույց տալ HTML ձևը
    return render(request, 'url_checker/check.html', {'page_title': 'Ստուգիր Հղումը'})


def determine_final_status(vt_result, kasp_result):
    """Որոշում է վերջնական կարգավիճակը երկու արդյունքների հիման վրա"""
    vt_status = vt_result.get('status', 'pending') if vt_result else 'pending'
    kasp_status = kasp_result.get('status', 'pending') if kasp_result else 'pending'
    
    # Վստահելի դոմենների դեպքում
    if vt_result.get('trusted') or kasp_result.get('trusted'):
        return 'safe'
    
    # Եթե մեկը վտանգավոր է դասակարգում
    if vt_status == 'malicious' or kasp_status == 'malicious':
        return 'malicious'
    
    # Եթե մեկը կասկածելի է և մյուսը ոչ անվտանգ
    if (vt_status == 'suspicious' and kasp_status != 'safe') or \
       (kasp_status == 'suspicious' and vt_status != 'safe'):
        return 'suspicious'
    
    # Եթե առնվազն մեկը անվտանգ է և մյուսը pending կամ safe
    if (vt_status == 'safe' and kasp_status in ['safe', 'pending']) or \
       (kasp_status == 'safe' and vt_status in ['safe', 'pending']):
        return 'safe'
    
    # Եթե երկուսն էլ pending են
    if vt_status == 'pending' and kasp_status == 'pending':
        return 'pending'
    
    # Default դեպք
    return 'pending'


def determine_confidence_level(vt_result, kasp_result, final_status):
    """Որոշում է վստահության մակարդակը"""
    if not vt_result and not kasp_result:
        return 'low'
        
    vt_confidence = vt_result.get('confidence', 'medium') if vt_result else 'low'
    kasp_confidence = kasp_result.get('confidence', 'medium') if kasp_result else 'low'
    
    if vt_result.get('trusted') or kasp_result.get('trusted'):
        return 'high'
    
    if final_status == 'malicious' and (vt_confidence == 'high' or kasp_confidence == 'high'):
        return 'high'
    
    if final_status == 'safe' and vt_confidence == 'high' and kasp_confidence == 'high':
        return 'high'
    
    if (vt_result and not vt_result.get('pending')) and (kasp_result and not kasp_result.get('pending')):
        return 'medium'
    
    return 'low'