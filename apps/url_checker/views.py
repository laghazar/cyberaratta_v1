import requests
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import URLCheck, UrlCheckResult
from .models_integrations import SecurityIntegration
from django.conf import settings
from apps.core.utils import update_statistics
from apps.core.security import security_rate_limit, sanitize_input, validate_url, log_security_event
from .email_checker import EmailPhishingChecker, get_email_provider_instructions
from .utils import (
    # Validators
    is_trusted_domain, 
    is_valid_url,
    categorize_url,
    
    # API clients
    check_url_virustotal, 
    check_url_kaspersky, 
    check_url_safebrowsing,
    
    # Formatting & Results
    format_scan_result_html,
    format_overall_result,
    format_detailed_response,
    
    # Analysis
    analyze_url_pattern,
    analyze_url_safety,
    
    # Recommendations
    generate_recommendations,
    
    # Database operations
    save_url_check_results,
    get_recent_url_checks,
    get_url_check_statistics
)
from .dynamic_integrations import integration_service
import json

@security_rate_limit(key='url_check', rate='10/m', method='POST')
def check_url(request):
    if request.method == 'GET':
        # Email provider instructions-ը context-ի մեջ ավելացնում ենք
        context = {
            'email_providers': get_email_provider_instructions()
        }
        return render(request, 'url_checker/check.html', context)
    
    if request.method == 'POST':
        try:
            input_text = request.POST.get('input_text', '').strip()
            input_type = request.POST.get('input_type', 'url')  # 'url' or 'email'
            selected_sources = request.POST.getlist('sources')  # Ընտրված աղբյուրները
            
            if not input_text:
                return JsonResponse({'error': 'URL կամ էլ. փոստ մուտքագրեք'})
            
            # Եթե email է, նույն մոդելում պահելու համար նշում ենք տիպը
            if input_type == 'email':
                return handle_email_check(request, input_text)
            
            # URL վալիդացիա
            try:
                validated_url = validate_url(input_text)
                input_text = validated_url  # Use validated URL
            except Exception as e:
                client_ip = request.META.get('REMOTE_ADDR', 'unknown')
                log_security_event('INVALID_URL_ATTEMPT', client_ip, str(e))
                return JsonResponse({'error': f'URL վալիդացիայի սխալ: {str(e)}'})
        
        except Exception as e:
            client_ip = request.META.get('REMOTE_ADDR', 'unknown')
            log_security_event('URL_CHECK_ERROR', client_ip, str(e))
            return JsonResponse({'error': 'Սխալ տեղի ունեցավ'})
        
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
            safebrowsing_result = {}
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
                    
            if 'safebrowsing' in selected_sources:
                print(f"Checking with Google Safe Browsing: {input_text}")
                safebrowsing_result = check_url_safebrowsing(input_text)
                print(f"Google Safe Browsing result: {safebrowsing_result.get('status', 'unknown')}")
                if not safebrowsing_result.get('pending') and not safebrowsing_result.get('trusted'):
                    sources_used.append('Google Safe Browsing')
            
            # Վստահելի դոմենից ստուգում
            if (vt_result and vt_result.get('trusted')) or (kasp_result and kasp_result.get('trusted')) or (safebrowsing_result and safebrowsing_result.get('trusted')):
                sources_used.append('Վստահելի Ցուցակ')

            # Եթե արտաքին աղբյուրները ոչինչ չեն գտել, manual review պահանջ
            need_manual_review = False
            statuses = [
                vt_result.get('status') if vt_result else None,
                kasp_result.get('status') if kasp_result else None, 
                safebrowsing_result.get('status') if safebrowsing_result else None
            ]
            
            if not any(status for status in statuses if status and status != 'pending') or all(
                status == 'pending' for status in statuses if status
            ):
                need_manual_review = True
                sources_used.append('Manual Review Pending')
                print(f"URL requires manual review - no results from external sources")

            # Բարդ տրամաբանություն արդյունքների համար
            final_status = determine_final_status(vt_result, kasp_result, safebrowsing_result, need_manual_review)

            # Մանրամասն պատասխան
            detailed_result = format_detailed_response(final_status, input_text, vt_result, kasp_result, safebrowsing_result, need_manual_review)
            
            url_check.status = final_status
            url_check.source = ', '.join(sources_used) if sources_used else 'Ներքին վերլուծություն'
            url_check.analysis_result = detailed_result
            url_check.save()

            # Արդյունքները պահպանում
            UrlCheckResult.objects.create(
                url_check=url_check,
                virustotal_result=vt_result,
                kaspersky_result=kasp_result,
                safebrowsing_result=safebrowsing_result,
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
            
            # Google Safe Browsing-ի վիճակագրություն
            if 'safebrowsing' in selected_sources and safebrowsing_result:
                total_sources += 1
                sb_status = safebrowsing_result.get('status', 'pending')
                if sb_status == 'safe':
                    safe_sources += 1
                elif sb_status == 'malicious':
                    malicious_sources += 1
                elif sb_status == 'suspicious':
                    suspicious_sources += 1
                else:
                    pending_sources += 1
            
            # Վստահելի դոմենների վիճակագրություն
            if (vt_result and vt_result.get('trusted')) or (kasp_result and kasp_result.get('trusted')) or (safebrowsing_result and safebrowsing_result.get('trusted')):
                total_sources += 1
                safe_sources += 1

            # Վիճակագրությունը թարմացնում
            update_statistics()

            # Վստահության մակարդակ
            confidence = determine_confidence_level(vt_result, kasp_result, final_status, safebrowsing_result)

            # Manual review message
            manual_review_message = None
            if need_manual_review:
                manual_review_message = "Այս URL-ը անհայտ է մեր արտաքին անվտանգության աղբյուրներում: Մեր անվտանգության թիմը կանցկացնի manual վերլուծություն 5 աշխատանքային օրվա ընթացքում: Արդյունքները կհրապարակվեն կայքի քարտեի էջում:"

            response_data = {
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
                    'safebrowsing': safebrowsing_result.get('verdict', 'unknown') if 'safebrowsing' in selected_sources else {},
                    'trusted_domain': (vt_result and vt_result.get('trusted', False)) or (kasp_result and kasp_result.get('trusted', False)) or (safebrowsing_result and safebrowsing_result.get('trusted', False))
                }
            }
            
            if manual_review_message:
                response_data['manual_review_required'] = True
                response_data['review_message'] = manual_review_message

            return JsonResponse(response_data)

        except Exception as e:
            print(f"Error during URL check: {str(e)}")
            url_check.status = 'pending'
            url_check.analysis_result = format_detailed_response(
                'pending', 
                input_text, 
                {'pending': True, 'message': str(e)}, 
                {'pending': True, 'message': str(e)}, 
                safebrowsing_result={'pending': True, 'message': str(e)},
                need_manual_review=True
            )
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


def determine_final_status(vt_result, kasp_result, safebrowsing_result=None, need_manual_review=False):
    """Որոշում է վերջնական կարգավիճակը բոլոր արդյունքների հիման վրա"""
    vt_status = vt_result.get('status', 'pending') if vt_result else 'pending'
    kasp_status = kasp_result.get('status', 'pending') if kasp_result else 'pending'
    sb_status = safebrowsing_result.get('status', 'pending') if safebrowsing_result else 'pending'
    
    # Վստահելի դոմենների դեպքում
    if (vt_result and vt_result.get('trusted')) or (kasp_result and kasp_result.get('trusted')) or (safebrowsing_result and safebrowsing_result.get('trusted')):
        return 'safe'
    
    # Արտաքին աղբյուրների առաջնություն - վտանգավոր
    if vt_status == 'malicious' or kasp_status == 'malicious' or sb_status == 'malicious':
        return 'malicious'
    
    # Կասկածելի
    if any(status == 'suspicious' for status in [vt_status, kasp_status, sb_status]):
        return 'suspicious'
    
    # Անվտանգ (երբ գոնե մեկը safe է և մյուսները pending կամ safe)
    safe_statuses = [vt_status, kasp_status, sb_status]
    if any(status == 'safe' for status in safe_statuses) and \
       all(status in ['safe', 'pending'] for status in safe_statuses):
        return 'safe'
    
    # Եթե արտաքին աղբյուրները ոչինչ չեն գտել, manual review
    if need_manual_review or all(status == 'pending' for status in [vt_status, kasp_status, sb_status]):
        return 'pending'
    
    # Default դեպք
    return 'pending'


def determine_confidence_level(vt_result, kasp_result, final_status='pending', safebrowsing_result=None):
    """Որոշում է վստահության մակարդակը"""
    if not vt_result and not kasp_result and not safebrowsing_result:
        return 'low'
        
    vt_confidence = vt_result.get('confidence', 'medium') if vt_result else 'low'
    kasp_confidence = kasp_result.get('confidence', 'medium') if kasp_result else 'low'
    sb_confidence = safebrowsing_result.get('confidence', 'medium') if safebrowsing_result else 'low'
    
    if (vt_result and vt_result.get('trusted')) or (kasp_result and kasp_result.get('trusted')) or (safebrowsing_result and safebrowsing_result.get('trusted')):
        return 'high'
    
    # Արտաքին աղբյուրների բարձր վստահություն
    if final_status == 'malicious' and (vt_confidence == 'high' or kasp_confidence == 'high' or sb_confidence == 'high'):
        return 'high'
    
    if final_status == 'safe' and vt_confidence == 'high' and kasp_confidence == 'high' and sb_confidence == 'high':
        return 'high'
    
    # Count available sources  
    available_sources = 0
    if vt_result and not vt_result.get('pending'):
        available_sources += 1
    if kasp_result and not kasp_result.get('pending'):
        available_sources += 1
    if safebrowsing_result and not safebrowsing_result.get('pending'):
        available_sources += 1
    
    if available_sources >= 2:
        return 'medium'
    
    return 'low'


def handle_email_check(request, raw_email_content):
    """Handle email phishing check"""
    try:
        # Email phishing checker ստեղծում
        email_checker = EmailPhishingChecker()
        
        # Email վերլուծություն
        analysis_result = email_checker.analyze_email(raw_email_content)
        
        # URLCheck մոդելում պահպանում (email տիպի համար)
        url_check = URLCheck.objects.create(
            input_text=f"EMAIL_CHECK: {raw_email_content[:100]}...",  # Սահմանափակ տեքստ
            status=analysis_result['status'],
            source='Email Phishing Analysis',
            analysis_result=format_email_analysis_result(analysis_result)
        )
        
        # Վիճակագրությունը թարմացնում
        update_statistics()
        
        # Response ձևավորում
        response_data = {
            'status': analysis_result['status'],
            'status_display': get_email_status_display(analysis_result['status']),
            'result': format_email_analysis_result(analysis_result),
            'confidence': get_email_confidence(analysis_result),
            'source': 'Email Phishing Analysis',
            'input_type': 'email',
            'risk_score': analysis_result.get('risk_score', 0),
            'total_checks': analysis_result.get('total_checks', 0),
            'email_details': {
                'authentication': analysis_result.get('details', {}).get('authentication', {}),
                'links_found': analysis_result.get('details', {}).get('links_found', 0),
                'headers': analysis_result.get('details', {}).get('headers', {}),
                'reasons': analysis_result.get('reasons', [])
            }
        }
        
        return JsonResponse(response_data)
        
    except Exception as e:
        print(f"Email check error: {str(e)}")
        return JsonResponse({
            'error': f'Email վերլուծության սխալ: {str(e)}',
            'input_type': 'email'
        }, status=500)


def format_email_analysis_result(analysis_result):
    """Format email analysis result for display"""
    status = analysis_result.get('status', 'error')
    risk_score = analysis_result.get('risk_score', 0)
    reasons = analysis_result.get('reasons', [])
    details = analysis_result.get('details', {})
    
    # Status-ի համاձայն գույներ
    if status == 'likely_phishing':
        status_color = '#dc3545'  # Red
        status_text = 'Phishing է (մեծ հավանականությամբ)'
        icon = 'fas fa-exclamation-triangle'
    elif status == 'suspicious':
        status_color = '#ffc107'  # Yellow
        status_text = 'Կասկածելի է'
        icon = 'fas fa-question-circle'
    elif status == 'safe':
        status_color = '#28a745'  # Green
        status_text = 'Անվտանգ է'
        icon = 'fas fa-check-circle'
    else:
        status_color = '#6c757d'  # Gray
        status_text = 'Վերլուծության սխալ'
        icon = 'fas fa-times-circle'
    
    html_result = f"""
    <div class="alert alert-info">
        <h5><i class="{icon}" style="color: {status_color};"></i> Email Phishing Analysis</h5>
        <p><strong>Կարգավիճակ:</strong> <span style="color: {status_color}; font-weight: bold;">{status_text}</span></p>
        <p><strong>Ռիսկի գնահատական:</strong> {risk_score}/100</p>
        <p><strong>Ստուգումների քանակ:</strong> {len(reasons)}</p>
    </div>
    """
    
    # Reasons ցուցակ
    if reasons:
        html_result += '<div class="alert alert-warning"><h6>Հայտնաբերված խնդիրներ:</h6><ul>'
        for reason in reasons:
            html_result += f'<li>{reason}</li>'
        html_result += '</ul></div>'
    
    # Authentication details
    auth_details = details.get('authentication', {})
    if auth_details:
        html_result += '<div class="alert alert-info"><h6>Email Authentication:</h6>'
        
        # SPF
        spf = auth_details.get('spf', {})
        if spf:
            spf_status = spf.get('status', 'unknown')
            spf_color = '#28a745' if spf_status == 'pass' else '#dc3545' if spf_status == 'fail' else '#ffc107'
            html_result += f'<p><strong>SPF:</strong> <span style="color: {spf_color};">{spf_status.upper()}</span> - {spf.get("reason", "N/A")}</p>'
        
        # DKIM
        dkim = auth_details.get('dkim', {})
        if dkim:
            dkim_status = dkim.get('status', 'unknown')
            dkim_color = '#28a745' if dkim_status in ['pass', 'present'] else '#dc3545' if dkim_status == 'fail' else '#ffc107'
            html_result += f'<p><strong>DKIM:</strong> <span style="color: {dkim_color};">{dkim_status.upper()}</span> - {dkim.get("reason", "N/A")}</p>'
        
        # DMARC
        dmarc = auth_details.get('dmarc', {})
        if dmarc:
            dmarc_status = dmarc.get('status', 'unknown')
            dmarc_color = '#28a745' if dmarc_status in ['strict', 'moderate'] else '#ffc107' if dmarc_status == 'lenient' else '#dc3545'
            html_result += f'<p><strong>DMARC:</strong> <span style="color: {dmarc_color};">{dmarc_status.upper()}</span> - {dmarc.get("reason", "N/A")}</p>'
        
        html_result += '</div>'
    
    # Links information
    links_found = details.get('links_found', 0)
    if links_found > 0:
        html_result += f'<div class="alert alert-info"><h6>Հղումներ:</h6><p>Գտնվել է {links_found} հղում email-ում</p>'
        
        # Blacklisted URLs
        blacklisted = details.get('blacklisted_urls', [])
        if blacklisted:
            html_result += f'<p><strong>Վտանգավոր հղումներ:</strong> {len(blacklisted)}</p><ul>'
            for url in blacklisted[:3]:  # Առաջին 3-ը
                html_result += f'<li style="color: #dc3545;">{url}</li>'
            html_result += '</ul>'
        
        # Brand impersonation
        brand_impersonation = details.get('brand_impersonation', [])
        if brand_impersonation:
            html_result += f'<p><strong>Brand Impersonation:</strong></p><ul>'
            for imp in brand_impersonation[:3]:
                suspected_brand = imp.get('suspected_brand', 'Unknown')
                domain = imp.get('domain', 'Unknown')
                html_result += f'<li style="color: #dc3545;">Կասկած {suspected_brand} նմանակման - {domain}</li>'
            html_result += '</ul>'
        
        html_result += '</div>'
    
    return html_result


def get_email_status_display(status):
    """Get display text for email status"""
    status_map = {
        'likely_phishing': 'Phishing (մեծ հավանականությամբ)',
        'suspicious': 'Կասկածելի',
        'safe': 'Անվտանգ',
        'error': 'Վերլուծության սխալ'
    }
    return status_map.get(status, 'Անհայտ')


def get_email_confidence(analysis_result):
    """Get confidence level for email analysis"""
    risk_score = analysis_result.get('risk_score', 0)
    total_checks = analysis_result.get('total_checks', 0)
    
    if total_checks >= 5 and risk_score >= 50:
        return 'high'
    elif total_checks >= 3 and risk_score >= 25:
        return 'medium'
    else:
        return 'low'