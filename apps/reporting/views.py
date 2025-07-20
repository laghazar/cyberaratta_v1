from django.shortcuts import render, redirect
from django.contrib import messages
from .models import PhishingReport  # Հստակ ներմուծում
from apps.core.utils import update_statistics

def phishing_report_view(request):
    """Handle phishing report submission and display report form."""
    if request.method == 'POST':
        category = request.POST.get('category')
        description = request.POST.get('description')
        suspicious_url = request.POST.get('suspicious_url', '')
        suspicious_email = request.POST.get('suspicious_email', '')
        contact_info = request.POST.get('contact_info', '')
        is_anonymous = request.POST.get('is_anonymous', False) == 'on'

        report = PhishingReport.objects.create(
            category=category,
            description=description,
            suspicious_url=suspicious_url,
            suspicious_email=suspicious_email,
            contact_info=contact_info,
            is_anonymous=is_anonymous
        )

        update_statistics()
        messages.success(request, 'Զեկուցումը հաջողությամբ ուղարկվել է։')
        return redirect('reporting:report')

    stats = update_statistics()
    return render(request, 'reporting/report.html', {
        'page_title': 'Զեկուցել Ֆիշինգի մասին',
        'categories': PhishingReport.CATEGORY_CHOICES,  # Հաշվի առնելով models.py
        'stats': stats
    })
    
    
    