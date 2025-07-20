from django.shortcuts import render, redirect
from django.contrib import messages
from .models import PhishingReport
from .forms import PhishingReportForm  # Ներմուծել ձևը
from apps.core.utils import update_statistics

def phishing_report_view(request):
    """Handle phishing report submission and display report form."""
    if request.method == 'POST':
        form = PhishingReportForm(request.POST)
        if form.is_valid():
            report = form.save()
            update_statistics()
            messages.success(request, 'Զեկուցումը հաջողությամբ ուղարկվել է։')
            return redirect('reporting:report')
    else:
        form = PhishingReportForm()

    stats = update_statistics()
    return render(request, 'reporting/report.html', {
        'page_title': 'Զեկուցել Ֆիշինգի մասին',
        'form': form,  # Փոխանցել ձևը կաղապարին
        'stats': stats
    })