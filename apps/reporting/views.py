from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta
from .models import PhishingReport, ContactInfo
from .forms import PhishingReportForm
from apps.core.utils import update_statistics

def phishing_report_view(request):
    """Handle phishing report submission and display report form."""
    if request.method == 'POST':
        form = PhishingReportForm(request.POST)
        if form.is_valid():
            report = form.save()
            update_statistics()
            messages.success(request, 'Զեկուցումը հաջողությամբ ուղարկվել է։ Շնորհակալություն ձեր կարևոր ներդրման համար։')
            return redirect('reporting:report')
        else:
            messages.error(request, 'Խնդրում ենք ստուգել բոլոր պարտադիր դաշտերը։')
    else:
        form = PhishingReportForm()

    # Get contacts for the right side
    contacts = ContactInfo.objects.all()
    
    # Get recent reports statistics
    stats = update_statistics()
    
    # Get recent reports count for last 30 days
    last_month = timezone.now() - timedelta(days=30)
    recent_reports = PhishingReport.objects.filter(created_at__gte=last_month).count()
    
    # Get category statistics
    category_stats = PhishingReport.objects.values('category').annotate(
        count=Count('category')
    ).order_by('-count')

    return render(request, 'reporting/report.html', {
        'page_title': 'Զեկուցել Ֆիշինգի մասին',
        'form': form,
        'contacts': contacts,
        'stats': stats,
        'recent_reports': recent_reports,
        'category_stats': category_stats,
        'categories': PhishingReport.CATEGORY_CHOICES,
    })

def reports_dashboard(request):
    """Dashboard view for administrators to see all reports."""
    reports = PhishingReport.objects.all().order_by('-created_at')
    paginator = Paginator(reports, 20)  # Show 20 reports per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'reporting/dashboard.html', {
        'page_title': 'Զեկուցումների վահանակ',
        'page_obj': page_obj,
        'total_reports': reports.count(),
    })