from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from datetime import timedelta
from .models import PhishingReport, ContactInfo, PlatformSource, DamageType, EvidenceFile
from .forms import PhishingReportForm
from apps.core.utils import update_statistics

@require_http_methods(["GET"])
def damage_types_api(request):
    """API endpoint to get damage types grouped by category"""
    damage_types = DamageType.objects.filter(is_active=True).order_by('category', 'order', 'name')
    
    # Group by category
    categories = {}
    for damage_type in damage_types:
        category_key = damage_type.category
        category_name = damage_type.get_category_display()
        
        if category_key not in categories:
            categories[category_key] = {
                'name': category_name,
                'items': []
            }
        
        categories[category_key]['items'].append({
            'id': damage_type.id,
            'name': damage_type.name,
            'description': damage_type.description
        })
    
    return JsonResponse({'categories': categories})

@require_http_methods(["GET"])
def platform_search_ajax(request):
    """AJAX view for searchable platform dropdown"""
    search_term = request.GET.get('q', '').strip()
    
    # Filter platforms based on search term
    platforms = PlatformSource.objects.filter(
        is_active=True,
        name__icontains=search_term
    ).order_by('name')
    
    # Separate "Այլ" from other platforms and put it at the end
    regular_platforms = platforms.exclude(name='Այլ')
    other_platform = platforms.filter(name='Այլ')
    
    results = []
    
    # Add regular platforms
    for platform in regular_platforms:
        results.append({
            'id': platform.id,
            'text': platform.name
        })
    
    # Add "Այլ" at the end if it exists
    for platform in other_platform:
        results.append({
            'id': platform.id,
            'text': platform.name
        })
    
    return JsonResponse({
        'results': results,
        'pagination': {'more': False}  # We're not implementing pagination for now
    })

def phishing_report_view(request):
    """Handle phishing report submission and display report form."""
    if request.method == 'POST':
        form = PhishingReportForm(request.POST, request.FILES)
        if form.is_valid():
            report = form.save(commit=False)
            
            # Handle platform_source conversion
            platform_source_id = form.cleaned_data.get('platform_source')
            if platform_source_id:
                try:
                    report.platform_source = PlatformSource.objects.get(pk=platform_source_id)
                except PlatformSource.DoesNotExist:
                    report.platform_source = None
            
            report.save()
            form.save_m2m()  # Save many-to-many relationships
            
            # Handle multiple file uploads
            files = request.FILES.getlist('evidence_files_multiple')
            for file in files:
                if file:
                    EvidenceFile.objects.create(
                        phishing_report=report,
                        file=file,
                        description=f"Uploaded file: {file.name}"
                    )
            
            update_statistics()
            
            # Create detailed success message
            success_msg = f"""
            <div class="alert-content">
                <h5><i class="fas fa-check-circle text-success me-2"></i>Զեկուցումը հաջողությամբ ընդունվեց</h5>
                <p class="mb-2"><strong>Զեկուցման ID:</strong> #{report.id:06d}</p>
                <p class="mb-2"><strong>Ակատեգորիա:</strong> {report.get_category_display()}</p>
                <p class="mb-2"><strong>Ստեղծման ամսաթիվ:</strong> {report.created_at.strftime('%d.%m.%Y %H:%M')}</p>
                <hr class="my-2">
                <p class="small text-muted mb-0">
                    <i class="fas fa-info-circle me-1"></i>
                    Ձեր զեկուցումը կուսումնասիրվի մեր մասնագետների կողմից և կճանակվի համապատասխան քայլեր։
                    Շնորհակալություն ձեր կարևոր ներդրման համար։
                </p>
            </div>
            """
            messages.success(request, success_msg, extra_tags='safe')
            return redirect('reporting:index')
        else:
            # Create detailed error message
            error_msg = """
            <div class="alert-content">
                <h6><i class="fas fa-exclamation-triangle text-warning me-2"></i>Զեկուցումը չի կարող ուղարկվել</h6>
                <p class="mb-0">Խնդրում ենք ստուգել և ճշտել բոլոր պարտադիր դաշտերը:</p>
            </div>
            """
            messages.error(request, error_msg, extra_tags='safe')
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