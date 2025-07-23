from django.contrib import admin
from django.utils.html import format_html
from .models import PhishingReport, ContactInfo, ReportStatistics, ContactGuideline

@admin.register(PhishingReport)
class PhishingReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'category', 'platform_source', 'severity', 'status_badge', 'suspicious_url_short', 'suspicious_email', 'is_anonymous', 'is_recent_badge', 'created_at']
    list_filter = ['category', 'status', 'severity', 'is_anonymous', 'created_at', 'platform_source']
    search_fields = ['description', 'suspicious_url', 'suspicious_email', 'contact_info', 'platform_source']
    readonly_fields = ['created_at', 'updated_at']
    fieldsets = (
        ('Հիմնական տեղեկություններ', {
            'fields': ('category', 'platform_source', 'severity', 'status', 'description')
        }),
        ('Կասկածելի տվյալներ', {
            'fields': ('suspicious_url', 'suspicious_email')
        }),
        ('Կապի տեղեկություններ', {
            'fields': ('contact_info', 'is_anonymous')
        }),
        ('Ադմինի գրառումներ', {
            'fields': ('admin_notes',)
        }),
        ('Ժամանակի տվյալներ', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def status_badge(self, obj):
        colors = {
            'pending': 'warning',
            'investigating': 'info',
            'resolved': 'success',
            'closed': 'secondary',
            'false_positive': 'danger'
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(
            '<span class="badge bg-{}">{}</span>',
            color,
            obj.get_status_display()
        )
    status_badge.short_description = 'Կարգավիճակ'
    
    def is_recent_badge(self, obj):
        if obj.is_recent:
            return format_html('<span class="badge bg-success">Նոր</span>')
        return ''
    is_recent_badge.short_description = 'Նորություն'
    
    def suspicious_url_short(self, obj):
        if obj.suspicious_url:
            if len(obj.suspicious_url) > 50:
                return obj.suspicious_url[:50] + '...'
            return obj.suspicious_url
        return '-'
    suspicious_url_short.short_description = 'Կասկածելի URL'

class ContactGuidelineInline(admin.StackedInline):
    model = ContactGuideline
    extra = 0
    fields = ('when_to_contact', 'required_documents', 'process_description', 'response_time', 'additional_info', 'is_active')

@admin.register(ContactInfo)
class ContactInfoAdmin(admin.ModelAdmin):
    list_display = ('name', 'phone', 'email', 'website', 'is_emergency_badge', 'is_active', 'order', 'has_guideline')
    list_filter = ('is_emergency', 'is_active')
    search_fields = ('name', 'description', 'email')
    list_editable = ('order', 'is_active')
    ordering = ('order', 'name')
    inlines = [ContactGuidelineInline]
    
    def is_emergency_badge(self, obj):
        if obj.is_emergency:
            return format_html('<span class="badge bg-danger">Արտակարգ</span>')
        return ''
    is_emergency_badge.short_description = 'Արտակարգ'
    
    def has_guideline(self, obj):
        if hasattr(obj, 'guideline') and obj.guideline:
            return format_html('<span class="badge bg-success">Այո</span>')
        return format_html('<span class="badge bg-secondary">Ոչ</span>')
    has_guideline.short_description = 'Ունի ուղեցույց'

@admin.register(ContactGuideline)
class ContactGuidelineAdmin(admin.ModelAdmin):
    list_display = ('contact', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('contact__name', 'when_to_contact', 'process_description')
    readonly_fields = ('created_at', 'updated_at')
    
    fieldsets = (
        ('Կոնտակտի տեղեկություններ', {
            'fields': ('contact', 'is_active')
        }),
        ('Ուղեցույցի բովանդակություն', {
            'fields': ('when_to_contact', 'required_documents', 'process_description', 'response_time', 'additional_info')
        }),
        ('Ժամանակի տվյալներ', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

@admin.register(ReportStatistics)
class ReportStatisticsAdmin(admin.ModelAdmin):
    list_display = ('date', 'total_reports', 'resolved_reports', 'pending_reports', 'resolution_rate')
    list_filter = ('date',)
    readonly_fields = ('date',)
    
    def resolution_rate(self, obj):
        if obj.total_reports > 0:
            rate = (obj.resolved_reports / obj.total_reports) * 100
            return f"{rate:.1f}%"
        return "0%"
    resolution_rate.short_description = 'Լուծման տոկոս'
