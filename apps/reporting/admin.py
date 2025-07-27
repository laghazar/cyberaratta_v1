from django.contrib import admin
from django.utils.html import format_html
from .models import PhishingReport, ContactInfo, ReportStatistics, ContactGuideline, PlatformSource, DamageType

@admin.register(PhishingReport)
class PhishingReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'category', 'platform_source', 'platform_source_other', 'severity', 'status_badge', 'has_damage_badge', 'suspicious_url_short', 'suspicious_email', 'is_recent_badge', 'created_at']
    list_filter = ['category', 'status', 'severity', 'has_damage', 'created_at', 'platform_source', 'damage_types']
    search_fields = ['description', 'suspicious_url', 'suspicious_email', 'contact_info', 'platform_source__name', 'platform_source_other', 'damage_details']
    readonly_fields = ['created_at', 'updated_at']
    filter_horizontal = ['damage_types']
    
    fieldsets = (
        ('Հիմնական տեղեկություններ', {
            'fields': ('category', 'platform_source', 'platform_source_other', 'severity', 'status', 'description')
        }),
        ('Կասկածելի տվյալներ', {
            'fields': ('suspicious_url', 'suspicious_email')
        }),
        ('Կապի տեղեկություններ', {
            'fields': ('contact_info',)
        }),
        ('Վնասի տեղեկություններ', {
            'fields': ('has_damage', 'damage_types', 'damage_details'),
            'description': 'Վնասի մասին տեղեկություններ'
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
    
    def has_damage_badge(self, obj):
        if obj.has_damage:
            damage_count = obj.damage_types.count()
            return format_html(
                '<span class="badge bg-danger">Վնաս կա ({})</span>',
                damage_count
            )
        return format_html('<span class="badge bg-success">Վնաս չկա</span>')
    has_damage_badge.short_description = 'Վնասի առկայություն'

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
# Register PlatformSource for admin management
@admin.register(PlatformSource)
class PlatformSourceAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('name',)
    ordering = ('name',)
    
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


@admin.register(DamageType)
class DamageTypeAdmin(admin.ModelAdmin):
    list_display = ['name', 'category_display', 'is_active', 'order', 'created_at']
    list_filter = ['category', 'is_active', 'created_at']
    search_fields = ['name', 'description']
    list_editable = ['is_active', 'order']
    ordering = ['category', 'order', 'name']
    
    fieldsets = (
        ('Հիմնական տեղեկություններ', {
            'fields': ('name', 'category', 'description')
        }),
        ('Կարգավորումներ', {
            'fields': ('is_active', 'order')
        }),
    )
    
    def category_display(self, obj):
        return obj.get_category_display()
    category_display.short_description = 'Կատեգորիա'
    
    # Add action to activate/deactivate multiple items
    actions = ['activate_damage_types', 'deactivate_damage_types']
    
    def activate_damage_types(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} վնասի տեսակ ակտիվացվեց')
    activate_damage_types.short_description = 'Ակտիվացնել ընտրված վնասի տեսակները'
    
    def deactivate_damage_types(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} վնասի տեսակ անակտիվացվեց')
    deactivate_damage_types.short_description = 'Անակտիվացնել ընտրված վնասի տեսակները'
