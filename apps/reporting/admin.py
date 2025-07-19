from django.contrib import admin
from .models import PhishingReport

@admin.register(PhishingReport)
class PhishingReportAdmin(admin.ModelAdmin):
    list_display = ['category', 'suspicious_url', 'suspicious_email', 'is_anonymous', 'created_at', 'status']
    list_filter = ['category', 'is_anonymous', 'status']
    search_fields = ['description', 'suspicious_url', 'suspicious_email']