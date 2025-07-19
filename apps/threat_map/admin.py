from django.contrib import admin
from .models import Threat

@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ['type', 'source_country', 'reported_at']
    list_filter = ['type', 'source_country']
    search_fields = ['description']