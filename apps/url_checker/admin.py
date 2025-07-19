from django.contrib import admin
from .models import URLCheck

@admin.register(URLCheck)
class URLCheckAdmin(admin.ModelAdmin):
    list_display = ['input_text', 'status', 'source', 'checked_at']
    list_filter = ['status', 'source']
    search_fields = ['input_text', 'analysis_result']