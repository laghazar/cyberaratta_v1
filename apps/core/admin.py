from django.contrib import admin
from .models import SiteStatistics, Character

@admin.register(SiteStatistics)
class SiteStatisticsAdmin(admin.ModelAdmin):
    list_display = ['total_reports', 'monthly_reports', 'total_quizzes', 'total_url_checks', 'last_updated']
    readonly_fields = ['last_updated']
    
    def has_add_permission(self, request):
        return not SiteStatistics.objects.exists()

@admin.register(Character)
class CharacterAdmin(admin.ModelAdmin):
    list_display = ['name', 'character_type', 'is_positive']
    list_filter = ['character_type', 'is_positive']
    search_fields = ['name', 'description']
    
    fieldsets = (
        ('Հիմնական տվյալներ', {
            'fields': ('name', 'character_type', 'is_positive')
        }),
        ('Բովանդակություն', {
            'fields': ('description', 'image')
        }),
    )