from django.db import models
from django.contrib import admin


class SecurityIntegration(models.Model):
    """Model for managing security API integrations"""
    
    STATUS_CHOICES = [
        ('active', 'Ակտիվ'),
        ('inactive', 'Ոչ ակտիվ'),
        ('maintenance', 'Սպասարկում'),
        ('coming_soon', 'Շուտով հասանելի'),
    ]
    
    INTEGRATION_TYPES = [
        ('url_scanner', 'URL Scanner'),
        ('ip_checker', 'IP Checker'),
        ('file_scanner', 'File Scanner'),
        ('domain_reputation', 'Domain Reputation'),
    ]
    
    name = models.CharField(max_length=100, verbose_name="Աղբյուրի անուն")
    slug = models.SlugField(max_length=100, unique=True, verbose_name="Slug (for code)")
    
    # API Configuration
    api_url = models.URLField(verbose_name="API URL", blank=True)
    api_key = models.CharField(max_length=500, verbose_name="API Key", blank=True)
    api_headers = models.JSONField(default=dict, blank=True, verbose_name="Additional Headers")
    
    # Display Configuration
    display_name = models.CharField(max_length=100, verbose_name="Ցուցադրվող անուն")
    description = models.CharField(max_length=200, verbose_name="Նկարագրություն")
    icon_class = models.CharField(max_length=100, verbose_name="Icon Class (FontAwesome)", 
                                 default="fas fa-shield-alt")
    color_class = models.CharField(max_length=50, verbose_name="Color Class", 
                                  default="text-primary")
    
    # Status and Configuration
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='coming_soon',
                             verbose_name="Կարգավիճակ")
    integration_type = models.CharField(max_length=30, choices=INTEGRATION_TYPES, 
                                      default='url_scanner', verbose_name="Ինտեգրացիայի տեսակ")
    
    # Order and Priority
    order = models.PositiveIntegerField(default=100, verbose_name="Դասակարգման հերթականություն")
    priority = models.PositiveIntegerField(default=50, verbose_name="Առաջնություն (1-100)")
    
    # Rate Limiting
    rate_limit_per_minute = models.PositiveIntegerField(default=60, 
                                                       verbose_name="Հարցումներ րոպեում")
    timeout_seconds = models.PositiveIntegerField(default=30, verbose_name="Timeout (վայրկյան)")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        verbose_name = "Անվտանգության Ինտեգրացիա"
        verbose_name_plural = "Անվտանգության Ինտեգրացիաներ"
        ordering = ['order', 'name']
    
    def __str__(self):
        return f"{self.display_name} ({self.status})"
    
    @property
    def is_active(self):
        return self.status == 'active'
    
    @property
    def has_api_config(self):
        return bool(self.api_url and self.api_key)


@admin.register(SecurityIntegration)
class SecurityIntegrationAdmin(admin.ModelAdmin):
    list_display = ['display_name', 'slug', 'status', 'integration_type', 'order', 'has_api_config']
    list_filter = ['status', 'integration_type', 'created_at']
    search_fields = ['name', 'display_name', 'slug']
    list_editable = ['status', 'order']
    prepopulated_fields = {'slug': ('name',)}
    
    fieldsets = (
        ('Հիմնական տեղեկություններ', {
            'fields': ('name', 'slug', 'display_name', 'description', 'integration_type')
        }),
        ('API Կոնֆիգուրացիա', {
            'fields': ('api_url', 'api_key', 'api_headers', 'rate_limit_per_minute', 'timeout_seconds'),
            'classes': ('collapse',)
        }),
        ('Ցուցադրում', {
            'fields': ('icon_class', 'color_class', 'status', 'order', 'priority')
        }),
        ('Մետադատա', {
            'fields': ('created_by',),
            'classes': ('collapse',)
        })
    )
    
    def save_model(self, request, obj, form, change):
        if not change:  # If creating new object
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


class IntegrationResult(models.Model):
    """Store results from security integrations"""
    
    integration = models.ForeignKey(SecurityIntegration, on_delete=models.CASCADE)
    url_check = models.ForeignKey('URLCheck', on_delete=models.CASCADE, related_name='integration_results')
    
    # Result data
    status = models.CharField(max_length=20, choices=[
        ('safe', 'Անվտանգ'),
        ('malicious', 'Վտանգավոր'),
        ('suspicious', 'Կասկածելի'),
        ('pending', 'Սպասում'),
        ('error', 'Սխալ'),
    ])
    
    confidence = models.CharField(max_length=10, choices=[
        ('high', 'Բարձր'),
        ('medium', 'Միջին'),
        ('low', 'Ցածր'),
    ], default='medium')
    
    raw_response = models.JSONField(default=dict, verbose_name="Raw API Response")
    processed_data = models.JSONField(default=dict, verbose_name="Processed Data")
    
    # Timing and metadata
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Ինտեգրացիայի արդյունք"
        verbose_name_plural = "Ինտեգրացիայի արդյունքներ"
        unique_together = ['integration', 'url_check']
    
    def __str__(self):
        return f"{self.integration.display_name} - {self.status}"
