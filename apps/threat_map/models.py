from django.db import models
from django.utils import timezone
from datetime import timedelta

class Threat(models.Model):
    """Կիբեռսպառնալիքի մոդել"""
    TYPE_CHOICES = [
        ('phishing', 'Ֆիշինգ'),
        ('malware', 'Վնասակար ծրագիր'),
        ('ddos', 'DDoS հարձակում'),
        ('data_breach', 'Տվյալների արտահոսք'),
        ('ransomware', 'Ransomware'),
        ('other', 'Այլ'),
    ]

    type = models.CharField(max_length=20, choices=TYPE_CHOICES, verbose_name="Տեսակ")
    source_country = models.CharField(max_length=100, blank=True, verbose_name="Աղբյուրի երկիր")
    target_country = models.CharField(max_length=100, default='Armenia', verbose_name="Թիրախային երկիր")
    severity = models.CharField(max_length=10, choices=[
        ('low', 'Ցածր'), 
        ('medium', 'Միջին'), 
        ('high', 'Բարձր'), 
        ('critical', 'Կրիտիկական')
    ], default='medium', verbose_name="Լուրջություն")
    reported_at = models.DateTimeField(auto_now_add=True, verbose_name="Հայտնաբերման ժամանակ")
    description = models.TextField(blank=True, verbose_name="Նկարագրություն")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ է")
    ip_address = models.GenericIPAddressField(blank=True, null=True, verbose_name="IP հասցե")
    
    class Meta:
        verbose_name = "Սպառնալիք"
        verbose_name_plural = "Սպառնալիքներ"
        ordering = ['-reported_at']

    def __str__(self):
        return f"{self.get_type_display()} - {self.source_country} → {self.target_country}"
    
    @property
    def is_recent(self):
        """Check if threat is from last 24 hours"""
        return (timezone.now() - self.reported_at).days < 1

class PhishingURL(models.Model):
    """Ֆիշինգ URL-ների մոդել զեկուցումներից"""
    url = models.CharField(max_length=500, verbose_name="URL")
    source_report = models.ForeignKey(
        'reporting.PhishingReport', 
        on_delete=models.CASCADE, 
        verbose_name="Նախնական զեկուցում"
    )
    category = models.CharField(max_length=20, verbose_name="Կատեգորիա")
    platform_source = models.CharField(max_length=200, blank=True, verbose_name="Հարթակ/Աղբյուր")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ է")
    last_checked = models.DateTimeField(auto_now=True, verbose_name="Վերջին ստուգում")
    status_code = models.IntegerField(null=True, blank=True, verbose_name="HTTP Status")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստեղծված")
    
    class Meta:
        verbose_name = "Ֆիշինգ URL"
        verbose_name_plural = "Ֆիշինգ URL-ներ"
        ordering = ['-created_at']
        unique_together = ['url', 'source_report']
    
    def __str__(self):
        return f"{self.url} ({self.category})"
    
    @property
    def is_recent(self):
        """Check if URL is from last 30 days"""
        return (timezone.now() - self.created_at).days <= 30
    
    @property
    def domain(self):
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            return urlparse(self.url).netloc
        except:
            return self.url

class CyberThreatIntelligence(models.Model):
    """Կիբեռ սպառնալիքների հետախուզական տվյալներ"""
    threat_type = models.CharField(max_length=50, verbose_name="Սպառնալիքի տեսակ")
    source_country = models.CharField(max_length=100, verbose_name="Աղբյուրի երկիր")
    target_sector = models.CharField(max_length=100, blank=True, verbose_name="Թիրախային ոլորտ")
    description = models.TextField(verbose_name="Նկարագրություն")
    confidence_level = models.CharField(max_length=20, choices=[
        ('low', 'Ցածր'),
        ('medium', 'Միջին'),
        ('high', 'Բարձր')
    ], default='medium', verbose_name="Վստահության մակարդակ")
    detected_at = models.DateTimeField(auto_now_add=True, verbose_name="Հայտնաբերում")
    source_feed = models.CharField(max_length=100, blank=True, verbose_name="Աղբյուրի feed")
    
    class Meta:
        verbose_name = "Կիբեռ հետախուզություն"
        verbose_name_plural = "Կիբեռ հետախուզություն"
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.threat_type} - {self.source_country}"