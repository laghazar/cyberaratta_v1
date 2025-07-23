from django.db import models
from django.utils import timezone
from django.core.validators import URLValidator

class PhishingReport(models.Model):
    """Ֆիշինգի զեկուցման մոդել"""
    CATEGORY_CHOICES = [
        ('banking', 'Բանկային ֆիշինգ'),
        ('social_media', 'Սոցիալական ցանցեր'),
        ('sms', 'SMS ֆիշինգ'),
        ('email', 'Էլ. փոստի ֆիշինգ'),
        ('cryptocurrency', 'Կրիպտոարժույթ'),
        ('online_shopping', 'Առցանց գնումներ'),
        ('government', 'Պետական ծառայություններ'),
        ('other', 'Այլ'),
    ]
    
    PLATFORM_CHOICES = [
        ('facebook', 'Facebook'),
        ('instagram', 'Instagram'),
        ('telegram', 'Telegram'),
        ('whatsapp', 'WhatsApp'),
        ('viber', 'Viber'),
        ('email', 'Էլ. փոստ'),
        ('sms', 'SMS'),
        ('website', 'Կայքէջ'),
        ('other', 'Այլ'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Դիտարկման տակ'),
        ('investigating', 'Քննվում է'),
        ('resolved', 'Լուծված'),
        ('closed', 'Փակված'),
        ('false_positive', 'Կեղծ ահազանգ'),
    ]

    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, verbose_name="Կատեգորիա")
    description = models.TextField(verbose_name="Նկարագրություն")
    platform_source = models.CharField(max_length=200, choices=PLATFORM_CHOICES, blank=True, verbose_name="Հարթակ/Աղբյուր")
    suspicious_url = models.CharField(max_length=500, blank=True, verbose_name="Կասկածելի URL")
    suspicious_email = models.CharField(max_length=200, blank=True, verbose_name="Կասկածելի էլ. փոստ")
    contact_info = models.CharField(max_length=200, blank=True, verbose_name="Հետադարձ կապի տվյալներ")
    is_anonymous = models.BooleanField(default=True, verbose_name="Անանուն")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստեղծված")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Թարմացված")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name="Կարգավիճակ")
    admin_notes = models.TextField(blank=True, verbose_name="Ադմինի գրառումներ")
    severity = models.CharField(max_length=10, choices=[
        ('low', 'Ցածր'), 
        ('medium', 'Միջին'), 
        ('high', 'Բարձր'), 
        ('critical', 'Կրիտիկական')
    ], default='medium', verbose_name="Լուրջություն")

    class Meta:
        verbose_name = "Ֆիշինգի զեկուցում"
        verbose_name_plural = "Ֆիշինգի զեկուցումներ"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_category_display()} - {self.created_at.date()}"
    
    @property
    def is_recent(self):
        """Check if report was created in last 24 hours"""
        return (timezone.now() - self.created_at).days < 1

class ContactInfo(models.Model):
    """Կոնտակտային տեղեկություններ"""
    name = models.CharField(max_length=255, verbose_name="Անուն")
    description = models.TextField(blank=True, null=True, verbose_name="Նկարագրություն")
    phone = models.CharField(max_length=50, blank=True, null=True, verbose_name="Հեռախոս")
    email = models.EmailField(blank=True, null=True, verbose_name="Էլ. փոստ")
    website = models.URLField(blank=True, null=True, verbose_name="Կայք")
    is_emergency = models.BooleanField(default=False, verbose_name="Արտակարգ իրավիճակի համար")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստեղծված")
    order = models.IntegerField(default=0, verbose_name="Հերթականություն")

    class Meta:
        verbose_name = "Կոնտակտային տեղեկություն"
        verbose_name_plural = "Կոնտակտային տեղեկություններ"
        ordering = ['order', 'name']

    def __str__(self):
        return self.name

class ContactGuideline(models.Model):
    """Մարմինների դիմելու համար ուղեցույցներ"""
    contact = models.OneToOneField(ContactInfo, on_delete=models.CASCADE, related_name='guideline', verbose_name="Կոնտակտ")
    when_to_contact = models.TextField(verbose_name="Երբ դիմել")
    required_documents = models.TextField(blank=True, verbose_name="Անհրաժեշտ փաստաթղթեր")
    process_description = models.TextField(blank=True, verbose_name="Գործընթացի նկարագրություն")
    response_time = models.CharField(max_length=100, blank=True, verbose_name="Պատասխանի ժամկետ")
    additional_info = models.TextField(blank=True, verbose_name="Լրացուցիչ տեղեկություններ")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստեղծված")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Թարմացված")

    class Meta:
        verbose_name = "Կոնտակտի ուղեցույց"
        verbose_name_plural = "Կոնտակտների ուղեցույցներ"

    def __str__(self):
        return f"{self.contact.name} - Ուղեցույց"

class ReportStatistics(models.Model):
    """Զեկուցումների վիճակագրություն"""
    date = models.DateField(auto_now_add=True, verbose_name="Ամսաթիվ")
    total_reports = models.IntegerField(default=0, verbose_name="Ընդհանուր զեկուցումներ")
    resolved_reports = models.IntegerField(default=0, verbose_name="Լուծված զեկուցումներ")
    pending_reports = models.IntegerField(default=0, verbose_name="Ընթացքի մեջ")
    
    class Meta:
        verbose_name = "Զեկուցման վիճակագրություն"
        verbose_name_plural = "Զեկուցումների վիճակագրություն"
        ordering = ['-date']

    def __str__(self):
        return f"Վիճակագրություն - {self.date}"

# Deprecated model - keeping for backward compatibility
class Report(models.Model):
    description = models.TextField()
    reported_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"Report at {self.reported_at}"