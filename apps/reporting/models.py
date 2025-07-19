from django.db import models
from django.utils import timezone

class PhishingReport(models.Model):
    """Ֆիշինգի զեկուցման մոդել"""
    CATEGORY_CHOICES = [
        ('banking', 'Բանկային'),
        ('social_media', 'Սոցիալական ցանցեր'),
        ('sms', 'SMS'),
        ('other', 'Այլ'),
    ]

    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, verbose_name="Կատեգորիա")
    description = models.TextField(verbose_name="Նկարագրություն")
    suspicious_url = models.CharField(max_length=500, blank=True, verbose_name="Կասկածելի URL")
    suspicious_email = models.CharField(max_length=200, blank=True, verbose_name="Կասկածելի էլ. փոստ")
    contact_info = models.CharField(max_length=200, blank=True, verbose_name="Հետադարձ կապի տվյալներ")
    is_anonymous = models.BooleanField(default=True, verbose_name="Անանուն")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստեղծված")
    status = models.CharField(max_length=20, default='pending', verbose_name="Կարգավիճակ")

    class Meta:
        verbose_name = "Ֆիշինգի զեկուցում"
        verbose_name_plural = "Ֆիշինգի զեկուցումներ"

    def __str__(self):
        return f"{self.get_category_display()} - {self.created_at.date()}"