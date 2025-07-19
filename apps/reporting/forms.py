from django import forms
from .models import PhishingReport

class PhishingReportForm(forms.ModelForm):
    class Meta:
        model = PhishingReport
        fields = ['category', 'description', 'suspicious_url', 'suspicious_email', 'contact_info', 'is_anonymous']