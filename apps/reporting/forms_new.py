from django import forms
from .models import PhishingReport

class PhishingReportForm(forms.ModelForm):
    """Ֆիշինգի զեկուցման ձև"""
    
    class Meta:
        model = PhishingReport
        fields = ['category', 'description', 'platform_source', 'suspicious_url', 'suspicious_email', 'contact_info', 'is_anonymous']
        widgets = {
            'category': forms.Select(attrs={
                'class': 'form-select',
                'required': True,
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Նկարագրեք ձեր հանդիպած դեպքը մանրամասն...',
                'required': True,
            }),
            'platform_source': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Օր.՝ Facebook, Instagram, Gmail, Viber և այլն',
            }),
            'suspicious_url': forms.URLInput(attrs={
                'class': 'form-control',
                'placeholder': 'https://example.com',
            }),
            'suspicious_email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'suspicious@example.com',
            }),
            'contact_info': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Հեռախոս, էլ. փոստ կամ այլ կապի միջոց (ոչ պարտադիր)',
            }),
            'is_anonymous': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
            }),
        }
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Customize field labels
        self.fields['category'].label = 'Կատեգորիա *'
        self.fields['description'].label = 'Դեպքի նկարագրություն *'
        self.fields['platform_source'].label = 'Հարթակ/Աղբյուր'
        self.fields['suspicious_url'].label = 'Կասկածելի URL հասցե'
        self.fields['suspicious_email'].label = 'Կասկածելի էլ. փոստ'
        self.fields['contact_info'].label = 'Հետադարձ կապի տվյալներ'
        self.fields['is_anonymous'].label = 'Անանուն զեկուցում'
        
        # Set help texts
        self.fields['category'].help_text = 'Ընտրեք ամենայն կատեգորիան'
        self.fields['description'].help_text = 'Նկարագրեք դեպքը հնարավորինս մանրամասն'
        self.fields['platform_source'].help_text = 'Նշեք, թե որ հարթակի/ծառայության միջոցով եք ստացել'
        self.fields['suspicious_url'].help_text = 'Եթե կա կասկածելի կայքի հասցե'
        self.fields['suspicious_email'].help_text = 'Եթե կա կասկածելի էլ. փոստի հասցե'
        self.fields['is_anonymous'].help_text = 'Նշեք, եթե ցանկանում եք անանուն մնալ'
        
    def clean_description(self):
        description = self.cleaned_data.get('description')
        if len(description.strip()) < 10:
            raise forms.ValidationError('Նկարագրությունը պետք է պարունակի առնվազն 10 նիշ')
        return description
        
    def clean(self):
        cleaned_data = super().clean()
        suspicious_url = cleaned_data.get('suspicious_url')
        suspicious_email = cleaned_data.get('suspicious_email')
        
        # At least one of URL or email should be provided
        if not suspicious_url and not suspicious_email:
            raise forms.ValidationError('Խնդրում ենք տրամադրել առնվազն կասկածելի URL-ը կամ էլ. փոստը')
            
        return cleaned_data
