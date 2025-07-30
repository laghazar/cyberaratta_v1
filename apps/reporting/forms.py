from django import forms
from .models import PhishingReport, PlatformSource, DamageType, EvidenceFile

class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True

class MultipleFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput())
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, (list, tuple)):
            result = [single_file_clean(d, initial) for d in data]
        else:
            result = single_file_clean(data, initial)
        return result

class PhishingReportForm(forms.ModelForm):
    """Ֆիշինգի զեկուցման ձև"""
    
    # Use simple ChoiceField instead of ModelChoiceField to get real dropdown
    platform_source = forms.ChoiceField(
        choices=[],  # Will be populated in __init__
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select select2-platform',
            'id': 'id_platform_source',
            'data-placeholder': 'Ընտրել աղբյուրը',
            'data-allow-clear': 'true',
        })
    )
    
    # Multi-select for damage types
    damage_types = forms.ModelMultipleChoiceField(
        queryset=DamageType.objects.none(),  # Will be populated in __init__
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'form-select select2-damage-types',
            'id': 'id_damage_types',
            'data-placeholder': 'Ընտրել վնասի տեսակները',
            'data-allow-clear': 'true',
            'multiple': 'multiple',
        })
    )
    
    # Multiple files field
    evidence_files_multiple = MultipleFileField(
        required=False,
        widget=MultipleFileInput(attrs={
            'class': 'form-control custom-file-input',
            'accept': '.jpg,.jpeg,.png,.gif,.webp,.bmp,.tiff,.pdf,.doc,.docx,.txt,.rtf,.odt,.mp4,.avi,.mov,.wmv,.flv,.webm,.mkv,.mp3,.wav,.ogg,.m4a,.aac,.flac,.zip,.rar,.7z',
            'multiple': True,
            'id': 'evidence-files-multiple-input'
        })
    )
    
    class Meta:
        model = PhishingReport
        fields = ['category', 'description', 'platform_source_other', 'suspicious_url', 'suspicious_email', 'contact_info', 'has_damage', 'damage_types', 'damage_details']
        widgets = {
            'category': forms.Select(attrs={
                'class': 'form-select',
                'required': True,
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Նկարագրեք ձեր հանդիպած դեպքը մանրամասն...'
            }),
            'platform_source_other': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Մուտքագրեք այլ հարթակ/աղբյուր',
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
            'has_damage': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
                'id': 'id_has_damage',
            }),
            'damage_details': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Մանրամասներ վնասի մասին կամ լրացուցիչ տեղեկություններ...',
            }),
        }
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Populate platform_source choices
        self.fields['platform_source'].choices = [(ps.id, ps.name) for ps in PlatformSource.objects.all()]

    def clean(self):
        cleaned_data = super().clean()
        suspicious_url = cleaned_data.get('suspicious_url')
        suspicious_email = cleaned_data.get('suspicious_email')
        platform_source_id = cleaned_data.get('platform_source')
        platform_source_other = cleaned_data.get('platform_source_other')
        has_damage = cleaned_data.get('has_damage')
        damage_types = cleaned_data.get('damage_types')
        
        # Check if "Այլ" is selected
        if platform_source_id:
            try:
                platform_obj = PlatformSource.objects.get(id=platform_source_id)
                if platform_obj.name == 'Այլ' and not platform_source_other:
                    self.add_error('platform_source_other', 'Խնդրում ենք մուտքագրել այլ հարթակ/աղբյուր')
            except PlatformSource.DoesNotExist:
                pass
        
        # At least one of URL or email should be provided
        if not suspicious_url and not suspicious_email:
            raise forms.ValidationError('Խնդրում ենք տրամադրել առնվազն կասկածելի URL-ը կամ էլ. փոստը')
        
        # If has damage is checked, at least one damage type should be selected
        if has_damage and not damage_types:
            self.add_error('damage_types', 'Եթե կրել եք վնաս, խնդրում ենք ընտրել առնվազն մեկ վնասի տեսակ')
        
        return cleaned_data
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        # Don't handle platform_source here - it's handled in the view
        if commit:
            instance.save()
        return instance
