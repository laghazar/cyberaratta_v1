from django.db import models
from django.utils import timezone
from django.core.validators import URLValidator, FileExtensionValidator
from django.core.exceptions import ValidationError
import os


def validate_file_size(value):
    """File size validator"""
    if value.size > 10 * 1024 * 1024:  # 10MB limit
        raise ValidationError('File size cannot exceed 10MB.')

def validate_image_size(value):
    """Image size validator"""
    if value.size > 5 * 1024 * 1024:  # 5MB limit for images
        raise ValidationError('Image size cannot exceed 5MB.')

def validate_audio_size(value):
    """Audio size validator"""
    if value.size > 15 * 1024 * 1024:  # 15MB limit for audio
        raise ValidationError('Audio file size cannot exceed 15MB.')

def validate_video_size(value):
    """Video size validator"""
    if value.size > 50 * 1024 * 1024:  # 50MB limit for video
        raise ValidationError('Video file size cannot exceed 50MB.')

def validate_any_file_size(value):
    """General file size validator"""
    if value.size > 25 * 1024 * 1024:  # 25MB limit for general files
        raise ValidationError('File size cannot exceed 25MB.')

def evidence_upload_path(instance, filename):
    """Generate upload path for evidence files"""
    return f'evidence/{instance.created_at.year}/{instance.created_at.month}/{filename}'


# Admin-managed platform list
class PlatformSourceManager(models.Manager):
    def get_queryset(self):
        # Custom ordering to put "Այլ" at the end
        from django.db.models import Case, When, Value, CharField
        return super().get_queryset().annotate(
            sort_order=Case(
                When(name='Այլ', then=Value('z_other')),
                default='name',
                output_field=CharField()
            )
        ).order_by('sort_order')

class PlatformSource(models.Model):
    name = models.CharField(max_length=200, unique=True, verbose_name="Հարթակ/Աղբյուր")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ")
    
    objects = PlatformSourceManager()

    class Meta:
        verbose_name = "Հարթակ/Աղբյուր"
        verbose_name_plural = "Հարթակներ/Աղբյուրներ"
        ordering = ['name']

    def __str__(self):
        return self.name


class DamageType(models.Model):
    """Վնասի տեսակներ - ադմինից կառավարվող"""
    CATEGORY_CHOICES = [
        ('data_breach', 'Տվյալների արտահոսք/գաղտնիության խախտում'),
        ('financial_loss', 'Ֆինանսական կորուստներ'),
        ('account_loss', 'Օգտահաշվի կորուստ/չարաշահում'),
        ('device_control_loss', 'Սարքի/համակարգի վերահսկողության կորուստ'),
        ('psychological_damage', 'Հոգեբանական/սոցիալական վնասներ'),
        ('incident_no_damage', 'Դեպք եղել է, բայց վնաս չկա'),
        ('other_damage', 'Այլ վնասներ'),
    ]
    
    name = models.CharField(max_length=300, verbose_name="Վնասի տեսակ")
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, verbose_name="Կատեգորիա")
    description = models.TextField(blank=True, verbose_name="Նկարագրություն")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ")
    order = models.IntegerField(default=0, verbose_name="Հերթականություն")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստեղծված")
    
    class Meta:
        verbose_name = "Վնասի տեսակ"
        verbose_name_plural = "Վնասի տեսակներ"
        ordering = ['category', 'order', 'name']
    
    def __str__(self):
        return f"{self.get_category_display()} - {self.name}"

class PhishingReport(models.Model):
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
    STATUS_CHOICES = [
        ('pending', 'Դիտարկման տակ'),
        ('investigating', 'Քննվում է'),
        ('resolved', 'Լուծված'),
        ('closed', 'Փակված'),
        ('false_positive', 'Կեղծ ահազանգ'),
    ]

    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, verbose_name="Կատեգորիա")
    description = models.TextField(verbose_name="Նկարագրություն", null=True, blank=True)
    platform_source = models.ForeignKey(PlatformSource, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Հարթակ/Աղբյուր")
    platform_source_other = models.CharField(max_length=200, blank=True, verbose_name="Այլ հարթակ/աղբյուր")
    suspicious_url = models.CharField(max_length=500, blank=True, verbose_name="Կասկածելի URL")
    suspicious_email = models.CharField(max_length=200, blank=True, verbose_name="Կասկածելի էլ. փոստ")
    contact_info = models.CharField(max_length=200, blank=True, verbose_name="Հետադարձ կապի տվյալներ")
    
    # Damage related fields
    has_damage = models.BooleanField(default=False, verbose_name="Արդյոք կրել եք վնաս այս դեպքի արդյունքում?")
    damage_types = models.ManyToManyField(DamageType, blank=True, verbose_name="Կրած վնասի տեսակները")
    damage_details = models.TextField(blank=True, verbose_name="Վնասի մանրամասներ")
    
    # Evidence files
    evidence_image = models.ImageField(
        upload_to=evidence_upload_path,
        blank=True,
        null=True,
        validators=[
            validate_image_size,
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'gif', 'webp'])
        ],
        verbose_name="Ապացույցի նկար (մաքս. 5ՄԲ)",
        help_text="Թույլատրելի ֆորմատներ: JPG, PNG, GIF, WebP (մաքս. 5ՄԲ)"
    )
    
    evidence_document = models.FileField(
        upload_to=evidence_upload_path,
        blank=True,
        null=True,
        validators=[
            validate_file_size,
            FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx', 'txt', 'rtf'])
        ],
        verbose_name="Ապացույցի փաստաթուղթ (մաքս. 10ՄԲ)",
        help_text="Թույլատրելի ֆորմատներ: PDF, DOC, DOCX, TXT, RTF (մաքս. 10ՄԲ)"
    )
    
    evidence_audio = models.FileField(
        upload_to=evidence_upload_path,
        blank=True,
        null=True,
        validators=[
            validate_audio_size,
            FileExtensionValidator(allowed_extensions=['mp3', 'wav', 'ogg', 'm4a', 'aac'])
        ],
        verbose_name="Ապացույցի ձայնագրություն (մաքս. 15ՄԲ)",
        help_text="Թույլատրելի ֆորմատներ: MP3, WAV, OGG, M4A, AAC (մաքս. 15ՄԲ)"
    )
    
    # General evidence files - multiple files support
    evidence_files = models.FileField(
        upload_to=evidence_upload_path,
        blank=True,
        null=True,
        validators=[
            validate_any_file_size,
            FileExtensionValidator(allowed_extensions=[
                # Images
                'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff',
                # Documents  
                'pdf', 'doc', 'docx', 'txt', 'rtf', 'odt',
                # Videos
                'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv',
                # Audio
                'mp3', 'wav', 'ogg', 'm4a', 'aac', 'flac',
                # Archives
                'zip', 'rar', '7z'
            ])
        ],
        verbose_name="Կցել ֆայլ",
        help_text="Թույլատրվում են՝ նկարներ (մաքս. 5ՄԲ), փաստաթղթեր (մաքս. 10ՄԲ), վիդեո (մաքս. 50ՄԲ), ձայն (մաքս. 15ՄԲ), արխիվ (մաքս. 25ՄԲ). Ընդհանուր մաքս. ծավալ՝ 100ՄԲ"
    )
    
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
        return (timezone.now() - self.created_at).days < 1

class EvidenceFile(models.Model):
    """Ապացույցի ֆայլեր բազմակի ֆայլերի համար"""
    phishing_report = models.ForeignKey('PhishingReport', on_delete=models.CASCADE, related_name='uploaded_files')
    file = models.FileField(
        upload_to=evidence_upload_path,
        validators=[
            validate_any_file_size,
            FileExtensionValidator(allowed_extensions=[
                # Images
                'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff',
                # Documents  
                'pdf', 'doc', 'docx', 'txt', 'rtf', 'odt',
                # Videos
                'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv',
                # Audio
                'mp3', 'wav', 'ogg', 'm4a', 'aac', 'flac',
                # Archives
                'zip', 'rar', '7z'
            ])
        ]
    )
    file_type = models.CharField(max_length=20, choices=[
        ('image', 'Նկար'),
        ('document', 'Փաստաթուղթ'),
        ('video', 'Վիդեո'),
        ('audio', 'Ձայն'),
        ('archive', 'Արխիվ'),
        ('other', 'Այլ')
    ], default='other')
    description = models.CharField(max_length=200, blank=True, verbose_name="Նկարագրություն")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    file_size = models.PositiveIntegerField(default=0)  # Size in bytes
    
    class Meta:
        verbose_name = "Ապացույցի ֆայլ"
        verbose_name_plural = "Ապացույցի ֆայլեր"
        ordering = ['-uploaded_at']
    
    def save(self, *args, **kwargs):
        if self.file:
            self.file_size = self.file.size
            # Auto-detect file type based on extension
            ext = self.file.name.split('.')[-1].lower()
            if ext in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff']:
                self.file_type = 'image'
            elif ext in ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt']:
                self.file_type = 'document'
            elif ext in ['mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv']:
                self.file_type = 'video'
            elif ext in ['mp3', 'wav', 'ogg', 'm4a', 'aac', 'flac']:
                self.file_type = 'audio'
            elif ext in ['zip', 'rar', '7z']:
                self.file_type = 'archive'
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.file.name} ({self.get_file_type_display()})"

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