"""
CyberAratta Authentication System
Բարելավված authentication հետ 2FA և session management
"""
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta
import secrets
import pyotp

class CyberArattaUser(AbstractUser):
    """
    Բարելավված User մոդել
    """
    # 2FA Settings
    two_factor_enabled = models.BooleanField(default=False, verbose_name="2FA միացված է")
    two_factor_secret = models.CharField(max_length=32, blank=True, verbose_name="2FA գաղտնի բանալի")
    backup_tokens = models.JSONField(default=list, verbose_name="Backup tokens")
    
    # Security fields
    failed_login_attempts = models.IntegerField(default=0, verbose_name="Ձախողված մուտքեր")
    account_locked_until = models.DateTimeField(null=True, blank=True, verbose_name="Հաշիվը կողպված է մինչ")
    last_password_change = models.DateTimeField(default=timezone.now, verbose_name="Վերջին գաղտնաբառի փոփոխություն")
    
    # User activity
    last_activity = models.DateTimeField(null=True, blank=True, verbose_name="Վերջին ակտիվություն")
    login_ip = models.GenericIPAddressField(null=True, blank=True, verbose_name="Մուտքի IP")
    
    class Meta:
        verbose_name = "CyberAratta Օգտատեր"
        verbose_name_plural = "CyberAratta Օգտատերեր"
    
    def is_account_locked(self):
        """Ստուգել արդյոք հաշիվը կողպված է"""
        if self.account_locked_until and self.account_locked_until > timezone.now():
            return True
        return False
    
    def lock_account(self, duration_minutes=30):
        """Կողպել հաշիվը"""
        self.account_locked_until = timezone.now() + timedelta(minutes=duration_minutes)
        self.save()
    
    def unlock_account(self):
        """Բացել հաշիվը"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save()
    
    def record_failed_login(self):
        """Գրանցել ձախողված մուտք"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lock_account()
        self.save()
    
    def record_successful_login(self, ip_address=None):
        """Գրանցել հաջողված մուտք"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_activity = timezone.now()
        if ip_address:
            self.login_ip = ip_address
        self.save()
    
    def enable_two_factor(self):
        """Միացնել 2FA"""
        self.two_factor_secret = pyotp.random_base32()
        self.two_factor_enabled = True
        # Ստեղծել backup tokens
        self.backup_tokens = [secrets.token_hex(8) for _ in range(10)]
        self.save()
        return self.two_factor_secret
    
    def disable_two_factor(self):
        """Անջատել 2FA"""
        self.two_factor_enabled = False
        self.two_factor_secret = ''
        self.backup_tokens = []
        self.save()
    
    def verify_totp(self, token):
        """TOTP token-ի ստուգում"""
        if not self.two_factor_enabled or not self.two_factor_secret:
            return False
        
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(token, valid_window=1)
    
    def verify_backup_token(self, token):
        """Backup token-ի ստուգում"""
        if token in self.backup_tokens:
            self.backup_tokens.remove(token)
            self.save()
            return True
        return False
    
    def need_password_change(self, days=90):
        """Ստուգել արդյոք գաղտնաբառը պետք է փոխել"""
        if not self.last_password_change:
            return True
        return (timezone.now() - self.last_password_change).days > days

class UserSession(models.Model):
    """
    Օգտատերերի session-ների մոնիտորինգ
    """
    user = models.ForeignKey(CyberArattaUser, on_delete=models.CASCADE, verbose_name="Օգտատեր")
    session_key = models.CharField(max_length=40, unique=True, verbose_name="Session բանալի")
    ip_address = models.GenericIPAddressField(verbose_name="IP հասցե")
    user_agent = models.TextField(verbose_name="Browser տվյալներ")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստեղծման ժամանակ")
    last_activity = models.DateTimeField(auto_now=True, verbose_name="Վերջին ակտիվություն")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ է")
    
    class Meta:
        verbose_name = "Օգտատերի Session"
        verbose_name_plural = "Օգտատերի Sessions"
    
    def __str__(self):
        return f"{self.user.username} - {self.ip_address}"

class SecurityLog(models.Model):
    """
    Անվտանգության իրադարձությունների գրանցում
    """
    EVENT_TYPES = [
        ('login_success', 'Հաջողված մուտք'),
        ('login_failed', 'Ձախողված մուտք'),
        ('account_locked', 'Հաշիվը կողպված է'),
        ('password_changed', 'Գաղտնաբառ փոխված է'),
        ('2fa_enabled', '2FA միացված է'),
        ('2fa_disabled', '2FA անջատված է'),
        ('suspicious_activity', 'Կասկածելի գործունեություն'),
        ('session_hijack', 'Session hijacking փորձ'),
        ('brute_force', 'Brute force հարձակում'),
    ]
    
    user = models.ForeignKey(CyberArattaUser, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Օգտատեր")
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES, verbose_name="Իրադարձության տեսակ")
    ip_address = models.GenericIPAddressField(verbose_name="IP հասցե")
    user_agent = models.TextField(blank=True, verbose_name="Browser տվյալներ")
    details = models.JSONField(default=dict, verbose_name="Մանրամասներ")
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name="Ժամանակ")
    
    class Meta:
        verbose_name = "Անվտանգության գրառում"
        verbose_name_plural = "Անվտանգության գրառումներ"
        ordering = ['-timestamp']
    
    def __str__(self):
        user_str = self.user.username if self.user else "Anonymous"
        return f"{user_str} - {self.get_event_type_display()} - {self.timestamp}"
