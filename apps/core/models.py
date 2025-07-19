from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class SiteStatistics(models.Model):
    """Կայքի ընդհանուր վիճակագրություն"""
    total_reports = models.IntegerField(default=0, verbose_name="Ընդհանուր զեկուցումներ")
    monthly_reports = models.IntegerField(default=0, verbose_name="Ամսվա զեկուցումներ")
    total_quizzes = models.IntegerField(default=0, verbose_name="Ընդհանուր քուիզներ")
    total_url_checks = models.IntegerField(default=0, verbose_name="URL ստուգումներ")
    last_updated = models.DateTimeField(auto_now=True, verbose_name="Վերջին թարմացում")
    
    class Meta:
        verbose_name = "Կայքի վիճակագրություն"
        verbose_name_plural = "Կայքի վիճակագրություններ"
    
    def __str__(self):
        return f"Վիճակագրություն - {self.last_updated.date()}"

class Character(models.Model):
    """Կերպարներ - Արա Գեղեցիկ և Շամիրամ"""
    CHARACTER_TYPES = [
        ('ara', 'Արա Գեղեցիկ'),
        ('shamiram', 'Շամիրամ'),
    ]
    
    name = models.CharField(max_length=50, verbose_name="Անուն")
    character_type = models.CharField(max_length=20, choices=CHARACTER_TYPES, verbose_name="Կերպարի տեսակ")
    description = models.TextField(verbose_name="Նկարագրություն")
    image = models.ImageField(upload_to='characters/', verbose_name="Նկար")
    is_positive = models.BooleanField(default=True, verbose_name="Դրական կերպար")
    
    class Meta:
        verbose_name = "Կերպար"
        verbose_name_plural = "Կերպարներ"
    
    def __str__(self):
        return self.name