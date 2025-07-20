from django.db import models

class URLCheck(models.Model):
    """URL/Էլ. փոստի ստուգման մոդել"""
    STATUS_CHOICES = [
        ('safe', 'Անվտանգ'),
        ('suspicious', 'Կասկածելի'),
        ('malicious', 'Վտանգավոր'),
        ('pending', 'Սպասում է ձեռքով մշակման'),
    ]

    input_text = models.CharField(max_length=500, verbose_name="URL կամ Էլ. փոստ")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name="Կարգավիճակ")
    source = models.CharField(max_length=100, blank=True, verbose_name="Աղբյուր")
    analysis_result = models.TextField(blank=True, verbose_name="Վերլուծության արդյունք")
    checked_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստուգման ժամանակ")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Թարմացման ժամանակ")

    class Meta:
        verbose_name = "URL ստուգում"
        verbose_name_plural = "URL ստուգումներ"

    def __str__(self):
        return f"{self.input_text} - {self.get_status_display()}"


class UrlCheckResult(models.Model):
    url_check = models.ForeignKey(URLCheck, on_delete=models.CASCADE, related_name='results')
    virustotal_result = models.JSONField(null=True, blank=True, verbose_name="VirusTotal արդյունք")
    kaspersky_result = models.JSONField(null=True, blank=True, verbose_name="Kaspersky արդյունք")
    checked_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստուգման ժամանակ")

    class Meta:
        verbose_name = "URL ստուգման արդյունք"
        verbose_name_plural = "URL ստուգման արդյունքներ"

    def __str__(self):
        return f"Արդյունքներ {self.url_check.input_text} համար՝ {self.checked_at}"
