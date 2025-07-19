from django.db import models

class Threat(models.Model):
    """Կիբեռսպառնալիքի մոդել"""
    TYPE_CHOICES = [
        ('phishing', 'Ֆիշինգ'),
        ('malware', 'Վնասակար ծրագիր'),
        ('ddos', 'DDoS հարձակում'),
        ('other', 'Այլ'),
    ]

    type = models.CharField(max_length=20, choices=TYPE_CHOICES, verbose_name="Տեսակ")
    source_country = models.CharField(max_length=100, blank=True, verbose_name="Աղբյուրի երկիր")
    reported_at = models.DateTimeField(auto_now_add=True, verbose_name="Հայտնաբերման ժամանակ")
    description = models.TextField(blank=True, verbose_name="Նկարագրություն")

    class Meta:
        verbose_name = "Սպառնալիք"
        verbose_name_plural = "Սպառնալիքներ"

    def __str__(self):
        return f"{self.get_type_display()} - {self.source_country}"