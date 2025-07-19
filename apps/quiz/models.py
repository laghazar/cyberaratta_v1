from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator

class QuizCategory(models.Model):
    """Քուիզի կատեգորիաներ"""
    CATEGORY_TYPES = [
        ('school', 'Դպրոցական'),
        ('student', 'Ուսանող'),
        ('professional', 'Մասնագիտական'),
    ]
    
    PROFESSIONAL_FIELDS = [
        ('government', 'Պետական'),
        ('banking', 'Բանկային/Ֆինանսներ'),
        ('education', 'Կրթություն'),
        ('healthcare', 'Առողջապահություն'),
        ('it', 'Տեղեկատվական տեխնոլոգիաներ'),
        ('other', 'Այլ'),
    ]
    
    name = models.CharField(max_length=100, verbose_name="Անվանում")
    category_type = models.CharField(max_length=20, choices=CATEGORY_TYPES, verbose_name="Կատեգորիա")
    professional_field = models.CharField(max_length=20, choices=PROFESSIONAL_FIELDS, blank=True, null=True, verbose_name="Մասնագիտական ոլորտ")
    description = models.TextField(blank=True, verbose_name="Նկարագրություն")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ")
    
    class Meta:
        verbose_name = "Քուիզի կատեգորիա"
        verbose_name_plural = "Քուիզի կատեգորիաներ"
    
    def __str__(self):
        if self.professional_field:
            return f"{self.name} - {self.get_professional_field_display()}"
        return self.name

class Question(models.Model):
    """Հարցեր"""
    QUESTION_TYPES = [
        ('phishing_detection', 'Ֆիշինգ է թե ոչ'),
        ('educational', 'Ուսուցողական'),
        ('millionaire', 'Միլիոնատեր'),
    ]
    
    DIFFICULTY_LEVELS = [
        ('easy', 'Հեշտ'),
        ('medium', 'Միջին'),
        ('hard', 'Դժվար'),
    ]
    
    question_text = models.TextField(verbose_name="Հարցի տեքստ")
    question_type = models.CharField(max_length=20, choices=QUESTION_TYPES, verbose_name="Հարցի տեսակ")
    category = models.ForeignKey(QuizCategory, on_delete=models.CASCADE, verbose_name="Կատեգորիա")
    difficulty = models.CharField(max_length=10, choices=DIFFICULTY_LEVELS, default='medium', verbose_name="Բարդություն")
    image = models.ImageField(upload_to='questions/', blank=True, null=True, verbose_name="Նկար")
    explanation = models.TextField(blank=True, verbose_name="Բացատրություն")
    points = models.IntegerField(default=10, validators=[MinValueValidator(1), MaxValueValidator(100)], verbose_name="Միավորներ")
    is_active = models.BooleanField(default=True, verbose_name="Ակտիվ")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ստեղծված")
    
    class Meta:
        verbose_name = "Հարց"
        verbose_name_plural = "Հարցեր"
        ordering = ['question_type', 'difficulty', 'created_at']
    
    def __str__(self):
        return f"{self.get_question_type_display()} - {self.question_text[:50]}..."

class Answer(models.Model):
    """Պատասխաններ"""
    question = models.ForeignKey(Question, related_name='answers', on_delete=models.CASCADE, verbose_name="Հարց")
    answer_text = models.CharField(max_length=200, verbose_name="Պատասխանի տեքստ")
    is_correct = models.BooleanField(default=False, verbose_name="Ճիշտ պատասխան")
    
    class Meta:
        verbose_name = "Պատասխան"
        verbose_name_plural = "Պատասխաններ"
    
    def __str__(self):
        return f"{self.question.question_text[:30]}... - {self.answer_text}"

class QuizSession(models.Model):
    """Քուիզի սեսիա"""
    session_key = models.CharField(max_length=100, unique=True, verbose_name="Սեսիայի բանալի")
    category = models.ForeignKey(QuizCategory, on_delete=models.CASCADE, verbose_name="Կատեգորիա")
    question_type = models.CharField(max_length=20, choices=Question.QUESTION_TYPES, verbose_name="Հարցի տեսակ")
    current_question = models.IntegerField(default=0, verbose_name="Ընթացիկ հարց")
    total_questions = models.IntegerField(default=10, verbose_name="Ընդհանուր հարցեր")
    score = models.IntegerField(default=0, verbose_name="Միավորներ")
    is_completed = models.BooleanField(default=False, verbose_name="Ավարտված")
    started_at = models.DateTimeField(auto_now_add=True, verbose_name="Սկսվել է")
    completed_at = models.DateTimeField(blank=True, null=True, verbose_name="Ավարտվել է")
    
    class Meta:
        verbose_name = "Քուիզի սեսիա"
        verbose_name_plural = "Քուիզի սեսիաներ"

class QuizResult(models.Model):
    """Քուիզի արդյունք"""
    session = models.OneToOneField(QuizSession, on_delete=models.CASCADE, verbose_name="Սեսիա")
    final_score = models.IntegerField(verbose_name="Վերջնական միավոր")
    percentage = models.FloatField(verbose_name="Տոկոսային արդյունք")
    character_result = models.CharField(max_length=20, choices=[('ara', 'Արա Գեղեցիկ'), ('shamiram', 'Շամիրամ')], verbose_name="Կերպարային արդյունք")
    feedback_message = models.TextField(verbose_name="Արձագանքի հաղորդագրություն")
    
    class Meta:
        verbose_name = "Քուիզի արդյունք"
        verbose_name_plural = "Քուիզի արդյունքներ"