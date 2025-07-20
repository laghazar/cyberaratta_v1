from django.db import models

class QuizCategory(models.Model):
    CATEGORY_TYPE_CHOICES = [
        ('school', 'Դպրոցական'),
        ('student', 'Ուսանող'),
        ('professional', 'Մասնագիտական'),
    ]
    PROFESSIONAL_FIELD_CHOICES = [
        ('gov', 'Պետական'),
        ('bank', 'Բանկային'),
        ('edu', 'Կրթական'),
        ('it', 'IT'),
        # ավելացրու ըստ անհրաժեշտության
    ]
    name = models.CharField(max_length=100)
    category_type = models.CharField(max_length=20, choices=CATEGORY_TYPE_CHOICES)
    professional_field = models.CharField(max_length=20, choices=PROFESSIONAL_FIELD_CHOICES, blank=True, null=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    def __str__(self):
        return self.name

class Question(models.Model):
    QUESTION_TYPES = [
        ('classic', 'Ուսուցողական Քուիզ'),
        ('millionaire', 'Միլիոնատեր'),
    ]
    question_text = models.TextField()
    question_type = models.CharField(max_length=20, choices=QUESTION_TYPES)
    category = models.ForeignKey(QuizCategory, on_delete=models.CASCADE)
    difficulty = models.IntegerField(default=1)
    points = models.IntegerField(default=10)
    image = models.ImageField(upload_to='questions/', blank=True, null=True)
    explanation = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    def __str__(self):
        return self.question_text

class Answer(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='answers')
    answer_text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)
    def __str__(self):
        return self.answer_text

class QuizSession(models.Model):
    session_key = models.CharField(max_length=64)
    category = models.ForeignKey(QuizCategory, on_delete=models.SET_NULL, null=True)
    question_type = models.CharField(max_length=20, choices=Question.QUESTION_TYPES)
    current_question = models.IntegerField(default=0)
    score = models.IntegerField(default=0)
    is_completed = models.BooleanField(default=False)
    started_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.session_key} - {self.category}"

class QuizResult(models.Model):
    CHARACTER_RESULT_CHOICES = [
        ('ara', 'Արա Գեղեցիկ'),
        ('shamiram', 'Շամիրամ'),
    ]
    session = models.OneToOneField(QuizSession, on_delete=models.CASCADE)
    final_score = models.IntegerField()
    percentage = models.FloatField()
    character_result = models.CharField(max_length=20, choices=CHARACTER_RESULT_CHOICES)
    feedback_message = models.TextField(blank=True)
    def get_character_result_display(self):
        return dict(self.CHARACTER_RESULT_CHOICES).get(self.character_result, "")
    def __str__(self):
        return f"{self.session} - {self.character_result}"

class QuizAttempt(models.Model):
    session = models.ForeignKey(QuizSession, on_delete=models.CASCADE)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    answer = models.ForeignKey(Answer, on_delete=models.SET_NULL, null=True, blank=True)
    is_correct = models.BooleanField(default=False)
    attempted_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.session} - {self.question} - {'Correct' if self.is_correct else 'Incorrect'}"