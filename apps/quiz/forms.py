from django import forms
from .models import Question, QuizCategory

class QuizStartForm(forms.Form):
    category = forms.ModelChoiceField(queryset=QuizCategory.objects.filter(is_active=True), label="Կատեգորիա")
    question_type = forms.ChoiceField(choices=Question.QUESTION_TYPES, label="Հարցի տեսակ")