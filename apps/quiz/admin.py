from django.contrib import admin
from .models import QuizCategory, Question, Answer, QuizSession, QuizResult

@admin.register(QuizCategory)
class QuizCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'category_type', 'professional_field', 'is_active']
    list_filter = ['category_type', 'professional_field', 'is_active']
    search_fields = ['name', 'description']

class AnswerInline(admin.TabularInline):
    model = Answer
    extra = 4
    max_num = 4

@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ['question_text_short', 'question_type', 'category', 'difficulty', 'points', 'is_active']
    list_filter = ['question_type', 'category', 'difficulty', 'is_active']
    search_fields = ['question_text']
    inlines = [AnswerInline]
    
    def question_text_short(self, obj):
        return obj.question_text[:50] + "..." if len(obj.question_text) > 50 else obj.question_text
    question_text_short.short_description = 'Հարցի տեքստ'

@admin.register(QuizSession)
class QuizSessionAdmin(admin.ModelAdmin):
    list_display = ['session_key', 'category', 'question_type', 'score', 'is_completed', 'started_at']
    list_filter = ['category', 'question_type', 'is_completed']

@admin.register(QuizResult)
class QuizResultAdmin(admin.ModelAdmin):
    list_display = ['session', 'final_score', 'percentage', 'character_result']
    list_filter = ['character_result']
    
    