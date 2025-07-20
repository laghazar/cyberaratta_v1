from django.urls import path
from . import views

app_name = 'quiz'

urlpatterns = [
    path('', views.quiz_home, name='home'),
    path('start/', views.start_quiz, name='start_quiz'),
    path('question/<int:session_id>/', views.quiz_question, name='quiz_question'),
    path('submit/<int:session_id>/', views.submit_answer, name='submit_answer'),
    path('result/<int:session_id>/', views.quiz_result, name='quiz_result'),
]
