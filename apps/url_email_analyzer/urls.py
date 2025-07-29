from django.urls import path
from . import views

app_name = 'url_email_analyzer'

urlpatterns = [
    path('', views.check_url, name='check_url'),  # Main URL for url_email_analyzer
    path('check/', views.check_url, name='check'),  # Alternative URL
]