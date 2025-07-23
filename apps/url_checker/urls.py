from django.urls import path
from . import views

app_name = 'url_checker'

urlpatterns = [
    path('', views.check_url, name='check_url'),  # Main URL for url_checker
    path('check/', views.check_url, name='check'),  # Alternative URL
]