from django.urls import path
from . import views

app_name = 'url_checker'

urlpatterns = [
    path('check/', views.check_url, name='check_url'),  # URL pattern for url_checker:check
]