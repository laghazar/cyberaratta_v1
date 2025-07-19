from django.urls import path
from . import views

app_name = 'url_checker'

urlpatterns = [
    path('', views.check_url, name='check_url'),
]