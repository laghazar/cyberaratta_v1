from django.urls import path
from . import views

app_name = 'reporting'

urlpatterns = [
    path('', views.report, name='report'),
]