from django.urls import path
from . import views

app_name = 'reporting'

urlpatterns = [
    path('report/', views.phishing_report_view, name='report'),
    path('dashboard/', views.reports_dashboard, name='dashboard'),
]