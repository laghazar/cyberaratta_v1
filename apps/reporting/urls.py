from django.urls import path
from . import views

app_name = 'reporting'

urlpatterns = [
    path('report/', views.phishing_report_view, name='report'),  # Փոխել views.PhishingReport-ը views.phishing_report_view-ի
]