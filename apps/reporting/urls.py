from django.urls import path
from . import views

app_name = 'reporting'

urlpatterns = [
    path('report/', views.PhishingReport, name='report'),  # Փոխել views.report-ը views.PhishingReport-ի
]