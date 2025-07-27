from django.urls import path
from . import views

app_name = 'reporting'

urlpatterns = [
    path('', views.phishing_report_view, name='index'),  # Root reporting page
    path('report/', views.phishing_report_view, name='report'),
    path('dashboard/', views.reports_dashboard, name='dashboard'),
    path('ajax/platform-search/', views.platform_search_ajax, name='platform_search_ajax'),
    path('api/damage-types/', views.damage_types_api, name='damage_types_api'),
]