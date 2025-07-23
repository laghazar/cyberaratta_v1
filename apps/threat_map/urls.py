from django.urls import path
from . import views

app_name = 'threat_map'

urlpatterns = [
    path('', views.threat_map_view, name='threat_map'),
    path('check-url/', views.check_url_status, name='check_url'),
    path('api/threats/', views.threat_data_api, name='threat_data_api'),
    path('api/stats/', views.stats_api, name='stats_api'),
    path('api/phishing-urls/', views.phishing_urls_api, name='phishing_urls_api'),
    path('api/check-url/', views.check_url_api, name='check_url_api'),
]