from django.urls import path
from . import views
# Import demo APIs
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from demo_api_views import (
    live_demo_stats_api, demo_threat_feed_api, demo_quiz_stats_api,
    demo_url_checker_stats_api, demo_reporting_stats_api
)

app_name = 'threat_map'

urlpatterns = [
    path('', views.unified_threat_map_view, name='threat_map'),
    path('old/', views.threat_map_view, name='old_threat_map'),
    path('check-url/', views.check_url_status, name='check_url'),
    path('api/threats/', views.threat_data_api, name='threat_data_api'),
    path('api/stats/', views.stats_api, name='stats_api'),
    path('api/phishing-urls/', views.phishing_urls_api, name='phishing_urls_api'),
    path('api/check-url/', views.check_url_api, name='check_url_api'),
    path('api/live-threats/', views.live_threats_api, name='live_threats_api'),
    path('api/site-statistics/', views.site_statistics_api, name='site_statistics_api'),
    
    # Demo APIs for presentation
    path('api/demo/stats/', live_demo_stats_api, name='demo_stats'),
    path('api/demo/threats/', demo_threat_feed_api, name='demo_threats'),
    path('api/demo/quiz/', demo_quiz_stats_api, name='demo_quiz'),
    path('api/demo/url-email-analyzer/', demo_url_checker_stats_api, name='demo_url_email_analyzer'),
    path('api/demo/reporting/', demo_reporting_stats_api, name='demo_reporting'),
]