from django.urls import path
from . import views

app_name = 'threat_map'

urlpatterns = [
    path('map/', views.threat_map, name='map'),  # URL pattern for threat_map:map
]