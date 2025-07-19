from django.urls import path
from . import views

app_name = 'threat_map'

urlpatterns = [
    path('', views.threat_map, name='map'),
]