from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.core.urls')),
    path('quiz/', include('apps.quiz.urls')),
    path('check/', include('apps.url_checker.urls')),
    path('report/', include('apps.reporting.urls')),
    path('map/', include('apps.threat_map.urls')),
    path('api/', include('apps.core.api_urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

admin.site.site_header = "CyberAratta Ադմինիստրացիա"
admin.site.site_title = "CyberAratta Admin"
admin.site.index_title = "Կառավարման Համակարգ"


