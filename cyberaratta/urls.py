from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.core.urls')),  # Core app for homepage
    path('quiz/', include('apps.quiz.urls', namespace='quiz')),  # Quiz app
    path('url_checker/', include('apps.url_checker.urls', namespace='url_checker')),  # URL Checker app
    path('reporting/', include('apps.reporting.urls', namespace='reporting')),  # Reporting app
    path('threat_map/', include('apps.threat_map.urls', namespace='threat_map')),  # Threat Map app
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

admin.site.site_header = "CyberAratta Ադմինիստրացիա"
admin.site.site_title = "CyberAratta Admin"
admin.site.index_title = "Կառավարման Համակարգ"


