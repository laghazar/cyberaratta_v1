from django.urls import path
from django.http import JsonResponse

def api_status(request):
    return JsonResponse({"status": "ok"})

urlpatterns = [
    path('status/', api_status),
]
#test