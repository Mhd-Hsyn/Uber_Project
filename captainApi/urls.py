from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

# Create a router for the viewset
router = DefaultRouter()
router.register(r"auth", CaptionAuthViewset, basename="auth")
router.register(r"api", captain_Api, basename="api")


urlpatterns = [
    path("captain/", include(router.urls)),
]
