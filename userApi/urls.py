from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

# Create a router for the viewset
router = DefaultRouter()
router.register(r"auth", CustomerAuthViewset, basename="auth")
router.register(r"api", CustomerApi, basename="api")


urlpatterns = [
    path("Customer/", include(router.urls)),
]
