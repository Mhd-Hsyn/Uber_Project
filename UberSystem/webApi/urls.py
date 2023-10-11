from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *

# Create a router for the viewset
router_superadmin = DefaultRouter()
router_superadmin.register(r"auth", SuperAdminAuthViewset, basename="auth")
router_superadmin.register(r"api", SuperAdminApi, basename="api")

router_staff = DefaultRouter()
router_staff.register(r"auth", StaffAuthViewset, basename="auths")
router_staff.register(r"api", StaffApi, basename="api")


urlpatterns = [
    path('hashpass/', view= encryptpass.as_view()),
    path("superadmin/", include(router_superadmin.urls)),
    path('staff/', include(router_staff.urls)),
    
]
