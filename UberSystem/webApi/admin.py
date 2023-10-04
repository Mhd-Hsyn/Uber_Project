from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(SuperAdmin)
admin.site.register(SuperAdminWhitelistToken)
admin.site.register(Place)
admin.site.register(Admin)
admin.site.register(AdminWhitelistToken)
admin.site.register(VehicleCategory)
admin.site.register(Service)
admin.site.register(Cost)
admin.site.register(Captain)
admin.site.register(CaptainWhitelistToken)
admin.site.register(CaptainVehicle)
admin.site.register(VehicleImages)
admin.site.register(CaptainWallet)
admin.site.register(captainWalletTransaction)
admin.site.register(Customer)
admin.site.register(CustomerWhitelistToken)
admin.site.register(CustomerWallet)
admin.site.register(BookServices)
admin.site.register(BookServiceDetail)
admin.site.register(CustomerServiceHistory)
admin.site.register(CaptainServiceHistory)
admin.site.register(CompanyProfitHistory)

