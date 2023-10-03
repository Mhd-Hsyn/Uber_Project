from django.db import models
import uuid


# Create your models here.
class BaseModel(models.Model):
    id = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        primary_key=True,
        unique=True,
        null=False,
        blank=False,
    )
    created_at = models.DateTimeField(
        auto_now=False, auto_now_add=True, null=True, blank=True
    )
    updated_at = models.DateTimeField(
        auto_now=True, auto_now_add=False, null=True, blank=True
    )

    class Meta:
        abstract = True



class Admin(BaseModel):
    user_role = (
        ("super-admin", "super-admin"),
        ("country-admin", "country-admin"),
        ("city-admin", "city-admin"),
        ("branch-manager", "branch-manager")
    )

    fname = models.CharField(max_length=255, default="")
    lname = models.CharField(max_length=255, default="")
    email = models.EmailField(max_length=255, unique= True)
    username = models.CharField(max_length=255, unique= True)
    password = models.TextField(null= False)
    contact = models.CharField(max_length=20, default="")
    profile = models.ImageField(upload_to="Admin/", default="Admin/dummy.jpg")
    address = models.TextField(default="")
    country = models.CharField(max_length=50, default="")
    city = models.CharField(max_length=50, default="")
    cnic = models.IntegerField(default=0)
    Otp = models.IntegerField(default=0)
    OtpCount = models.IntegerField(default=0)
    OtpStatus = models.BooleanField(default=False)
    status = models.BooleanField(default=True)
    role = models.CharField(choices=user_role, max_length=10, default="super-admin")

    def __str__(self):
        return self.email


class AdminWhitelistToken(models.Model):
    admin = models.ForeignKey(Admin, on_delete=models.CASCADE, blank= True, null= True)
    token = models.TextField(default="")
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True, auto_now=False)

    def __str__(self) :
        return str(self.token)


class Area(BaseModel):
    country = models.CharField( max_length=50, default="")
    city = models.CharField( max_length=50, default="")

    def __str__(self) -> str:
        return str(self.city)


class VehicleCategory(BaseModel):
    title = models.CharField(max_length=50, default="")
    description = models.CharField( max_length=50, default="")
    engine = models.TextField(default="")
    area = models.ForeignKey(Area, on_delete=models.CASCADE, blank= True, null= True)

    def __str__(self):
        return str(self.title)

class Service(BaseModel):
    title = models.CharField( max_length=50, default="")
    description = models.CharField(max_length=50, default="")

    def __str__(self):
        return str(self.title)

class ServiceDetail(BaseModel):
    title = models.CharField(max_length=50, default="")
    city_to_city = models.BooleanField(default= False)
    vehicle_category = models.ForeignKey(VehicleCategory, on_delete=models.CASCADE, blank= True, null= True)
    service = models.ForeignKey(Service, on_delete=models.CASCADE, blank= True, null= True)

    def __str__(self) -> str:
        return str(self.title)

class Cost(BaseModel):
    title = models.CharField(max_length=50, default="")
    initial_cost = models.CharField( max_length=50, default="")
    price_per_km = models.CharField( max_length=50, default="")
    waiting_cost = models.CharField( max_length=50, default="")
    profit_percentage = models.CharField( max_length=50, default="")
    service_detail = models.ForeignKey(ServiceDetail, on_delete=models.CASCADE, blank= True, null= True)
    
    def __str__(self) -> str:
        return str(self.title)

# Captain side 
class Captain(BaseModel):
    fname = models.CharField(max_length=255, default="")
    lname = models.CharField(max_length=255, default="")
    email = models.EmailField(max_length=255, unique= True)
    username = models.CharField(max_length=255, unique= True)
    password = models.TextField(null= False)
    contact = models.CharField(max_length=20, default="", unique= True)
    profile = models.ImageField(upload_to="Captain/Profile", default="")
    address = models.TextField(default="")
    cnic = models.IntegerField(default=0)
    cnic_front_image = models.ImageField(upload_to="Captain/Cnic/", default="")
    cnic_back_image = models.ImageField(upload_to="Captain/Cnic/", default="")
    Otp = models.IntegerField(default=0)
    OtpCount = models.IntegerField(default=0)
    OtpStatus = models.BooleanField(default=False)
    no_of_attempts_allowed = models.IntegerField(default=3)
    no_of_wrong_attempts = models.IntegerField(default=0)
    status = models.BooleanField(default=False)
    area = models.ForeignKey(Area, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self) -> str:
        return str(self.email)
    
    
class CaptainWhitelistToken(models.Model):
    captain = models.ForeignKey(Captain, on_delete=models.CASCADE, blank= True, null= True)
    token = models.TextField(default="")
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True, auto_now=False)

    def __str__(self) :
        return str(self.token)

class CaptainVehicle(BaseModel):
    vehicle_number = models.CharField( max_length=50, default="")
    numberplate_image = models.ImageField(upload_to="Captain/Vehicle/Numberplate/", default="")
    vehicle_document_image = models.ImageField( upload_to="Captain/Vehicle/Document/", default="")
    license_number = models.CharField(max_length=50, default="")
    license_front_image = models.ImageField( upload_to="Captain/License/", default="")
    license_back_image = models.ImageField( upload_to="Captain/License/", default="")
    approval_status = models.BooleanField(default=False)
    approval_message = models.CharField( max_length=50, default="")
    captain = models.ForeignKey(Captain, on_delete=models.CASCADE, blank=True, null=True)
    vehicle_category = models.ForeignKey(VehicleCategory, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self) -> str:
        return str(self.vehicle_number)

class VehicleImages(BaseModel):
    captain_vehicle =  models.ForeignKey(CaptainVehicle, on_delete=models.CASCADE, blank=True, null=True)
    image = models.ImageField( upload_to="Captain/Vehicle/Image/", default="")

class CaptainLocation(BaseModel):
    online_status = models.BooleanField(default=False)
    latitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    longitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    captain = models.ForeignKey(Captain, on_delete=models.CASCADE, blank=True, null=True)

class CaptainWallet(BaseModel):
    amount = models.DecimalField( max_digits=5, decimal_places=2, default=0.0)
    wallet_status = models.BooleanField(default=False)
    captain = models.ForeignKey(Captain, on_delete=models.CASCADE, blank=True, null=True)

class captainWalletHistory(BaseModel):
    payment_choice = (
        ("paypal", "paypal"),
        ("card", "card")
    )
    payment_type = models.CharField( max_length=50, choices= payment_choice, default="")
    payment_amount = models.DecimalField( max_digits=5, decimal_places=2, default=0.0)
    captain_wallet = models.ForeignKey(CaptainWallet, on_delete=models.CASCADE, blank=True, null=True)


# Customer Side

class Customer(BaseModel):
    fname = models.CharField(max_length=255, default="")
    lname = models.CharField(max_length=255, default="")
    email = models.EmailField(max_length=255, unique= True)
    username = models.CharField(max_length=255, unique= True)
    password = models.TextField(null= True)
    contact = models.CharField(max_length=20, default="", unique= True)
    profile = models.ImageField(upload_to="Customer/Profile", default="")
    address = models.TextField(default="")
    Otp = models.IntegerField(default=0)
    OtpCount = models.IntegerField(default=0)
    OtpStatus = models.BooleanField(default=False)
    no_of_attempts_allowed = models.IntegerField(default=3)
    no_of_wrong_attempts = models.IntegerField(default=0)
    status = models.BooleanField(default=True)

    def __str__(self) -> str:
        return str(self.email)


class CustomerWhitelistToken(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, blank= True, null= True)
    token = models.TextField(default="")
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True, auto_now=False)

    def __str__(self) :
        return str(self.token)

class CustomerLocation(BaseModel):
    online_status = models.BooleanField(default=False)
    latitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    longitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, blank=True, null=True)


class BookService(BaseModel):
    status_choice = (
        ("searching-captain", "searching-captain"),
        ("captain-arrived", "captain-arrived"),
        ("start-service", "start-service"),
        ("end-service","end-service")
    )
    start_service_datetime = models.DateTimeField(auto_now=False, auto_now_add=False, blank=True, null= True)
    start_service_latitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    start_service_longitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    end_service_datetime = models.DateTimeField(auto_now=False, auto_now_add=False, blank=True, null= True)
    end_service_latitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    end_service_longitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    city_to_city = models.BooleanField(default=False)
    total_distance = models.DecimalField( max_digits=5, decimal_places=2, default=0.0)
    total_time = models.DateTimeField( auto_now=False, auto_now_add=False,blank= True, null= True)
    waiting_time = models.DateTimeField(auto_now=False, auto_now_add=False, blank= True, null= True)
    estimate_cost = models.DecimalField( max_digits=5, decimal_places=2, default= 0.0)
    total_cost = models.DecimalField( max_digits=5, decimal_places=2, default=0.0)
    ride_status = models.CharField( max_length=50, choices= "", default="")
    customer =  models.ForeignKey(Customer, on_delete=models.CASCADE, blank=True, null=True)
    captain_vehicle =  models.ForeignKey(CaptainVehicle, on_delete=models.CASCADE, blank=True, null=True)
    service_detail =  models.ForeignKey(ServiceDetail, on_delete=models.CASCADE, blank=True, null=True)
    captain_location =  models.ForeignKey(CaptainLocation, on_delete=models.CASCADE, blank=True, null=True)
    customer_location =  models.ForeignKey(CustomerLocation, on_delete=models.CASCADE, blank=True, null=True)
    cost =  models.ForeignKey(Cost, on_delete=models.CASCADE, blank=True, null=True)
    status = models.CharField( max_length=50, choices= status_choice, default="")

class ServicePayment(BaseModel):
    payment_choice = (
        ("paypal", "paypal"),
        ("card", "card")
    )
    payment_type = models.CharField( max_length=50, choices= payment_choice, default="")
    payment_amount = models.DecimalField( max_digits=5, decimal_places=2, default=0.0)
    status = models.BooleanField(default= False)
    book_service = models.ForeignKey(BookService, on_delete=models.CASCADE, blank=True, null=True)

class CourierDetail (BaseModel):
    title = models.CharField( max_length=50, default="")
    desription = models.CharField( max_length=50, default="")
    sender_name = models.CharField( max_length=50, default="")
    sender_address = models.CharField( max_length=50, default="")
    sender_contact = models.CharField( max_length=50, default="")
    receiver_name = models.CharField( max_length=50, default="")
    receiver_address = models.CharField( max_length=50, default="")
    receiver_contact = models.CharField( max_length=50, default="")
    courier_value = models.IntegerField(default=0)
    book_service = models.ForeignKey(BookService, on_delete=models.CASCADE, blank=True, null=True)

class ShoppingDetail(BaseModel):
    title = models.CharField( max_length=50, default="")
    desription = models.CharField( max_length=50, default="")
    shop_name = models.CharField( max_length=50, default="")
    shop_latitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    shop_langitude = models.DecimalField(max_digits=11, decimal_places=8, default=0.0)
    item= models.TextField(default="")
    item_description=models.TextField(default="")
    estimate_price = models.IntegerField(default= 0)
    book_service = models.ForeignKey(BookService, on_delete=models.CASCADE, blank=True, null=True)


#  Captain History
class CaptainServiceHistory(BaseModel):
    total_amount = models.DecimalField( max_digits=5, decimal_places=2, default= 0.0)
    captain_profit = models.DecimalField( max_digits=5, decimal_places=2, default= 0.0)
    company_charges = models.DecimalField( max_digits=5, decimal_places=2, default= 0.0)
    wallet_before = models.DecimalField( max_digits=5, decimal_places=2, default= 0.0)
    wallet_after = models.DecimalField( max_digits=5, decimal_places=2, default= 0.0)
    book_service = models.ForeignKey(BookService, on_delete=models.CASCADE, blank=True, null=True)
    service_payment = models.ForeignKey(ServicePayment, on_delete=models.CASCADE, blank=True, null=True)
    captain_wallet = models.ForeignKey(CaptainWallet, on_delete=models.CASCADE, blank=True, null=True)

class CompanyProfitHistory(BaseModel):
    profit_amount = models.DecimalField(max_digits=5, decimal_places=2, default=0.0)
    profit_percentage = models.DecimalField( max_digits=5, decimal_places=2, default=0.0)
    captain_service_history = models.ForeignKey(CaptainServiceHistory, on_delete=models.CASCADE, blank=True, null=True)
    area = models.ForeignKey(Area, on_delete=models.CASCADE, blank=True, null=True)
