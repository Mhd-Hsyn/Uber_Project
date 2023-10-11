from rest_framework import serializers
from passlib.hash import django_pbkdf2_sha256 as handler

from .models import *
from Usable import useable as uc 
import uuid

class SuperAdminLoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = SuperAdmin
        fields = ["email", "password"]

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        fetch_user = SuperAdmin.objects.filter(email=email).first()
        if not fetch_user:
            raise serializers.ValidationError("Email not found . . .")
        check_pass = handler.verify(password, fetch_user.password)
        if not check_pass:
            raise serializers.ValidationError("Wrong Password !!!")
        attrs["fetch_user"] = fetch_user
        return attrs

class GetCitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Place
        fields = ['id', 'country', 'city']

class AddCitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Place
        fields = "__all__"

    def validate(self, attrs):
        country = attrs['country']
        city = attrs['city']
        if Place.objects.filter(country = country.lower(), city = city.lower()).filter():
            raise serializers.ValidationError(f"city {city} already exist in country {country}")
        return attrs
    def create(self, validated_data):
        validated_data['city'] = validated_data['city'].lower()
        validated_data['country'] = validated_data['country'].lower()
        return super().create(validated_data)

class AddStaffSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ['fname', 'lname','email' ,'contact', 'address', 'password', 'city', 'role']
    
    def validate_email(self, value):
        if not uc.checkEmailPattern(value):
            raise serializers.ValidationError("Wrong email pattern")
        if Admin.objects.filter(email = value).first():
            raise serializers.ValidationError(f"{value} This email already exists ")
        return value
    
    def validate_password(self, value):
        if not uc.checkpasslen(value):
            raise serializers.ValidationError("Password Length must be greater than 8")
        return value

    def validate_role(self, role):
        city_id = self.context['city_id']
        fetch_city = Place.objects.filter(id=city_id).first()
        if role == "city-admin":
            if Admin.objects.filter(role=role, city=fetch_city).exists():
                raise serializers.ValidationError(f"City Admin for {fetch_city.city}, {fetch_city.country} already exists")
        return role

    def create(self, validated_data):
        validated_data['password'] = handler.hash(validated_data['password'])
        return super().create(validated_data)

class GetStaffByCitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ['id','role','email' , 'contact', 'profile', 'address', 'created_at', 'updated_at']

class AddVehicleCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = VehicleCategory
        fields = '__all__'

    def validate(self, attrs):
        city_id = self.context
        fetch_city = Place.objects.filter(id = city_id).first()
        if not fetch_city:
            raise serializers.ValidationError("City id not exist")
        title = attrs['title'].lower()
        if VehicleCategory.objects.filter(title = title, city = fetch_city).exists():
            raise serializers.ValidationError(f"{title} this vehicle category exists in {fetch_city.city}")
        data = {"city": fetch_city, "title" : title, "description": attrs['description'].lower() }
        return data
    
    def create(self, validated_data):
        return super().create(validated_data)

class GetVehicleCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = VehicleCategory
        fields = ['id','title', 'description']

class EditVehicleCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = VehicleCategory
        fields = '__all__'
    
    def update(self, instance, validated_data):
        city_id = self.context['city_id']
        title = validated_data['title'].lower()
        fetch_city = Place.objects.filter(id = city_id).first()
        # Make sure the instance exists before trying to update
        if not instance:
            raise serializers.ValidationError("Invalid instance for update.")

        if not fetch_city:
            raise serializers.ValidationError("Invalid city ID .")
        if VehicleCategory.objects.filter(city = fetch_city, title=title).exists():
            raise serializers.ValidationError(f"{title} category exists in {fetch_city.city} City")
        
        instance.city = fetch_city
        instance.title = validated_data.get('title', instance.title).lower()
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        return instance

class AddServicesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = '__all__'
    
    def validate_title(self, val):
        title = val.lower()
        vehicle_cat_id = self.context
        fetch_cat = VehicleCategory.objects.filter(id = vehicle_cat_id).first()
        if not fetch_cat:
            raise serializers.ValidationError("Vehicle category id not exist")
        if Service.objects.filter(vehicle_category = fetch_cat, title = title).exists():
            raise serializers.ValidationError(f"{title} Service exist on {fetch_cat.title} Category in {fetch_cat.city.city} City")
        
        # return {"title":title, "fetch_cat": fetch_cat}
        return title,  fetch_cat

    
    def create(self, validated_data):
        title =  validated_data['title'][0]
        fetch_cat = validated_data['title'][1]
        description = validated_data['description']

        return Service.objects.create(vehicle_category = fetch_cat, title = title, description = description)


class EditServiceSerializer(serializers.ModelSerializer):
    class Meta :
        model = Service
        fields = ['id', 'title', 'description', 'vehicle_category']
    
    def validate_title(self, value):
        title = value.lower()
        if not self.instance:
            raise serializers.ValidationError("Service not found !")
        
        check_services =  Service.objects.filter(vehicle_category = self.instance.vehicle_category , title = title).first()
        if check_services:
            raise serializers.ValidationError(f"{title} Service already exists in {check_services.vehicle_category}")
        
        return title

    def update(self, instance, validated_data):
        instance.title = validated_data['title'].lower() 
        instance.description = validated_data['description']
        instance.save()
        return instance

class AddCostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cost
        exclude = ['created_at', 'updated_at']
    
    def validate_service(self, value):
        fetch_cost= Cost.objects.filter(service = value).first()
        if fetch_cost:
            raise serializers.ValidationError(f"Cost for {fetch_cost.service.title} Service in {fetch_cost.service.vehicle_category.title} Category in {fetch_cost.service.vehicle_category.city.city} City already exists ")
        return value

class EditCostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cost
        fields = ['id', 'initial_cost', 'price_per_km', 'waiting_cost', 'profit_percentage']
    
    def validate(self, attrs):
        for key, value in attrs.items():
            if int(value) == 0 :
                raise serializers.ValidationError(f"{key} should not be 0")
        return super().validate(attrs)
    
    def update(self, instance, validated_data):
        if not instance:
            raise serializers.ValidationError("instance not available")
        instance.initial_cost = validated_data['initial_cost']
        instance.price_per_km = validated_data['price_per_km']
        instance.waiting_cost = validated_data['waiting_cost']
        instance.profit_percentage = validated_data['profit_percentage']
        instance.save()
        return instance 
    


######################################################################################

#     ````````````````````````````````   City Admin and Branch Admin  ````````````````````````````


class AdminLoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = Admin
        fields = ["email", "password"]

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        fetch_user = Admin.objects.filter(email=email).first()
        if not fetch_user:
            raise serializers.ValidationError("Email not found . . .")
        check_pass = handler.verify(password, fetch_user.password)
        if not check_pass:
            raise serializers.ValidationError("Wrong Password !!!")
        attrs["fetch_user"] = fetch_user
        return attrs
