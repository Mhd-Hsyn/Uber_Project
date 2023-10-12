from rest_framework import serializers
from passlib.hash import django_pbkdf2_sha256 as handler
from webApi.models import *
from Usable import useable as uc 
from django.contrib.auth.hashers import make_password


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ['fname', 'lname', 'email', 'password', 'contact', 'address']

    def validate(self, data):
        requireFields = ['fname', 'lname', 'email', 'password', 'contact']

        validator = uc.requireFeildValidation(data, requireFields) 

        if not validator:
            raise serializers.ValidationError({"error": validator["message"]})  # Change "requireFields" to "message"

        # Email validation
        if not uc.checkEmailPattern(data["email"]):
            raise serializers.ValidationError({"error": "Email is not valid"})

        return data



    def validate_email(self, value):
        if not uc.checkEmailPattern(value):
            raise serializers.ValidationError("Email Format Is Incorrect")
        return value

    def validate_password(self, value):
        if not uc.validate_password(value):
            raise serializers.ValidationError("Password must contain at least one special character and one uppercase letter, and be between 8 and 20 characters long")
        return make_password(value) 

    def validate_contact(self, contact):
        existing_customer = Customer.objects.filter(contact=contact).first()
        if existing_customer:
            raise serializers.ValidationError("This contact number is already in use by another user.")
        
        return contact
 
 

class CustomerLoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = Customer
        fields = ["email", "password"]

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        fetch_user = Customer.objects.filter(email=email).first()
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