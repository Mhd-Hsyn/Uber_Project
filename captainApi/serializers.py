from rest_framework import serializers
from passlib.hash import django_pbkdf2_sha256 as handler
from webApi.models import *
from Usable import useable as uc 
from django.contrib.auth.hashers import make_password


class CaptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Captain
        fields = ['fname', 'lname', 'email', 'password', 'contact', 'address','profile']

    def validate(self, data):
        requireFields = ['fname', 'lname', 'email', 'password', 'contact', 'address','profile']

        validator = uc.requireFeildValidation(data, requireFields) 

        if not validator['status']:
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
        existing_rider = Captain.objects.filter(contact=contact).first()
        if existing_rider:
            raise serializers.ValidationError("This contact number is already in use by another user.")
        
        return contact
 
 

class CaptainLoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = Captain
        fields = ["email", "password"]

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        fetch_user = Captain.objects.filter(email=email).first()
        if not fetch_user:
            raise serializers.ValidationError("Email not found . . .")
        check_pass = handler.verify(password, fetch_user.password)
        if not check_pass:
            raise serializers.ValidationError("Wrong Password !!!")
        attrs["fetch_user"] = fetch_user
        return attrs

class GetCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = VehicleCategory
        fields= ['id', 'title', 'description']



def validate_image_size(value):
    max_size = 1 * 1024 * 1024

    if value.size > max_size:
        raise serializers.ValidationError("Image size should not exceed 5 MB.")

class CaptionVehicleSerializer(serializers.ModelSerializer):
    class Meta:
        model = CaptainVehicle
        fields = '__all__'