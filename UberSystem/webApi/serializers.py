from rest_framework import serializers
from passlib.hash import django_pbkdf2_sha256 as handler

from .models import SuperAdmin, Place
from Usable import useable as uc 

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