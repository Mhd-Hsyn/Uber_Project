from django.shortcuts import render
from rest_framework.viewsets import ModelViewSet
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from passlib.hash import django_pbkdf2_sha256 as handler
from decouple import config
from operator import itemgetter

from .serializers import *
from .models import *
from Usable import useable as uc
from Usable import token as _auth
from Usable import emailpattern as verified
from Usable.permissions import SuperAdminPermission

import random

# Create your views here.

class encryptpass(APIView):
    def post(self, request):
        try:
            passw = handler.hash(request.data.get("passw"))
            print(passw)
            return Response({"Hash":passw})
        except Exception as e:
            message = {"status": "Error", "message": str(e)}
            return Response(message)


class SuperAdminAuthViewset(ModelViewSet):

    @action(detail=False, methods=['POST'])
    def login(self, request):
        try:
            requireFeild = ['email', 'password']
            validator = uc.requireFeildValidation(request.data, requireFeild)
            if validator['status']:
                ser = SuperAdminLoginSerializer(data=request.data)
                if ser.is_valid():
                    fetchuser = ser.validated_data["fetch_user"]
                    admin_token = _auth.SuperAdminGenerateToken(fetchuser)
                    if admin_token["status"]:
                        return Response(
                            {
                                "status": True,
                                "msg": "Login Successfully",
                                "token": admin_token["token"],
                                "payload": admin_token["payload"],
                            },
                            status=200,
                        )
                    return Response({"status": False,"message": f"Invalid Credentials {admin_token['message']}",},status=400,)
                return Response({"status": False, "msg": ser.errors}, status=400)
            return Response({"status": False, "message": str(validator['message'])}, status= status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status=400)
    
    @action(detail= False, methods= ['POST'])
    def forgotPassSendMail(self, request):
        try:
            requireFeild = ["email"]
            validator = uc.requireFeildValidation(request.data, requireFeild)
            if validator["status"]:
                email = request.data['email']
                fetchuser = SuperAdmin.objects.filter(email=email).first()
                if fetchuser:
                    otpCode = random.randint(1000, 9999)
                    fetchuser.Otp = otpCode
                    fetchuser.OtpStatus = True
                    fetchuser.OtpCount = 0
                    fetchuser.save()
                    data = {
                        "subject": "OTP for Reset Password Uber App",
                        "EMAIL_HOST_USER" : config('EMAIL_HOST_USER'),
                        "toemail": email,
                        "token" : otpCode

                    }
                    email_status = verified.forgetEmailPattern(data)
                    if email_status:
                        return Response(
                            {
                                "status": True,
                                "message": f"OTP send Successfully check your email {email}",
                                "id": str(fetchuser.id),
                            },
                            status=status.HTTP_200_OK,
                        )
                    else:
                        return Response({'status': False, 'message': 'Something went wrong'})
                return Response({"status": False, "error": "No User found in this email"},status=status.HTTP_404_NOT_FOUND,)
            return Response({"status": False, "error": "email required"})
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status=400)
        
    @action(detail=False, methods=["POST"])
    def checkOtpToken(self, request):
        try:
            requireFeild = ["otp", "id"]
            feild_status = uc.requireFeildValidation(request.data, requireFeild)
            if feild_status["status"]:
                otp = request.data["otp"]
                uid = request.data["id"]
                fetchuser = SuperAdmin.objects.filter(id=uid).first()
                if fetchuser:
                    if fetchuser.OtpStatus and fetchuser.OtpCount < 3:
                        if fetchuser.Otp == int(otp):
                            fetchuser.Otp = 0
                            fetchuser.save()
                            return Response(
                                {
                                    "status": True,
                                    "message": "Otp verified . . . ",
                                    "id": str(fetchuser.id),
                                },
                                status=status.HTTP_200_OK,
                            )
                        else:
                            fetchuser.OtpCount += 1
                            fetchuser.save()
                            if fetchuser.OtpCount >= 3:
                                fetchuser.Otp = 0
                                fetchuser.OtpCount = 0
                                fetchuser.OtpStatus = False
                                fetchuser.save()
                                return Response({"status": False,"message": f"Your OTP is expired . . . Kindly get OTP again ",})
                            return Response({"status": False, "message": f"Your OTP is wrong . You have only {3- fetchuser.OtpCount} attempts left ",})
                    return Response({"status": False, "error": "No OTP , Otp Status False"},status=404,)
                return Response({"status": False, "error": "User not exist"}, status=404)
            return Response({"status": False, "error": feild_status["message"]})
        except Exception as e:
            return Response({"status": False, "message": str(e)}, status=400)
    
    @action(detail=False, methods=["POST"])
    def resetPassword(self, request):
        try:
            requireFeild = ["id", "newpassword"]
            requiredFeild_status = uc.requireFeildValidation(request.data, requireFeild)
            if requiredFeild_status["status"]:
                uid = request.data["id"]
                newpassword = request.data["newpassword"]
                if not uc.checkpasslen(password=newpassword):
                    return Response({"status": False,"error": "Password length must be greater than 8",})
                fetchuser = SuperAdmin.objects.filter(id=uid).first()
                if fetchuser:
                    if fetchuser.OtpStatus and fetchuser.Otp == 0:
                        fetchuser.password = handler.hash(newpassword)
                        fetchuser.OtpStatus = False
                        fetchuser.OtpCount = 0
                        fetchuser.save()
                        logout_all = SuperAdminWhitelistToken.objects.filter(admin=fetchuser)
                        logout_all.delete()
                        return Response(
                            {
                                "status": True,
                                "message": "Password Reset Successfully Go to Login",
                            },
                            status=200,
                        )
                    return Response({"status": False, "error": "Token not verified !!!!"}, status= 400)
                return Response({"status": False, "error": "User Not Exist !!!"}, status= 404)
            return Response({"status": False, "error": requiredFeild_status["message"]}, status= 400)
        except Exception as e:
            return Response({"status": False, "message": str(e)}, status=400)
    
# New Class use permission_classes    Admin Profile / change password / Logout
class SuperAdminApi(ModelViewSet):
    permission_classes = [SuperAdminPermission]

    @action(detail=False, methods=["GET"])
    def logout(self, request):
        try:
            token = request.auth  # access from permission class after decode
            fetchuser = SuperAdmin.objects.filter(id=token["id"]).first()
            _auth.SuperAdminDeleteToken(fetchuser, request)
            return Response({"status": True, "message": "Logout Successfully"}, status=200)
        except Exception as e:
            return Response({"status": False, "error": f"Something wrong {str(e)}"}, status=400)

    @action(detail=False, methods=["GET", "PUT"])
    def profile(self, request):
        try:
            decoded_token = request.auth  # get decoded token from permission class
            email = decoded_token["email"]
            fetchuser = SuperAdmin.objects.filter(email=email).first()
            if request.method == "GET":
                payload = {
                    "id": str(fetchuser.id),
                    "fname": fetchuser.fname,
                    "lname": fetchuser.lname,
                    "email": fetchuser.email,
                    "contact": fetchuser.contact,
                    "profile": fetchuser.profile.url,
                }
                return Response({"status": True, "data": payload})

            if request.method == "PUT":
                requirefeilds = ["fname", "lname", "contact"]
                validator = uc.requireFeildValidation(request.data, requirefeilds)
                if validator["status"]:
                    (
                        fetchuser.fname,
                        fetchuser.lname,
                        fetchuser.contact,
                    ) = itemgetter("fname", "lname", "contact")(request.data)
                    if request.FILES.get("profile"):
                        fetchuser.profile = request.FILES["profile"]
                    fetchuser.save()
                    payload = {
                        "id": str(fetchuser.id),
                        "fname": fetchuser.fname,
                        "lname": fetchuser.lname,
                        "email": fetchuser.email,
                        "contact": fetchuser.contact,
                        "profile": fetchuser.profile.url,
                    }
                    return Response(
                        {
                            "status": True,
                            "message": "Updated Successfully",
                            "data": payload,
                        },
                        status=status.HTTP_200_OK,
                    )
                return Response({"status": False, "error": validator["message"]},status=status.HTTP_400_BAD_REQUEST,)
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status=400)

    @action(detail=False, methods=["POST"])
    def changePass(self, request):
        try:
            requireFeilds = ["oldpassword", "newpassword"]
            validator = uc.requireFeildValidation(request.data, requireFeilds)
            if validator["status"]:
                token = request.auth
                fetchuser = SuperAdmin.objects.filter(id=token["id"]).first()
                if handler.verify(request.data["oldpassword"], fetchuser.password):
                    if uc.checkpasslen(request.data["newpassword"]):
                        fetchuser.password = handler.hash(request.data["newpassword"])
                        # delete old token
                        _auth.SuperAdminDeleteToken(fetchuser, request)
                        # generate new token
                        token = _auth.SuperAdminGenerateToken(fetchuser)
                        fetchuser.save()
                        return Response(
                            {
                                "status": True,
                                "message": "Password Successfully Changed",
                                "token": token["token"],
                            },
                            status=200,
                        )
                    return Response({"status": False,"error": "New Password Length must be graterthan 8",},status=400,)
                return Response({"status": False, "error": "Old Password not verified"}, status=400)
            return Response({"status": False, "error": validator["message"]}, status=400)
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status=400)
        
    @action(detail=False, methods=["POST", "PUT", "DELETE", "GET"])
    def cities(self, request):
        try:
            if request.method == "POST":
                requireFeilds = ["country", "city"]
                validator = uc.requireFeildValidation(request.data, requireFeilds)
                if validator['status']:
                    ser = AddCitySerializer(data= request.data)
                    if ser.is_valid():
                        ser.save()
                        return Response({"status": True, "message": "Added Successfully"})
                    return Response({"status": False, "message": str(ser.errors)}, status= 400)
                return Response({"status": False, "error": str(validator['message'])}, status= 400)
            
            if request.method == "GET":
                fetch_city = Place.objects.all().order_by("country")
                ser = GetCitySerializer(fetch_city, many = True)                
                return Response({"status": True, "message": ser.data}, status= 200)
            
            if request.method == "DELETE":
                requireFeilds = ['id']
                validator = uc.requireFeildValidation(request.data , requireFeilds)
                if validator['status']:
                    fetch_city = Place.objects.filter(id = request.data['id']).first()
                    if fetch_city:
                        fetch_city.delete()
                        return Response({"status": True, "message": f"{fetch_city.city} deleted successfully"}, status= 200)
                    return Response({"status": False, "error": "id not exist"}, status= 400)
                return Response({"status": False, "error": str(validator['message'])}, status= 400)
            
            if request.method == "PUT":
                requireFeilds = ['id', 'country', 'city']
                validator = uc.requireFeildValidation(request.data , requireFeilds)
                if validator['status']:
                    fetch_city = Place.objects.filter(id = request.data['id']).first()
                    if fetch_city:
                        country = request.data['country'].lower()
                        city = request.data['city'].lower()
                        if Place.objects.filter(country = country, city = city).first():
                            return Response({"status": False, "error": f"{city} alreadey exist"}, status= 400)
                        
                        fetch_city.country = country
                        fetch_city.city = city
                        fetch_city.save()
                        return Response({"status": True, "message": f"{fetch_city.city} Updated Successfully"}, status= 200)
                    return Response({"status": False, "error": "id not exist"}, status= 400)
                return Response({"status": False, "error": validator['message']}, status= 400)

        except Exception as e:
            return Response({"status": False, "error": str(e)}, status= 400)

    @action(detail= False, methods=['POST', 'GET', 'DELETE'])
    def staff(self, request):
        try:
            if request.method == 'POST':
                requireFeilds = ['city', 'role', 'fname', 'lname', 'email', 'contact', 'address','password']
                validator = uc.requireFeildValidation(request.data, requireFeilds)
                if validator['status']:
                    data = request.data
                    fetch_city = Place.objects.filter(id = data['city']).first()
                    if fetch_city:
                        ser = AddStaffSerializer(data= data, context = {'city_id': data['city']})
                        if ser.is_valid():
                            ser.save()
                            return Response({"status": True, "message": "Staff member Created Successfully !!!"})                    
                        return Response({"status": False, "error": str(ser.errors)}, status= 400)
                    return Response({"status": False, "error": "City not exist"}, status= 400)
                return Response({"status": False, "error": validator['message']}, status= 400)    
            
            if request.method == "GET":
                requireFeilds = ['city_id']
                validator = uc.requireFeildValidation(request.data, requireFeilds)
                if validator['status']:
                    fetch_city = Place.objects.filter(id = request.data['city_id']).first()
                    if fetch_city:
                        fetch_staff = Admin.objects.filter(city = fetch_city).order_by('role')
                        ser = GetStaffByCitySerializer(fetch_staff, many=True)
                        sorted_data = sorted(ser.data, key=lambda x: x['role'] != 'city-admin')
                        return Response({"status": True, "city": str(fetch_city) ,"data": sorted_data}, status= 200)
                    return Response({"status": False, "error": "Invalid city ID"}, status= 400)
                return Response({"status": False, "error": validator['message']}, status= 400)
            
            if request.method == 'DELETE':
                requireFeilds = ['staff_id']
                validator = uc.requireFeildValidation(request.data, requireFeilds)
                if validator['status']:
                    fetch_staff = Admin.objects.filter(id = request.data['staff_id']).first()
                    if fetch_staff:
                        fetch_staff.delete()
                        return Response({"status": True, "message": f"{fetch_staff} deleted successfully"})
                    return Response({"status": False, "error": "staff doesnot exists"}, status= 400)
                return Response({"status": False, "error": validator['message']}, status= 400)
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status= 400)
    
    
    @action(detail=False, methods=['POST', 'GET', 'PUT', "DELETE"])
    def vehicleCategory(self, request):
        try:
            if request.method == "POST":
                requireFeild = ['city_id' ,'title', 'description']
                validator = uc.requireFeildValidation(request.data, requireFeild)
                if validator['status']:
                    ser = AddVehicleCategorySerializer(data= request.data, context= request.data['city_id'])
                    if ser.is_valid():
                        ser.save()
                        return Response({"status": True, "message": "Added successfully"})
                    return Response({"status": False, "error": str(ser.errors)}, status=400)
                return Response({"status": False, "error": str(validator['message'])}, status=400)

            elif request.method == "GET":
                requireFeild = ['city_id']
                validator = uc.requireFeildValidation(request.data, requireFeild)
                if validator['status']:
                    fetch_city = Place.objects.filter(id = request.data['city_id']).first()
                    if not fetch_city:
                        return Response({"status": False, "error": "invalid city id"}, status=400)
                    fetch_vehicleCategory = VehicleCategory.objects.filter(city = fetch_city).order_by('title')
                    if fetch_vehicleCategory:
                        ser = GetVehicleCategorySerializer(fetch_vehicleCategory, many = True)
                        return Response({"status": True ,"city": fetch_city.city ,"Vehicle_Categories": ser.data}, status= 200)
                    return Response({"status": False, "error": "city has no vehicle category"}, status=400)
                return Response({"status": False, "error": str(validator['message'])}, status=400)

            elif request.method == "PUT":
                requireFeild = ['city_id', 'vehicle_cat_id' ,'title', 'description']
                validator = uc.requireFeildValidation(request.data, requireFeild)
                if validator['status']:
                    fetch_vehicleCategory = VehicleCategory.objects.filter(id = request.data['vehicle_cat_id']).first()
                    ser = EditVehicleCategorySerializer(instance= fetch_vehicleCategory, data= request.data, context={'city_id':request.data['city_id']})
                    if ser.is_valid():
                        ser.save()
                        return Response({"status": True, "message": f"{request.data['title']} Updated in city successfully !!!!"})
                    return Response({"status": False, "error": str(ser.errors)}, status=400)
                return Response({"status": False, "error": str(validator['message'])}, status=400)

            elif request.method == "DELETE":
                requireFeild = ['vehicle_cat_id']
                validator = uc.requireFeildValidation(request.data, requireFeild)
                if validator['status']:
                    fetch_vehicleCategory = VehicleCategory.objects.filter(id = request.data['vehicle_cat_id']).first()
                    if fetch_vehicleCategory:
                        fetch_vehicleCategory.delete()
                        return Response({"status": True, "message": f"{fetch_vehicleCategory.title} Category Deleted from {fetch_vehicleCategory.city.city} city !!!!"})
                    return Response({"status": False, "error": "Invalid id Vehicle category not exists"}, status=400)
                return Response({"status": False, "error": str(validator['message'])}, status=400)
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status= 400)
    
    @action(detail= False, methods= ['POST', 'GET', 'PUT', 'DELETE'])
    def services (self, request):
        try:
            if request.method == 'POST':
                requireFeild = ['vehicle_cat_id', 'title', 'description']
                validator = uc.requireFeildValidation(request.data, requireFeild)
                if not validator['status']:
                    return Response({"status": False, "error": validator['message']}, status=400)
                ser = AddServicesSerializer(data= request.data, context = request.data['vehicle_cat_id'])
                if ser.is_valid():
                    ser.save()
                    return Response({"status": True, "message": "Added Successfully"}, status=400)
                return Response({"status": False, "error": ser.errors}, status=400)
            
            if request.method == 'GET':
                requireFeild = ['city_id']
                validator = uc.requireFeildValidation(request.data, requireFeild)
                if validator ['status']:
                    # get the list of vehicle category in the city
                    list_cat = VehicleCategory.objects.filter(city = request.data['city_id']).values('id','title', 'description', 'city')
                    if list_cat:
                        result = []
                        for category in list_cat:
                            category_data = {
                                'vehicle_category_id': category['id'],
                                "vehicle_category_title": category['title'],
                                'services': []
                            }
                            #  get the services provided by vehicle category
                            services_list = Service.objects.filter(vehicle_category = category['id']).values('id','title','description')
                            for service in services_list:
                                service_data = {
                                'service_id': service['id'],
                                'service_name': service['title'],
                                'service_description' : service['description']
                                }
                                category_data['services'].append(service_data)                                
                            result.append(category_data)        
                        return Response({"status": True,"data": result}, status= 200)
                    return Response({"status": False,"error": "Invalid City ID "}, status=400)
                return Response({"status": False, "error": str(validator['message'])}, status=400)         
            
            if request.method == 'PUT':
                requireFeild = ['service_id', 'title', 'description']
                validator = uc.requireFeildValidation(request.data, requireFeild)
                if validator['status']:
                    fetch_service = Service.objects.filter(id = request.data['service_id']).first()
                    if fetch_service:
                        ser = EditServiceSerializer(instance= fetch_service, data= request.data, context = {'service_id': request.data['service_id']})
                        if ser.is_valid():
                            return Response({"status": True,"data": ser.data}, status= 200)                   
                        return Response({"status": False, "error": ser.errors}, status=400)                 
                    return Response({"status": False, "error": "Service not found . . . "}, status=400)
                return Response({"status": False, "error": str(validator['message'])}, status=400)         
            if request.method == 'DELETE':
                pass
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status= 400)