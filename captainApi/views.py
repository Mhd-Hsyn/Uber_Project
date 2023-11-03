from django.shortcuts import render
from django.shortcuts import render
from rest_framework.viewsets import ModelViewSet
from rest_framework import status
# Create your views here.
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from passlib.hash import django_pbkdf2_sha256 as handler
from django.db.models import F, Q
from geopy.geocoders import GoogleV3
from decouple import config
from operator import itemgetter
from .serializers import *
from webApi.models import *
from Usable import useable as uc
from Usable import token as _auth
from Usable import emailpattern as verified
from Usable.permissions import *
from rest_framework.exceptions import NotFound
import random


# Rider personal-detail sign-up Api

class CaptionAuthViewset(ModelViewSet):
    
    queryset = Captain.objects.all()
    serializer_class = CaptionSerializer

    @action(detail=False, methods=['POST'])
    def signup(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.save()

        return Response({"status": True, "message": "Account Created Successfully!"}, status=status.HTTP_201_CREATED)


# Rider location get Api

    @action(detail=False, methods=['get'])
    def captain_location_info(self, request):
        latitude = request.query_params.get('latitude')
        longitude = request.query_params.get('longitude')

        if not latitude or not longitude:
            return Response({'error': 'Latitude and Longitude are required in the request.'}, status=status.HTTP_400_BAD_REQUEST)

        geolocator = GoogleV3(api_key="AIzaSyAEMeWgeUm5zc7D4mjUdh_gkdRdyYf_ZcU")

        location = geolocator.reverse((latitude, longitude), exactly_one=True)

        address = location.raw['address_components']

        citys = next((component['long_name'] for component in address if 'locality' in component['types']), 'City information not available')
        citys = citys.lower()
        try:
            fetch_city = Place.objects.filter(city = citys).first()
            if fetch_city:
                fetch_categories = VehicleCategory.objects.filter(city=fetch_city)
                ser = GetCategorySerializer(fetch_categories, many = True)
                    
                response_data = {
                    'data': ser.data 
                }
                return Response(response_data, status=status.HTTP_200_OK)
            return Response({"status": False, "error": f"Sorry! Services not available in {citys} city "})
        except VehicleCategory.DoesNotExist:
            return Response({"services is not available"}, status=status.HTTP_404_NOT_FOUND)


# Captain sign-in

    @action(detail=False, methods=['POST'])
    def login(self, request):
        try:
            requireFeild = ['email', 'password']
            validator = uc.requireFeildValidation(request.data, requireFeild)
            if validator['status']:
                ser = CaptainLoginSerializer(data=request.data)
                if ser.is_valid():
                    fetchuser = ser.validated_data["fetch_user"]
                    captain_token = _auth.CaptainGenerateToken(fetchuser)
                    if captain_token["status"]:
                        return Response(
                            {
                                "status": True,
                                "msg": "Login Successfully",
                                "token": captain_token["token"],
                                "payload": captain_token["payload"],
                            },
                            status=200,
                        )
                    return Response({"status": False,"message": f"Invalid Credentials {captain_token['message']}",},status=400,)
                return Response({"status": False, "msg": ser.errors}, status=400)
            return Response({"status": False, "message": str(validator['message'])}, status= status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status=400)

# Captain adminForgotPassSendMail

    @action(detail= False, methods= ['POST'])
    def adminForgotPassSendMail(self, request):
        try:
            requireFeild = ["email"]
            validator = uc.requireFeildValidation(request.data, requireFeild)
            if validator["status"]:
                email = request.data['email']
                fetchuser = Captain.objects.filter(email=email).first()
                if fetchuser:
                    otpCode = random.randint(1000, 9999)
                    fetchuser.Otp = otpCode
                    fetchuser.OtpStatus = True
                    fetchuser.OtpCount = 0
                    fetchuser.save()
                    data = {
                        "subject": "OTP for Reset Password Ubers",
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
        

# Captain checkOtpToken

    @action(detail=False, methods=["POST"])
    def checkOtpToken(self, request):
        try:
            requireFeild = ["otp", "id"]
            feild_status = uc.requireFeildValidation(request.data, requireFeild)
            if feild_status["status"]:
                otp = request.data["otp"]
                uid = request.data["id"]
                fetchuser = Captain.objects.filter(id=uid).first()
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
    
# Captain resetPassword

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
                fetchuser = Captain.objects.filter(id=uid).first()
                if fetchuser:
                    if fetchuser.OtpStatus and fetchuser.Otp == 0:
                        fetchuser.password = handler.hash(newpassword)
                        fetchuser.OtpStatus = False
                        fetchuser.OtpCount = 0
                        fetchuser.save()
                        logout_all = CaptainWhitelistToken.objects.filter(captain=fetchuser)
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



# captain_vehicle_info Api

class captain_Api(ModelViewSet):
    permission_classes = [CaptainPermission]

    queryset = CaptainVehicle.objects.all()
    serializer_class = CaptionVehicleSerializer   
     
    @action(detail=False, methods=['POST'])
    def captain_vehicle_info(self, request, *args, **kwargs):
        requireFeild = ['cnic','cnic_front_image','cnic_back_image','vehicle_number','numberplate_image','vehicle_document_image','license_number','license_front_image','license_back_image','vehicle_category']
        validator = uc.requireFeildValidation(request.data, requireFeild)
        if validator['status']:
            captain = request.data.get('captain')
            vehicle_category = request.data.get('vehicle_category')

            captain_uid = Captain.objects.filter(id=captain).first()
            vehicle_category_obj = VehicleCategory.objects.filter(id=vehicle_category).first()

            serializer = sel.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.validated_data['captain'] = captain_uid
            serializer.validated_data['vehicle_category'] = vehicle_category_obj
            serializer.save()
            return Response({"status": True, "message": "Vehicle details Successfully Saved!"}, status=status.HTTP_201_CREATED)
        return Response({"status": False, "message": str(validator['message'])}, status=status.HTTP_400_BAD_REQUEST)

    

# rider-info-get Api

    @action(detail=False, methods=["GET"])
    def captain_vehicle_info_get(self, request):
        try:
            token = request.auth 
            fetchuser = CaptainVehicle.objects.filter(captain=token["id"]).values('approval_status','approval_message','cnic','cnic_front_image','cnic_back_image','vehicle_number','numberplate_image',
            'vehicle_document_image','license_number','license_front_image','license_back_image', 
            first_name=F('captain__fname'), lastname=F('captain__lname'),
            Email=F('captain__email'), Contact=F('captain__contact'),Address=F('captain__address'),Profile=F('captain__profile'),
            vehiclename=F('vehicle_category__title'),City=F('vehicle_category__city__city'))
            if token:
                return Response({"status": True, "message" : fetchuser}, status=200)
            else:
                return Response({"status": True, "message" : "unthorized"}, status=500)
        except Exception as e:
            return Response({"status": False, "error": f"Something wrong {str(e)}"}, status=400)
    
    
    
    @action(detail=False, methods=["PUT"])
    def profile(self, request):
        try:
            decoded_token = request.auth  
            email = decoded_token["email"]
            fetchuser = Captain.objects.filter(email=email).first()

            requirefeilds = ["fname", "lname","contact","address","profile"]
            validator = uc.requireFeildValidation(request.data, requirefeilds)
            if validator["status"]:
                (
                    fetchuser.fname,
                    fetchuser.lname,
                    fetchuser.contact,
                    fetchuser.address,

                ) = itemgetter("email")(request.data)
                if request.FILES.get("profile"):
                    fetchuser.profile = request.FILES["profile"]
                fetchuser.save()
                payload = {
                    "id": str(fetchuser.id),
                    "fname": fetchuser.fname,
                    "lname": fetchuser.lname,
                    "email": fetchuser.email,
                    "address":fetchuser.address,
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
        

    @action(detail=False, methods=["PUT"])
    def profile_info(self, request):
        token = request.auth
        fetch_captain = CaptainVehicle.objects.filter(captain=token["id"]).first()
        cnic  = request.data.get("cnic")
        vehicle_number = request.data.get("vehicle_number")
        cnic_front_image = request.FILES["cnic_front_image"]
        cnic_back_image = request.FILES["cnic_back_image"]
        numberplate_image = request.FILES["numberplate_image"]
        vehicle_document_image = request.FILES["vehicle_document_image"]
        license_number = request.data.get("vehicle_number")
        license_front_image = request.FILES["license_front_image"]
        license_back_image = request.FILES["license_back_image"]

        if fetch_captain:
            fetch_captain.cnic=cnic
            fetch_captain.vehicle_number = vehicle_number
            fetch_captain.cnic_front_image = cnic_front_image
            fetch_captain.cnic_back_image = cnic_back_image
            fetch_captain.numberplate_image = numberplate_image
            fetch_captain.vehicle_document_image = vehicle_document_image
            fetch_captain.license_number=license_number
            fetch_captain.license_front_image = license_front_image
            fetch_captain.license_back_image = license_back_image
            fetch_captain.save()

            serializer = CaptionVehicleSerializer(fetch_captain)

            serialized_data = serializer.data

            return Response({"status": True, "message": "Update Successfully", "data": serialized_data})
        else:
            return Response({"status": False, "message": "Unauthorized"})


        
    
# New Class use permission_classes    Admin Profile / change password / Logout
class SuperAdminApi(ModelViewSet):
    permission_classes = [SuperAdminPermission]

    @action(detail=False, methods=["GET"])
    def logout(self, request):
        try:
            token = request.auth  # access from permission class after decode
            fetchuser = Customer.objects.filter(id=token["id"]).first()
            _auth.SuperAdminDeleteToken(fetchuser, request)
            return Response({"status": True, "message": "Logout Successfully"}, status=200)
        except Exception as e:
            return Response({"status": False, "error": f"Something wrong {str(e)}"}, status=400)




    @action(detail=False, methods=["POST"])
    def changePass(self, request):
        try:
            requireFeilds = ["oldpassword", "newpassword"]
            validator = uc.requireFeildValidation(request.data, requireFeilds)
            if validator["status"]:
                token = request.auth
                fetchuser = Customer.objects.filter(id=token["id"]).first()
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
                return Response({"status": False, "error": "Old Password not verified"}, status=400)
            return Response({"status": False, "error": validator["message"]}, status=400)
        except Exception as e:
            return Response({"status": False, "error": str(e)}, status=400)
  