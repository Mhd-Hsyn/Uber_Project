from rest_framework.permissions import BasePermission
from rest_framework.exceptions import AuthenticationFailed
from decouple import config

from webApi.models import *

import jwt 

class SuperAdminPermission(BasePermission):
    def has_permission(self, request, view):
        try:
            auth_token = request.META["HTTP_AUTHORIZATION"][7:]
            decode_token = jwt.decode(auth_token, config('SuperAdmin_jwt_token'), "HS256")
            whitelist = SuperAdminWhitelistToken.objects.filter(admin =  decode_token['id'],token = auth_token).exists()
            if not whitelist:
                raise AuthenticationFailed("You must need to Login first")
            request.auth = decode_token
            return True
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed({"status": False,"error":"Session Expired !!"})
        except jwt.DecodeError:
            raise AuthenticationFailed({"status": False,"error":"Invalid token"})
        except Exception as e:
            raise AuthenticationFailed({"status": False,"error":"Need Login"})
        


class CaptainPermission(BasePermission):
    def has_permission(self, request, view):
        try:
            auth_token = request.META["HTTP_AUTHORIZATION"][7:]
            decode_token = jwt.decode(auth_token, config('captain_jwt_token'), "HS256")
            whitelist = CaptainWhitelistToken.objects.filter(captain =  decode_token['id'],token = auth_token).exists()
            if not whitelist:
                raise AuthenticationFailed("You must need to Login first")
            request.auth = decode_token
            return True
        except AuthenticationFailed as af:
            raise af
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed({"status": False,"error":"Session Expired !!"})
        except jwt.DecodeError:
            raise AuthenticationFailed({"status": False,"error":"Invalid token"})
        except Exception as e:
            raise AuthenticationFailed({"status": False,"error":"Need Login"})
        