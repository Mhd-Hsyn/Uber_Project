from decouple import config
import jwt, datetime
from webApi.models import *

def SuperAdminGenerateToken(fetchuser):
    try:
        secret_key = config("SuperAdmin_jwt_token")
        total_days = 1
        token_payload = {
            "id": str(fetchuser.id),
            "email":fetchuser.email,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=total_days),
            # "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1),  
              
        }
        detail_payload = {
            "id": str(fetchuser.id),
            "email":fetchuser.email,
            "first_name": fetchuser.fname,
            "last_name": fetchuser.lname,
            "phone": fetchuser.contact,
            "profile": fetchuser.profile.url
        }
        token = jwt.encode(token_payload, key= secret_key, algorithm="HS256")
        SuperAdminWhitelistToken.objects.create(admin = fetchuser, token = token)
        return {"status": True, "token" : token, "payload": detail_payload}
    except Exception as e:
        return {"status": False, "message": f"Error during generationg token {str(e)}"}

# Logout
def SuperAdminDeleteToken(fetchuser, request):
    try:
        token = request.META["HTTP_AUTHORIZATION"][7:]
        whitelist_token = SuperAdminWhitelistToken.objects.filter(admin = fetchuser.id, token = token).first()
        whitelist_token.delete()
        admin_all_tokens = SuperAdminWhitelistToken.objects.filter(admin = fetchuser)
        for fetch_token in admin_all_tokens:
            try:
                decode_token = jwt.decode(fetch_token.token, config('SuperAdmin_jwt_token'), "HS256")
            except:    
                fetch_token.delete()
        return True
    except Exception :
        return False