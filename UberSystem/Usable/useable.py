import re
from passlib.hash import django_pbkdf2_sha256 as handler
from decouple import config
import jwt, datetime
from webApi.models import *

def checkpasslen(password):
    if len(password) < 8 :
        return False
    else:
        return True

def checkEmailPattern(email):
    try:
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        email_status = re.match(pattern, email)
        if not email_status:
            return False
        return True
    except:
        return False    

def keystatus (reqData, requireFeilds):
    try:
        for i in requireFeilds:
            if i not in reqData:
                return False
        return True
    except:
        return False

def feildstatus (reqData, requireFeilds):
    try:
        for i in requireFeilds:
            if len(reqData[i]) == 0:
                return False
        return True
    except:
        return False

def requireFeildValidation(reqData, requireFeilds):
    try:
        key_status = keystatus(reqData, requireFeilds)
        feild_status = feildstatus(reqData, requireFeilds)
        if not key_status:
            return {"status": False, "message": f"{requireFeilds} All keys are required "}
        if not feild_status:
            return {"status": False, "message": f"{requireFeilds} All feild must be filled "}
        return {"status": True}
    except Exception as e:
        return {"status": False, "message": str(e)}



def checkPasswordValidation(fetch_user, password):
    try:
        check_pass = handler.verify(secret= password, hash= fetch_user.password )
        if not check_pass:
            if fetch_user.no_of_wrong_attempts == fetch_user.no_of_attempts_allowed:
                fetch_user.account_status = False
                return {"status": False,"message":"Your Account is disable because You attempt 3 times wrong password "}
            else:
                fetch_user.no_of_wrong_attempts += 1
            fetch_user.save()
            return {"status": False,"message":f"Password doesnt match . . . you attempt {fetch_user.no_of_wrong_attempts} wrong attempt"}
        return {"status": True}
    except Exception as e:
        return {"status": False, "message": str(e)}
    
    # Tokens

    