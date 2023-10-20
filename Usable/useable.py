import re
from passlib.hash import django_pbkdf2_sha256 as handler
from decouple import config
import jwt, datetime
from webApi.models import *
from PIL import Image

def checkpasslen(password):
    if not (re.search(r'[!@#$%^&*(),.?":{}|<>]', password) and re.search(r'[A-Z]', password) and 8 <= len(password) <= 20):
        return False
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
            return {"status": False, "message": f"{requireFeilds} All fields must be filled "}  # Changed "feild" to "field"
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

    

def validate_password(password):
    if not (re.search(r'[!@#$%^&*(),.?":{}|<>]', password) and re.search(r'[A-Z]', password) and 8 <= len(password) <= 20):
        return False
    return True



def imageValidator(img,ignoredimension = True,formatcheck = False):

    try:

        if img.name[-3:] == "svg":
            return True
        im = Image.open(img)
        width, height = im.size
        if ignoredimension:
            if width > 330 and height > 330:
                return False

            else:
                return True

        if formatcheck:
            if im.format == "PNG":
                
                return True

            else:
                
                return False
            
        return True
    
    except:
        return False


def makedict(obj,key,imgkey=False):
    dictobj = {}
    
    for j in range(len(key)):
        keydata = getattr(obj,key[j])
        if keydata:
            dictobj[key[j]] = keydata
    
    if imgkey:
        imgUrl = getattr(obj,key[-1])
        if imgUrl:
            dictobj[key[-1]] = imgUrl.url
        else:
             dictobj[key[-1]] = ""



  

    return dictobj