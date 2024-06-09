from django.contrib.auth.backends import ModelBackend
import hashlib

from django.shortcuts import get_object_or_404
from .models import User, Admin

class CustomBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None):
        try:
            try:
                user = User.objects.get(email=email)
                if user and user.password == hashlib.sha256(password.encode()).hexdigest():
                    return user
            except User.DoesNotExist:
                admin = Admin.objects.get(email=email)
                if admin and admin.password == hashlib.sha256(password.encode()).hexdigest():
                    return admin
                else:
                    return None
        except (User.DoesNotExist, Admin.DoesNotExist):
            return None
        

def auth(request):
    try: 
        uid = request.session['admin_id']
        user = get_object_or_404(Admin, pk=uid)
        if user is None:
            return False 
        return user
    except:
        return False


        


# class CustomBackend(ModelBackend):
#     def authenticate(self, request, email=None, password=None):
#         try:
#             user = User.objects.get(email=email)
            
#             if user and check_password(password, user.password):
#                 return user
#             else:
#                 return None
#         except:
#             try:
#                 admin = Admin.objects.get(email=email)
                
#                 if admin and check_password(password, admin.password):
#                     return admin
#                 else:
#                     return None
#             except Admin.DoesNotExist:
#                 return None
#     def checkUser(self, request, email=None):
#             user = User.objects.get(email=email)
#             if user:
#                 return user
#             else:
#                 return None
