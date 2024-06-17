import json
from django.shortcuts import render, redirect
from django import forms
from .models import User, Resetpass, EmailVerification, Admin
from django.contrib.auth import authenticate, login
from django.contrib import messages
from .custom_auth import  CustomBackend, auth
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.db.models import Count
import uuid
from .mail_helper import send_forget_password_mail, send_user_confirmation_email
from django.utils import timezone
from datetime import timedelta, datetime
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseForbidden
from .models import Trip, Photo, Note
import hashlib


def index(request):
    return render(request, "home.html")


def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password') 
        custom_backend = CustomBackend()
        user = custom_backend.authenticate(request, email=email, password=password)
        # regUser = custom_backend.authenticate(request, email=email)
        if user is not None:
            if isinstance(user, User):
                request.session['user_id'] = str(user.id)
                print(str(user.id))
                #to revert back to uuid while retireving use this user_id = uuid.UUID(request.session['user_id'])
                if user.is_verified == 0:
                    return redirect('email-verification-pending/')
                # elif user.status == 'pending':
                #     return redirect("/wait")
                # elif user.status == 'rejected':
                #     return redirect("/application-rejected")
                else:
                    return redirect('user_home', user_id = user.id)
            elif isinstance(user, Admin):
                request.session['admin_id'] = user.id
                if user.status == 'active':
                    request.session['role'] = 'admin'
                    return redirect("/adminPanel")
                else:
                    messages.error(request, 'Admin status inactive.')
                    return redirect('/login')
        # else:
        #     admin_backend = CustomBackend1()
        #     user = admin_backend.authenticate(request, email=email, password=password)
        #     print(user)
        #     if user is not None:
        #         request.session['super_admin_id'] = user.id
        #         request.session['role'] = 'superadmin'
        #         return redirect("/adminPanel")
        #     else:
        #         request.session['user_id'] = 0    #invalidated user
        #         messages.error(request, 'Invalid email or password.')
        #         return redirect('/login')
    else:
        # Render the login page
        return render(request, 'login.html' , {"message":messages.get_messages(request)})

class UserForm(forms.ModelForm):
    location1 = forms.CharField(max_length=255, label='Address Line 1')
    location2 = forms.CharField(max_length=255, label='Address Line 2')
    location3 = forms.CharField(max_length=255, label='Address Line 3')
    state = forms.CharField(max_length=255, label='State')

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'is_verified']

    def save(self, commit=True):
        user = super(UserForm, self).save(commit=False)
        location = ",".join([self.cleaned_data['location1'], self.cleaned_data['location2'], self.cleaned_data['state'], self.cleaned_data['location3']])
        user.location = location
        if commit:
            user.save()
        return user


# views.py
def register(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        print("-------------------        register function was called        ----------------")
        if form.is_valid():
            print("-------------------        form is valid        ----------------")
            user = form.save()
            send_user_confirmation_email(user)
            return redirect('/email-verification-pending/')
        else:
            print("-------------------        form is not valid        ----------------")
    else:
        form = UserForm()
    return render(request, 'register.html', {'form': form})

def check_user_existence(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        username = data.get('username')

        if User.objects.filter(email=email).exists() or User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'User already exists'}, status=400)
        else:
            return JsonResponse({'success': 'User does not exist'})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

def email_verification_pending(request):
    return render(request, 'verification_pending.html')

def email_verified(request):
    return render(request, 'email_confirmed.html')


def confirm_account(request, token):
    try:
        verification = get_object_or_404(EmailVerification, token=token)
        user = verification.user
        print(user)
        if user.is_verified:
            messages.success(request, 'Email already verified.')
            return redirect('/login')
        user.is_verified = True
        user.save(update_fields=['is_verified'])
        verification.delete()
        return redirect('/email-verified/')
    except:
        error_message = 'Invalid URL.'
        return render(request, 'failed_verification.html', {'error_message': error_message})
    

def failed_to_verify(request):
    return render(request, 'failed_verification.html')




def waitingPage(request):
    return render(request, "waitingPage.html")
    

def change_password(request, token):
    context = {}
    try:
        profile_obj = Resetpass.objects.filter(forget_password_token=token).first()
        # print(token)
        # print(Resetpass.objects.get(forget_password_token=token))
        if profile_obj is None:
            return redirect('/invalid-token/')

        # Check if the token is older than 30 minutes
        if profile_obj.created_at < timezone.now() - timedelta(minutes=30):
            messages.success(request, 'Token has expired.')
            profile_obj.delete()
            return redirect('/forget-password/')
        
        context = {'user_id': profile_obj.user.id}

        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('reconfirm_password')
            user_id = request.POST.get('user_id')
            # print(user_id)

            if user_id is None:
                messages.success(request, 'No user id found.')
                return redirect(f'/forget-password/')

            if new_password != confirm_password:
                messages.success(request, 'Passwords do not match.')
                return redirect(f'/change-password/{token}/')

            user_obj = User.objects.get(id=user_id)
            # hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            user_obj.password = new_password
            user_obj.save()
            profile_obj.delete()  # Delete the Resetpass entry
            return redirect('/login')

    except Exception as e:
        print(e)
        messages.success(request, 'link expired.')
    return render(request, 'change_password.html', context)


def forget_password(request):
    try:
        if request.method == 'POST':
            email = request.POST.get('email')

            if email == '':
                messages.success(request, 'No email provided.')
                return redirect('/forget-password/')
            if not User.objects.filter(email=email).exists():
                messages.success(request, 'No user found with this email.')
                return redirect('/forget-password/')
            
            user_obj = User.objects.get(email=email)
            resetpass_obj, created = Resetpass.objects.get_or_create(user=user_obj)
            if not created:
                if resetpass_obj.created_at < timezone.now() - timedelta(minutes=30):
                    resetpass_obj.forget_password_token = str(uuid.uuid4())
                    resetpass_obj.created_at = timezone.now()
                    resetpass_obj.save()
                    send_forget_password_mail(user_obj.email, resetpass_obj.forget_password_token)
                    messages.success(request, 'An email is sent.')
                    return redirect('/forget-password/')
                else:
                    messages.success(request, 'A verification email was already sent. Please check your inbox.')
                    return redirect('/forget-password/')
            else:
                resetpass_obj.forget_password_token = str(uuid.uuid4())
                resetpass_obj.created_at = timezone.now()
                resetpass_obj.save()
                send_forget_password_mail(user_obj.email, resetpass_obj.forget_password_token)
                messages.success(request, 'An email is sent.')
                return redirect('/forget-password/')
    
    except Exception as e:
        print(e)
    return render(request, 'forgot_password.html')

def resend_email(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if email == '':
            messages.success(request, 'No email provided.')
            return redirect('/forget-password/')
        # print("email is : ", email)
        try:
            user_obj = User.objects.get(email=email)
            resetpass_obj = Resetpass.objects.get(user=user_obj)
            if resetpass_obj.created_at < timezone.now() - timedelta(minutes=30):
                resetpass_obj.forget_password_token = str(uuid.uuid4())
                resetpass_obj.created_at = timezone.now()
                resetpass_obj.save()
                send_forget_password_mail(user_obj.email, resetpass_obj.forget_password_token)
                messages.success(request, 'An email is sent.')
                return redirect('/forget-password/')
            else:
                # print("it is in else block and email is sent")
                send_forget_password_mail(user_obj.email, resetpass_obj.forget_password_token)
                messages.success(request, 'An email is sent.')
                return redirect('/forget-password/')
        except Exception as e:
            print(e)
            messages.error(request, 'Failed to resend email. Please try again later.')
    return redirect('/forget-password/')

def invalid_token(request):
    return render(request, 'invalid_token.html')



def application_rejected(request):
    return render(request, 'rejecteduser.html')

def info(request):
    return render(request, 'info.html')

def user_home(request, user_id):
    try:
        user_id = uuid.UUID(user_id)
    except ValueError:
        logout(request)
        return redirect('login')

    if request.session.get('user_id') != str(user_id):
        logout(request)
        return redirect('login')

    query = request.GET.get('query', '')
    trips = Trip.objects.filter(user_id=user_id, country__icontains=query)
    user = User.objects.get(id=user_id)
    return render(request, 'user_home.html', {'trips': trips, 'user': user})

def toggle_visibility(request, trip_id):
    if request.method == 'POST':
        trip = get_object_or_404(Trip, id=trip_id)
        new_visibility = 'private' if trip.visibility == 'public' else 'public'
        trip.visibility = new_visibility
        trip.save()
        return JsonResponse({'status': 'success', 'new_visibility': new_visibility})
    return HttpResponseForbidden()

class TripForm(forms.ModelForm):
    class Meta:
        model = Trip
        fields = ['country', 'start_date', 'end_date']
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'end_date': forms.DateInput(attrs={'type': 'date'}),
        }

def create_trip(request):
    if request.method == 'POST':
        user_id = request.session.get('user_id')
        form = TripForm(request.POST)
        print(form.is_valid())
        print(form.errors)
        if form.is_valid():
            print("form is valid")
            trip = form.save(commit=False)
            user = get_object_or_404(User, id=user_id)
            trip.user = user
            trip.save()
            return redirect('user_home', user_id=user.id)
    else:
        print("form is not valid")
        form = TripForm()
    return HttpResponseForbidden()

def view_trip(request, user_id, trip_id):
    print("entered view_trip")
    print(user_id)
    try:
        user_id = uuid.UUID(user_id)
    except ValueError:
        logout(request)
        return redirect('login')
    
    print("uuid validation of user id finished")

    if request.session.get('user_id') != str(user_id):
        logout(request)
        return redirect('login')
    
    print("correct user validation is finished")
    print("brfore trip object")
    trip = get_object_or_404(Trip, id=trip_id, user_id=user_id)
    print("after trip object")
    photos = trip.photos.all()
    notes = trip.notes.all()
    return render(request, 'view_trip.html', {'trip': trip, 'photos': photos, 'notes': notes})

def add_photo(request, user_id, trip_id):
    if request.method == 'POST':
        try:
            user_id = uuid.UUID(user_id)  # Convert user_id to UUID
        except ValueError:
            logout(request)
            return redirect('login')

        if request.session.get('user_id') != str(user_id):
            logout(request)
            return redirect('login')

        trip = get_object_or_404(Trip, id=trip_id, user_id=user_id)
        images = request.FILES.getlist('images')
        duplicate_images = []

        for image in images:
            image_hash = hashlib.md5(image.read()).hexdigest()
            image.seek(0)  # Reset file pointer to the beginning after reading
            if Photo.objects.filter(image_hash=image_hash).exists():
                duplicate_images.append(image.name)
            else:
                Photo.objects.create(trip=trip, image=image, image_hash=image_hash)

        if duplicate_images:
            return JsonResponse({'duplicate_images': duplicate_images})

        return JsonResponse({'status': 'success'})
    return HttpResponseForbidden()

def delete_photos(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        ids = data.get('ids', [])
        print(ids)
        Photo.objects.filter(id__in=ids).delete()
        return JsonResponse({'status': 'success'})
    return HttpResponseForbidden()

def add_note(request, user_id, trip_id):
    if request.method == 'POST':
        try:
            user_id = uuid.UUID(user_id)  # Convert user_id to UUID
        except ValueError:
            logout(request)
            return redirect('login')

        if request.session.get('user_id') != str(user_id):
            logout(request)
            return redirect('login')

        trip = get_object_or_404(Trip, id=trip_id, user_id=user_id)
        note = Note.objects.create(trip=trip, content=request.POST['content'])
        return redirect('view_trip', user_id=user_id, trip_id=trip_id)
    return HttpResponseForbidden()

def delete_duplicate_photo(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        image_hash = data.get('image_hash')
        Photo.objects.filter(image_hash=image_hash).delete()
        return JsonResponse({'status': 'success'})
    return HttpResponseForbidden()

def logout_view(request):
    logout(request)
    request.session.flush()
    return redirect('login')

def delete_trip(request, trip_id):
    if request.method == 'DELETE':
        trip = get_object_or_404(Trip, id=trip_id)
        trip.photos.all().delete()
        trip.notes.all().delete()
        trip.delete()
        return JsonResponse({'status': 'success'})
    return HttpResponseForbidden()

def search_users(request):
    print("Headers:", request.headers)
    print("Query Parameters:", request.GET)
    
    if request.headers.get('x-requested-with') == 'XMLHttpRequest' and 'q' in request.GET:
        print("Request is here")
        query = request.GET.get('q', '')
        users = User.objects.filter(username__icontains=query)
        results = [{'id': user.id, 'username': user.username} for user in users]
        return JsonResponse({'users': results})
    return JsonResponse({'users': []})

def profile_view(request, user_id):
    user = get_object_or_404(User, id=user_id)
    trips = Trip.objects.filter(user=user, visibility='public')
    trip_count = trips.count()
    photo_count = sum(trip.photos.count() for trip in trips)
    context = {
        'profile_user': user,
        'trip_count': trip_count,
        'photo_count': photo_count,
        'trips': trips,
    }
    return render(request, 'profile_view.html', context)

def public_view_trip(request, user_name, trip_id):
    user_id = get_object_or_404(User, username=user_name)
    
    trip = get_object_or_404(Trip, id=trip_id, user_id=user_id)
    photos = trip.photos.all()
    notes = trip.notes.all()
    return render(request, 'public_trip_view.html', {'trip': trip, 'photos': photos, 'notes': notes})