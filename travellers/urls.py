from django.urls import path
from . import views

urlpatterns = [
    path("", views.index),
    path("login", views.login, name='login'),
    path("register", views.register),
    path("wait", views.waitingPage),
    path('check_user_existence/', views.check_user_existence, name='check_user_existence'),
    path('forget-password/' , views.forget_password , name="forget_password"),
    path('change-password/<token>/' , views.change_password , name="change_password"),
    path('confirm-account/<str:token>/', views.confirm_account, name='confirm_account'),
    path('email-verification-pending/', views.email_verification_pending, name='email_verification_pending'),
    path('email-verified/', views.email_verified, name='email_verified'),
    path('failed-to-verify/', views.failed_to_verify),
    path('forget-password/resend-email/', views.resend_email, name='resend_email'),
    path('invalid-token/', views.invalid_token, name='invalid_token'),
    path('application-rejected', views.application_rejected, name='application_rejected'),
    path('info/', views.info, name='info'),
    path('logout/', views.logout_view, name='logout'),
    path('user/<user_id>/', views.user_home, name='user_home'),
    path('user/<user_id>/trip/<int:trip_id>/', views.view_trip, name='view_trip'),
    path('user/<user_id>/trip/<int:trip_id>/add_photo/', views.add_photo, name='add_photo'),
    path('user/<user_id>/trip/<int:trip_id>/add_note/', views.add_note, name='add_note'),
    path('create_trip/', views.create_trip, name='create_trip'),
    path('delete_photos/', views.delete_photos, name='delete_photos'),
    path('delete_duplicate_photo/', views.delete_duplicate_photo, name='delete_duplicate_photo'),
    path('delete_trip/<int:trip_id>/', views.delete_trip, name='delete_trip'),
    path('toggle_visibility/<int:trip_id>/', views.toggle_visibility, name='toggle_visibility'),
    path('search_users/', views.search_users, name='search_users'),
    path('profile/<user_id>/', views.profile_view, name='profile_view'),
    path('user/<user_name>/<trip_id>/', views.public_view_trip, name='public_view_trip'),

]
