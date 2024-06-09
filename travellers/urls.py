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
    # path('logout/', views.logout, name='logout'),
]
