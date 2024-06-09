import base64
from django.conf import settings
from django.core.mail import send_mail
from .models import EmailVerification, adminReg

def send_forget_password_mail(email, token):
    subject = 'Please reset your password'
    message = f'''
    <html>
    <body>
    <p>Dear User,</p>
    <p>You have requested to reset your password. Please click the button below to finish resetting your password.</p>
    <a href="http://127.0.0.1:8000/change-password/{token}/"><button style="background-color: #0084FF;
    border: none;
    color: white;
    padding: 15px 32px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;">Reset password</button></a>
    <p>If the button above doesn't work, enter the address below in your browser.</p>
    <p><a href="http://127.0.0.1:8000/change-password/{token}/">http://127.0.0.1:8000/change-password/{token}/</a></p>
    <p>This password reset link is only valid for 30 minutes after you receive this email.</p>
    <p>If you didn't ask us to reset your password, reset it now to keep your account secure.</p>
    <p>Your TJ team</p>
    </body>
    </html>
    '''
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list, html_message=message)
    return True


def send_user_confirmation_email(user):
    verification_token = base64.urlsafe_b64encode(user.email.encode()).decode()[:20]
    EmailVerification.objects.create(user=user, token=verification_token)
    subject = 'Verify your Email Address'
    message = f'''
    <html>
    <body>
    <p>Dear User,</p>
    <p>Tap the button below to confirm your email address.</p>
    <a href="http://127.0.0.1:8000/confirm-account/{verification_token}/"><button style="background-color: #0084FF;
    border: none;
    color: white;
    padding: 15px 32px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;">Confirm account</button></a>
    <p>If the button above doesn't work, copy and paste the following link in your browser:</p>
    <p><a href="http://127.0.0.1:8000/confirm-account/{verification_token}/">http://127.0.0.1:8000/confirm-account/{verification_token}/</a></p>
    <p>This account verification link is only valid for 30 minutes after you receive this email.</p>
    <p>If this was not you, you can safely delete this email.</p>
    <p>Your TJ team</p>
    </body>
    </html>
    '''
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    send_mail(subject, message, email_from, recipient_list, html_message=message)
    return True


def send_admin_reg_email(email):
    if email is None:
        return False
    
    verification_token = base64.urlsafe_b64encode(email.encode()).decode()[:20]
    adminReg.objects.create(email=email, token=verification_token)
    subject = 'Admin Registration'
    message = f'''
    <html>
    <body>
    <p>Dear User,</p>
    <p> We're thrilled to have you onboard as one of the admins of TJ.</p>
    <p>Please click the button below to finish registering yourself as an admin.</p>
    <a href="http://127.0.0.1:8000/register-new/{verification_token}/"><button style="background-color: #0084FF;
    border: none;
    color: white;
    padding: 15px 32px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;">Confirm account</button></a>
    <p>If the button above doesn't work, copy and paste the following link in your browser:</p>
    <p><a href="http://127.0.0.1:8000/register-new/{verification_token}/">http://127.0.0.1:8000/register-new/{verification_token}/</a></p>
    <p>This registration link is only valid for 24 hours after you receive this email.</p>
    <p>If this was not you, you can safely delete this email.</p>
    <p>Your TJ team</p>
    </body>
    </html>
    '''
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list, html_message=message)
    return True