import os
from urllib import request
from rest_framework import generics,status,views
from expenses import serializers
from .serializers import EmailVerificationSerializer, LoginSerializer, RegisterSerializer, ResetPasswordEmailRequestSerializer , SetNewPasswordSerializer , LogoutSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from rest_framework import permissions
from django.shortcuts import redirect
from .utils import Util
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str,smart_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.http import HttpResponsePermanentRedirect
import environ
env = environ.Env()
environ.Env.read_env()
FRONTEND_URL = "http://localhost:8000"
APP_SCHEME = "incomeexpenses"
class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = ['APP_SCHEME','http','https']

class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)
    def post(self,request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        absurl = 'http://' + current_site + relativeLink + '?token=' + str(token)
        to_email = []
        to_email.append(user.email)
        email_body='Hi '+user.username+' Use The Link Below To Verify Your Email: \n' + absurl
        data={'email_body':email_body,'to_email':to_email,'email_subject':"Verify Your Email"}
        Util.send_email(data)
        return Response(data=user_data, status=status.HTTP_201_CREATED)

class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter('token',in_=openapi.IN_QUERY,description='Description',type=openapi.TYPE_STRING)
    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self,request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user =  User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email':'successfully activated'},status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error':'activation link expired'},status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error':'invalid token  '},status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self,request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email) 
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request = request).domain
            relativeLink = reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
            absurl = 'http://' + current_site + relativeLink
            to_email = []
            to_email.append(email)
            redirect_url = request.data.get('redirect_url','')
            email_body='Hello,\nUse The Link Below To Reset Your Password: \n' + absurl + "?redirect_url=" + redirect_url
            data={'email_body':email_body,'to_email':to_email,'email_subject':"Reset Your Password"}
            Util.send_email(data)
        return Response({'success':'We Have Sent You a Link To Reset Your Password'},status=status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self , request , uidb64 , token):

        redirect_url = request.GET.get("redirect_url")

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+"?token_valid=False")
                else:
                    return CustomRedirect(FRONTEND_URL+"?token_valid=False")

            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+"?token_valid=True&?message=credentialsvalid&?uidb64="+uidb64+'&?token='+token)
            else:
                return CustomRedirect(FRONTEND_URL+"?token_valid=False")

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user,token):
                return CustomRedirect(redirect_url+"?token_valid=False")

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    
    def patch(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)
        return Response({'success':True,'message':'password reset success'},status=status.HTTP_200_OK)

class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)





