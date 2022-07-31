from asyncore import write
from dataclasses import field
from pyexpat import model
from unittest.util import _MAX_LENGTH
from xml.etree.ElementTree import fromstring
from django.forms import ValidationError
from rest_framework import serializers

from .utils import Util
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str,smart_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68,min_length=6,write_only=True)
    class Meta: 
        model=User
        fields = ['email','username','password']

    def validate(self, attrs):
        email = attrs.get('email','')
        username = attrs.get('username','')

        if not username.isalnum():
            raise serializers.ValidationError('The Username Should Only Have AlphaNumeric Characters')
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255,min_length=3)
    password = serializers.CharField(max_length = 68 , min_length = 6,write_only=True)
    username = serializers.CharField(max_length = 255 , min_length = 3,read_only=True)
    tokens = serializers.CharField(max_length = 68 , min_length = 6,read_only=True)

    class Meta:
        model = User
        fields = ['email','password','username','tokens']

    def validate(self, attrs):
        email = attrs.get('email','')
        password = attrs.get('password','')
        user = auth.authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed('invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account Disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('email is not verified')
        return{
            'email' : user.email,
            'username' : user.username,
            'tokens' : user.tokens
        }

class ResetPasswordEmailRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        model = User
        fields = ['email']

    #def validate(self, attrs):
#       email = attrs['data'].get('email','')

 #       if User.objects.filter(email=email).exists():
#
 #           user = User.objects.filter(email=email)
  #          uidb64 = urlsafe_base64_encode(user.id)
   #         token = PasswordResetTokenGenerator().make_token(user)
    #        current_site = get_current_site(request = attrs['data'].get('request')).domain
     #       relativeLink = reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
      #      absurl = 'http://' + current_site + relativeLink
       #     to_email = []
        #    to_email.append(user.email)
         #   email_body='Hello,\nUse The Link Below To Reset Your Password: \n' + absurl
          #  data={'email_body':email_body,'to_email':to_email,'email_subject':"Reset Your Password"}
           # Util.send_email(data)

        #return super().validate(attrs)

class SetNewPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(min_length=6,max_length=68,write_only=True)
    token = serializers.CharField(min_length=1,write_only=True)
    uidb64 = serializers.CharField(min_length=1,write_only=True)
    
    class Meta:
        fields = ['password','token','uidb64']
        model = User

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed('the reset link is invalid',401)
            user.set_password(password)
            user.save()
            return (user)
        except Exception as e:
                raise AuthenticationFailed('the reset link is invalid',401)

