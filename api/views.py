from django.shortcuts import render

from rest_framework.response import Response
from .serializers import UserSerializer, RegisterSerializer
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from rest_framework.renderers import JSONRenderer
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.compat import coreapi, coreschema
from rest_framework.schemas import coreapi as coreapi_schema
from rest_framework.schemas import ManualSchema

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from rest_framework import generics

from rest_framework.views import APIView

from PIL import Image
import base64
import io
import numpy as np
import cv2
import re
from .utils import get_protected_image, get_phone_number

import threading
import base64

from email.message import EmailMessage
import smtplib

import datetime

class UserDetailAPI(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def get(self, request, *args, **kwargs):
        user = User.objects.get(id=request.user.id)
        serializer = UserSerializer(user)
        return Response(serializer.data)

class RegisterUserAPI(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

class LoginUserAPI(generics.CreateAPIView):
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    renderer_classes = (JSONRenderer,)
    serializer_class = AuthTokenSerializer

    if coreapi_schema.is_enabled():
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name="username",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Username",
                        description="Valid username for authentication",
                    ),
                ),
                coreapi.Field(
                    name="password",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Password",
                        description="Valid password for authentication",
                    ),
                ),
            ],
            encoding="application/json",
        )

    def get_serializer_context(self):
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def get_serializer(self, *args, **kwargs):
        kwargs['context'] = self.get_serializer_context()
        return self.serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        now = datetime.datetime.now()
        user.last_login = str(now)
        user.save()
        return Response({'token': token.key})

@method_decorator(csrf_exempt, name='dispatch')
class ProtectImageAPI(APIView):
   # authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):


        def cv2_to_base64(cv2_image):
            # Codificar la imagen a formato JPEG

            _,_,canales = cv2_image.shape
            print(canales)
            _, buffer = cv2.imencode('.jpg', cv2_image)

            # Convertir el buffer codificado a base64
            base64_image = base64.b64encode(buffer).decode('utf-8')

            return base64_image

        phone_number = request.data['phone_number']
        file_base64 = request.data['base64']
        file_base64 = re.sub(r'^.*?base64,', '', file_base64)

        decoded_data = base64.b64decode(file_base64)
        np_data = np.fromstring(decoded_data, np.uint8)
        imagen = cv2.imdecode(np_data, cv2.IMREAD_UNCHANGED)

        protected_image = get_protected_image(imagen, phone_number)

    
        imagen_base64 = cv2_to_base64(protected_image)
        
        response =  Response({"base64": imagen_base64})
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

        return response

@method_decorator(csrf_exempt, name='dispatch')
class GetImageMarkAPI(APIView):
  #  authentication_classes = (TokenAuthentication,)
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        file_base64 = request.data['base64']
        file_base64 = re.sub(r'^.*?base64,', '', file_base64)

        decoded_data = base64.b64decode(file_base64)
        np_data = np.fromstring(decoded_data, np.uint8)
        imagen = cv2.imdecode(np_data, cv2.IMREAD_UNCHANGED)

        phone_number = get_phone_number(imagen)

        response = Response({"phone_number": phone_number})
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

        return response