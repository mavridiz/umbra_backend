from django.urls import path

from rest_framework.authtoken import views
from .views import UserDetailAPI, RegisterUserAPI, LoginUserAPI, ProtectImageAPI, GetImageMarkAPI


urlpatterns = [
    path("get-details", UserDetailAPI.as_view()),
    path('register', RegisterUserAPI.as_view()),
    path('login', LoginUserAPI.as_view()),
    path('protect-image', ProtectImageAPI.as_view()),
    path('get-image-mark', GetImageMarkAPI.as_view()),
]
