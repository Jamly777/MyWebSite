from django.urls import path,include
from . import views

urlpatterns = [
    path('loading',views.index),
    path('login',views.login),
    path('picture',views.picture),
    path('check',views.check.as_view()),
    path('register',views.register.as_view())
]
