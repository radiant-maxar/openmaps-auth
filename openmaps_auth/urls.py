from django.contrib import admin
from django.conf import settings
from django.urls import include, path

from . import views

urlpatterns = [
    path(f"{settings.BASE_PATH}callback", views.callback, name="callback"),
    path(f"{settings.BASE_PATH}index", views.index, name="index"),
    path(f"{settings.BASE_PATH}v0/auth/login", views.login, name="openmaps_login"),
    path(f"{settings.BASE_PATH}v0/auth/logout", views.logout, name="openmaps_logout"),
    path(f"{settings.BASE_PATH}v0/auth/valid", views.valid, name="valid"),
    path(f"{settings.BASE_PATH}v0/admin/", admin.site.urls),
    path(
        f"{settings.BASE_PATH}v0/social/",
        include("social_django.urls", namespace="social"),
    ),
]
