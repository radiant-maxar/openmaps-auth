from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from . import views

urlpatterns = [
    path(f"{settings.BASE_URL_PATTERN}callback", views.callback, name="callback"),
    path(f"{settings.BASE_URL_PATTERN}index", views.index, name="index"),
    path(f"{settings.BASE_URL_PATTERN}login", views.login, name="openmaps_login"),
    path(f"{settings.BASE_URL_PATTERN}logout", views.logout, name="openmaps_logout"),
    path(f"{settings.BASE_URL_PATTERN}status", views.status, name="status"),
    path(f"{settings.BASE_URL_PATTERN}valid", views.valid, name="valid"),
    path(f"{settings.BASE_URL_PATTERN}admin/", admin.site.urls),
    path(
        f"{settings.BASE_URL_PATTERN}social/",
        include("social_django.urls", namespace="social"),
    ),
]

if settings.OPENMAPS_AUTH_CLIENT_TLS:
    urlpatterns += [
        path(f"{settings.BASE_URL_PATTERN}josm/", include("openmaps_auth.josm.urls")),
        path(f"{settings.BASE_URL_PATTERN}certs/", include("openmaps_auth.tls.urls")),
    ]
