import logging

import social_core.exceptions
import social_django.views
from django.conf import settings
from django.contrib.auth.views import LoginView, LogoutView
from django.core.exceptions import PermissionDenied
from django.http import (
    HttpResponseForbidden,
    HttpResponseRedirect,
    JsonResponse,
)
from django.shortcuts import render
from django.urls import reverse


logger = logging.getLogger(__name__)


def index(request):
    return render(request, "index.html", {})


def logout(request):
    response = LogoutView.as_view(template_name="index.html")(request)
    for cookie in request.COOKIES:
        response.delete_cookie(cookie)
    return response


def valid(request):
    if not request.user.is_authenticated:
        return JsonResponse({}, status=401)
    else:
        return JsonResponse({})


def set_osm_cookie(request, response):
    response.set_cookie(
        settings.OSM_SESSION_KEY,
        request.session[settings.OSM_SESSION_KEY],
        domain=settings.SESSION_COOKIE_DOMAIN,
    )
    return response


if settings.OPENMAPS_AUTH_BACKEND:

    def callback(request, *args, **kwargs):
        try:
            response = social_django.views.complete(
                request,
                settings.OPENMAPS_AUTH_BACKEND,
                *args,
                **kwargs,
            )
        except social_core.exceptions.AuthForbidden as denied:
            logger.info(denied)
            raise PermissionDenied

        return set_osm_cookie(request, response)

    def login(request):
        return social_django.views.auth(request, settings.OPENMAPS_AUTH_BACKEND)

else:

    def callback(request):
        response = HttpResponseRedirect(reverse("index"))
        return set_osm_cookie(request, response)

    login = LoginView.as_view(template_name="login.html")
