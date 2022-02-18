from django.conf import settings
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse


def index(request):
    return render(request, "index.html", {})


def logout(request):
    resp = LogoutView.as_view(template_name="index.html")(request)
    for cookie in request.COOKIES:
        resp.delete_cookie(cookie)
    return resp


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
    import social_django.views

    def callback(request, *args, **kwargs):
        response = social_django.views.complete(
            request,
            settings.OPENMAPS_AUTH_BACKEND,
            *args,
            **kwargs,
        )
        return set_osm_cookie(request, response)

    def login(request):
        return social_django.views.auth(request, settings.OPENMAPS_AUTH_BACKEND)

else:

    def callback(request):
        response = HttpResponseRedirect(reverse("index"))
        return set_osm_cookie(request, response)

    login = LoginView.as_view(template_name="login.html")
