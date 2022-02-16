from django.conf import settings
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse


def index(request):
    return render(request, "index.html", {})


logout = LogoutView.as_view(template_name="index.html")


def valid(request):
    if not request.user.is_authenticated:
        return JsonResponse({}, status=401)
    else:
        return JsonResponse({})


if settings.OPENMAPS_AUTH_BACKEND:
    import social_django.views

    def callback(request, *args, **kwargs):
        resp = social_django.views.complete(
            request,
            settings.OPENMAPS_AUTH_BACKEND,
            *args,
            **kwargs,
        )
        resp.set_cookie(
            settings.OSM_SESSION_KEY, request.session[settings.OSM_SESSION_KEY]
        )
        return resp

    def login(request):
        return social_django.views.auth(request, settings.OPENMAPS_AUTH_BACKEND)
else:

    def callback(request):
        resp = HttpResponseRedirect(reverse("index"))
        resp.set_cookie(
            settings.OSM_SESSION_KEY,
            request.session[settings.OSM_SESSION_KEY],
            domain=settings.SESSION_COOKIE_DOMAIN,
        )
        return resp

    login = LoginView.as_view(template_name="login.html")
